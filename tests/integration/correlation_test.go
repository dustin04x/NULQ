package integration_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/correlation"
	"github.com/dustin04x/nulq/internal/engine/store"
)

// TestCorrelationCOR001 verifies COR-001: Executable replacement exposure
func TestCorrelationCOR001(t *testing.T) {
	root := t.TempDir()

	// Create the executable file
	execFile := filepath.Join(root, "bin", "admintool")
	os.WriteFile(execFile, []byte("fixture"), 0o600)
	os.Chmod(execFile, 0o755)
	execDir := filepath.Dir(execFile) // /root/bin

	// Create a process that "executes" this binary
	procDir := filepath.Join(root, "tmp")
	os.MkdirAll(procDir, 0o755)
	procFile := filepath.Join(procDir, "script.sh")
	os.WriteFile(procFile, []byte("fixture"), 0o600)
	os.Chmod(procFile, 0o755)

	// Observations with all required attributes for COR-001 evaluation
	// Key: process exe_path points to the same file as the file observation
	obsStore := store.New([]models.Observation{
		{ID: models.ObservationID(models.KindProcess, execFile), Kind: models.KindProcess, Resource: execFile, Attributes: map[string]string{
			"exe_path":    execFile,
			"process_uid": "duser",
		}},
		{ID: models.ObservationID(models.KindFile, execFile), Kind: models.KindFile, Resource: execFile, Attributes: map[string]string{
			"path": execFile,
			"mode": "0755",
		}},
		{ID: models.ObservationID(models.KindDirectory, execDir), Kind: models.KindDirectory, Resource: execDir, Attributes: map[string]string{
			"path":  execDir,
			"owner": "duser",
		}},
		{ID: models.ObservationID(models.KindMount, execDir), Kind: models.KindMount, Resource: execDir, Attributes: map[string]string{
			"mount_point": execDir,
			"flags":       "rw,exec",
		}},
	})

	// Debug: print all observations and byKind
	t.Logf("COR-001: All observations count: %d", obsStore.Len())

	processObs := obsStore.ByKind(models.KindProcess)
	fileObs := obsStore.ByKind(models.KindFile)
	dirObs := obsStore.ByKind(models.KindDirectory)
	mountObs := obsStore.ByKind(models.KindMount)

	t.Logf("COR-001: Process observations: %d", len(processObs))
	t.Logf("COR-001: File observations: %d", len(fileObs))
	t.Logf("COR-001: Directory observations: %d", len(dirObs))
	t.Logf("COR-001: Mount observations: %d", len(mountObs))

	for _, obs := range obsStore.All() {
		id6 := "<empty>"
		if len(obs.ID) >= 6 {
			id6 = obs.ID[:6]
		}
		t.Logf("COR-001:   %s ID=%s(%s) %s", obs.Kind, id6, obs.ID, obs.Resource)
	}

	engine := correlation.NewEngine(obsStore)
	result := engine.Run()

	t.Logf("COR-001: Result relationships: %d", len(result.Relationships))
	for i, rel := range result.Relationships {
		t.Logf("COR-001:   [%d] ScenarioID=%q Type=%q Outcome=%q", i, rel.ScenarioID, rel.Type, rel.EvaluationOutcome)
	}

	// Check that there is at least one COR-001 relationship
	c001Found := false
	for _, rel := range result.Relationships {
		if rel.ScenarioID == "COR-001" {
			c001Found = true
			if string(rel.EvaluationOutcome) == "unknown" {
				t.Fatal("COR-001: outcome should not be unknown when evidence is present")
			}
		}
	}
	if !c001Found {
		t.Fatal("COR-001: expected at least one relationship with scenario_id COR-001")
	}
}
