// Command labverify validates a NULQ laboratory run.
//
// It loads the real reports produced inside the container, validates each
// against the published JSON Schema, evaluates every scenario in the manifest,
// verifies the container isolation probe and writes validation.json and
// summary.md. It is not a scanner and contains no detection logic.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/dustin04x/nulq/internal/lab"
	"github.com/dustin04x/nulq/pkg/api"
)

func main() {
	resultsDir := flag.String("results", "lab/results", "directory containing laboratory artifacts")
	manifestPath := flag.String("manifest", "lab/scenarios/manifest.json", "scenario manifest")
	schemaPath := flag.String("schema", "schemas/nulq-report-v1.schema.json", "published report schema")
	flag.Parse()

	if err := run(*resultsDir, *manifestPath, *schemaPath); err != nil {
		fmt.Fprintf(os.Stderr, "labverify: %v\n", err)
		os.Exit(1)
	}
}

func run(resultsDir, manifestPath, schemaPath string) error {
	schema, err := lab.LoadSchema(schemaPath)
	if err != nil {
		return err
	}
	manifest, err := lab.LoadManifest(manifestPath)
	if err != nil {
		return err
	}

	scans := make(map[string]lab.ScanArtifact, len(manifest.Artifacts))
	for _, name := range manifest.ScanNames() {
		artifact := lab.ScanArtifact{Name: name, Artifact: manifest.Artifacts[name]}
		path := filepath.Join(resultsDir, artifact.Artifact)
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			artifact.SchemaErrors = []string{"cannot read artifact: " + readErr.Error()}
			scans[name] = artifact
			continue
		}
		artifact.SchemaErrors = schema.ValidateFile(path)
		report, parseErr := api.ParseReport(bytes.NewReader(data))
		if parseErr != nil {
			artifact.SchemaErrors = append(artifact.SchemaErrors, parseErr.Error())
		} else {
			artifact.Report = report
			artifact.Loaded = true
		}
		scans[name] = artifact
	}

	isolation := lab.Isolation{}
	isolationPath := filepath.Join(resultsDir, "isolation.json")
	if data, readErr := os.ReadFile(isolationPath); readErr == nil {
		if err := json.Unmarshal(data, &isolation); err != nil {
			return fmt.Errorf("parse %s: %w", isolationPath, err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "labverify: warning: %s is missing: %v\n", isolationPath, readErr)
	}

	image := lab.ImageInfo{}
	imagePath := filepath.Join(resultsDir, "image.json")
	if data, readErr := os.ReadFile(imagePath); readErr == nil {
		if err := json.Unmarshal(data, &image); err != nil {
			return fmt.Errorf("parse %s: %w", imagePath, err)
		}
	}

	result := lab.Evaluate(manifest, scans, isolation, image)

	validation, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	validation = append(validation, '\n')
	if err := os.WriteFile(filepath.Join(resultsDir, "validation.json"), validation, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(resultsDir, "summary.md"), []byte(lab.RenderSummary(result)), 0o600); err != nil {
		return err
	}

	verdict := "FAIL"
	if result.Summary.Passed {
		verdict = "PASS"
	}
	fmt.Printf("%s: %d/%d scenarios passed, %d unsupported, %d missing findings, %d unexpected, %d scan(s) invalid\n",
		verdict,
		result.Summary.ScenariosPassed,
		result.Summary.ScenariosTotal-result.Summary.ScenariosUnsupported,
		result.Summary.ScenariosUnsupported,
		result.Summary.MissingFindings,
		result.Summary.UnexpectedFindings,
		result.Summary.ScansInvalid,
	)

	for _, scenario := range result.Scenarios {
		if scenario.Status == "failed" {
			for _, check := range scenario.Checks {
				if !check.Passed {
					fmt.Fprintf(os.Stderr, "  %s: %s (%s)\n", scenario.ID, check.Description, check.Detail)
				}
			}
		}
	}
	for _, check := range result.Isolation.Checks {
		if !check.Passed {
			fmt.Fprintf(os.Stderr, "  isolation: %s (%s)\n", check.Description, check.Detail)
		}
	}
	for _, scan := range result.Scans {
		for _, problem := range scan.SchemaErrors {
			fmt.Fprintf(os.Stderr, "  %s schema: %s\n", scan.Name, problem)
		}
	}

	if !result.Summary.Passed {
		return fmt.Errorf("laboratory validation failed; see %s", filepath.Join(resultsDir, "summary.md"))
	}
	return nil
}
