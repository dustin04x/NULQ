package correlation

import (
	"sort"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
)

type Relationship struct {
	Source            EntityID          `json:"source"`
	Target            EntityID          `json:"target"`
	Type              RelationshipType  `json:"type"`
	Evidence          []EntityReference `json:"evidence"`
	ScenarioID        string            `json:"scenario_id"`
	EvidenceKind      models.Kind       `json:"evidence_kind"`
	EvaluationOutcome EvaluationOutcome `json:"evaluation_outcome"`
}

type RelationshipType string

const (
	PROCESS_EXECUTES              RelationshipType = "process_executes"
	PROCESS_RUNS_AS               RelationshipType = "process_runs_as"
	PATH_RESOLVES_TO              RelationshipType = "path_resolves_to"
	OBJECT_OWNED_BY               RelationshipType = "object_owned_by"
	DIRECTORY_CONTAINS            RelationshipType = "directory_contains"
	IDENTITY_CAN_WRITE            RelationshipType = "identity_can_write"
	OBJECT_MOUNTED_ON             RelationshipType = "object_mounted_on"
	ACL_GRANTS_ACCESS             RelationshipType = "acl_grants_access"
	OBJECT_HAS_PRIVILEGE_METADATA RelationshipType = "object_has_privilege_metadata"
)

type EntityID string

type EntityReference struct {
	Kind models.Kind `json:"kind"`
	ID   EntityID    `json:"id"`
	Path string      `json:"path,omitempty"`
}

type EvaluationOutcome string

const (
	EvaluationConfirmed    EvaluationOutcome = "confirmed"
	EvaluationPotential    EvaluationOutcome = "potential"
	EvaluationInsufficient EvaluationOutcome = "insufficient"
	EvaluationContradicted EvaluationOutcome = "contradicted"
	EvaluationUnknown      EvaluationOutcome = "unknown"
)

func AllEvaluationOutcomes() []EvaluationOutcome {
	return []EvaluationOutcome{
		EvaluationConfirmed,
		EvaluationPotential,
		EvaluationInsufficient,
		EvaluationContradicted,
		EvaluationUnknown,
	}
}

func (s EvaluationOutcome) Valid() bool {
	switch s {
	case EvaluationConfirmed, EvaluationPotential, EvaluationInsufficient, EvaluationContradicted, EvaluationUnknown:
		return true
	}
	return false
}

func (s EvaluationOutcome) Rank() int {
	switch s {
	case EvaluationConfirmed:
		return 4
	case EvaluationPotential:
		return 3
	case EvaluationInsufficient:
		return 2
	case EvaluationContradicted:
		return 1
	case EvaluationUnknown:
		return 0
	}
	return -1
}

func (s EvaluationOutcome) Less(t EvaluationOutcome) bool {
	if !s.Valid() || !t.Valid() {
		return false
	}
	return s.Rank() < t.Rank()
}

func (s EvaluationOutcome) String() string {
	return string(s)
}

type CorrelationResult struct {
	Relationships []Relationship   `json:"relationships"`
	Findings      []models.Finding `json:"findings,omitempty"`
}

type Engine struct {
	observationSet interfaces.ObservationSet
}

func NewEngine(observationSet interfaces.ObservationSet) *Engine {
	return &Engine{observationSet: observationSet}
}

func (e *Engine) Run() *CorrelationResult {
	relationships := []Relationship{}

	processes := e.observationSet.ByKind(models.KindProcess)
	files := e.observationSet.ByKind(models.KindFile)
	dirs := e.observationSet.ByKind(models.KindDirectory)
	mounts := e.observationSet.ByKind(models.KindMount)
	_ = e.observationSet.ByKind(models.KindExecutionContext)

	if len(processes) == 0 && len(files) == 0 && len(dirs) == 0 && len(mounts) == 0 {
		return &CorrelationResult{Relationships: relationships}
	}

	relCOR001 := evaluateCOR001(processes, files, dirs, mounts)
	relationships = append(relationships, relCOR001...)

	relCOR002 := evaluateCOR002(processes, files, dirs)
	relationships = append(relationships, relCOR002...)

	relCOR003 := evaluateCOR003(processes, files, dirs, mounts)
	relationships = append(relationships, relCOR003...)

	relCOR004 := evaluateCOR004(processes, files, dirs, mounts)
	relationships = append(relationships, relCOR004...)

	relCOR005 := evaluateCOR005(processes, files, dirs, mounts)
	relationships = append(relationships, relCOR005...)

	sort.Slice(relationships, func(i, j int) bool {
		if relationships[i].Source != relationships[j].Source {
			return relationships[i].Source < relationships[j].Source
		}
		if relationships[i].Target != relationships[j].Target {
			return relationships[i].Target < relationships[j].Target
		}
		return relationships[i].Type < relationships[j].Type
	})

	return &CorrelationResult{Relationships: relationships}
}

func attr(obs models.Observation, key string) string {
	return obs.Attributes[key]
}

func attrBool(obs models.Observation, key string) bool {
	v, ok := obs.Attributes[key]
	if !ok {
		return false
	}
	return v == "true"
}

func parentDirectory(path string) string {
	if path == "" {
		return ""
	}
	lastSlash := -1
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			lastSlash = i
			break
		}
	}
	if lastSlash <= 0 {
		return "/"
	}
	return path[:lastSlash]
}

func containsPath(path, mountPoint string) bool {
	if path == "" || mountPoint == "" {
		return false
	}
	return len(path) >= len(mountPoint) && path[:len(mountPoint)] == mountPoint
}

func getPath(obs models.Observation) string {
	for k, v := range obs.Attributes {
		if k == "path" {
			return v
		}
	}
	return ""
}

func containsSuperOption(options string, flag string) bool {
	if options == "" {
		return false
	}
	for _, o := range splitSuperOptions(options) {
		if o == flag {
			return true
		}
	}
	return false
}

func splitSuperOptions(options string) []string {
	var result []string
	current := ""
	for _, r := range options {
		if r == ',' {
			if current != "" {
				result = append(result, current)
				current = ""
			}
		} else {
			current += string(r)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func attrBoolOpts(obs models.Observation, key string) (string, bool) {
	v, ok := obs.Attributes[key]
	return v, ok
}

func evaluateCOR001(processes []models.Observation, files []models.Observation, dirs []models.Observation, mounts []models.Observation) []Relationship {
	var relationships []Relationship

	for _, proc := range processes {
		procExec := attr(proc, "exe_path")
		if procExec == "" {
			continue
		}

		var exeFile models.Observation
		for _, f := range files {
			filePath := attr(f, "path")
			if filePath == procExec {
				exeFile = f
				break
			}
			fileInode := attr(f, "inode")
			if fileInode == procExec {
				exeFile = f
				break
			}
		}

		exeFilePath := attr(exeFile, "path")
		if exeFilePath == "" {
			continue
		}

		dirPath := parentDirectory(exeFilePath)

		var dirObs models.Observation
		if dirPath != "" {
			for _, d := range dirs {
				dirPathAttr := attr(d, "path")
				if dirPathAttr == dirPath {
					dirObs = d
					break
				}
			}
		}

		acl := attr(exeFile, "acl_access")
		if acl != "" {
			procUID := attr(proc, "process_uid")
			exeInode := attr(exeFile, "inode")
			if procUID != "" && exeInode != "" {
				relationships = append(relationships, Relationship{
					Source:            EntityID(procUID),
					Target:            EntityID(exeInode),
					Type:              ACL_GRANTS_ACCESS,
					Evidence:          []EntityReference{{Kind: models.KindFile, ID: EntityID(exeInode), Path: exeFilePath}},
					ScenarioID:        "COR-001",
					EvidenceKind:      models.KindFile,
					EvaluationOutcome: EvaluationPotential,
				})
			}
		}

		for _, m := range mounts {
			mountPoint := attr(m, "mount_point")
			if mountPoint == "" {
				continue
			}
			if containsPath(exeFilePath, mountPoint) {
				flags := attr(m, "mount_options")
				relType := PATH_RESOLVES_TO
				if containsSuperOption(flags, "nosuid") {
					relType = OBJECT_HAS_PRIVILEGE_METADATA
				}
				if containsSuperOption(flags, "noexec") {
					relType = OBJECT_HAS_PRIVILEGE_METADATA
				}
				mountInode := attr(m, "inode")
				relationships = append(relationships, Relationship{
					Source:            EntityID(""),
					Target:            EntityID(""),
					Type:              relType,
					Evidence:          []EntityReference{{Kind: models.KindMount, ID: EntityID(mountInode), Path: mountPoint}},
					ScenarioID:        "COR-001",
					EvidenceKind:      models.KindMount,
					EvaluationOutcome: EvaluationPotential,
				})
			}
		}

		dirOwner := attr(dirObs, "uid")
		dirPathVal := attr(dirObs, "path")
		if dirPathVal != "" && dirOwner != "" && dirPath != "" {
			exeInode := attr(exeFile, "inode")
			if exeInode != "" {
				relationships = append(relationships, Relationship{
					Source:            EntityID(dirOwner),
					Target:            EntityID(exeInode),
					Type:              OBJECT_OWNED_BY,
					Evidence:          []EntityReference{{Kind: models.KindDirectory, ID: EntityID(""), Path: dirPathVal}},
					ScenarioID:        "COR-001",
					EvidenceKind:      models.KindDirectory,
					EvaluationOutcome: EvaluationPotential,
				})
			}
		}
	}

	return relationships
}

func evaluateCOR002(processes []models.Observation, files []models.Observation, dirs []models.Observation) []Relationship {
	var relationships []Relationship

	for _, f := range files {
		mode := attr(f, "mode")
		acl := attr(f, "acl_access")

		if mode == "" && acl == "" {
			continue
		}

		if mode != "" && acl != "" {
			inode := attr(f, "inode")
			if inode != "" {
				relationships = append(relationships, Relationship{
					Source:            EntityID(inode),
					Target:            EntityID(inode),
					Type:              ACL_GRANTS_ACCESS,
					Evidence:          []EntityReference{{Kind: models.KindFile, ID: EntityID(inode), Path: getPath(f)}},
					ScenarioID:        "COR-002",
					EvidenceKind:      models.KindFile,
					EvaluationOutcome: EvaluationPotential,
				})
			}
		} else if mode != "" && acl == "" {
			inode := attr(f, "inode")
			if inode != "" {
				relationships = append(relationships, Relationship{
					Source:            EntityID(inode),
					Target:            EntityID(inode),
					Type:              PATH_RESOLVES_TO,
					Evidence:          []EntityReference{{Kind: models.KindFile, ID: EntityID(inode), Path: getPath(f)}},
					ScenarioID:        "COR-002",
					EvidenceKind:      models.KindFile,
					EvaluationOutcome: EvaluationInsufficient,
				})
			}
		} else if mode == "" && acl != "" {
			inode := attr(f, "inode")
			if inode != "" {
				relationships = append(relationships, Relationship{
					Source:            EntityID(inode),
					Target:            EntityID(inode),
					Type:              ACL_GRANTS_ACCESS,
					Evidence:          []EntityReference{{Kind: models.KindFile, ID: EntityID(inode), Path: getPath(f)}},
					ScenarioID:        "COR-002",
					EvidenceKind:      models.KindFile,
					EvaluationOutcome: EvaluationPotential,
				})
			}
		}
	}

	for _, d := range dirs {
		mode := attr(d, "mode")
		acl := attr(d, "acl_access")

		if mode == "" && acl == "" {
			continue
		}

		if mode != "" && acl != "" {
			inode := attr(d, "inode")
			if inode != "" {
				relationships = append(relationships, Relationship{
					Source:            EntityID(inode),
					Target:            EntityID(inode),
					Type:              ACL_GRANTS_ACCESS,
					Evidence:          []EntityReference{{Kind: models.KindDirectory, ID: EntityID(inode), Path: getPath(d)}},
					ScenarioID:        "COR-002",
					EvidenceKind:      models.KindDirectory,
					EvaluationOutcome: EvaluationPotential,
				})
			}
		}
	}

	return relationships
}

func evaluateCOR003(processes []models.Observation, files []models.Observation, dirs []models.Observation, mounts []models.Observation) []Relationship {
	var relationships []Relationship

	mountMap := make(map[string]models.Observation)
	for _, m := range mounts {
		mountPoint := attr(m, "mount_point")
		if mountPoint == "" {
			continue
		}
		mountMap[mountPoint] = m
	}

	evaluated := make(map[string]bool)

	evaluatePath := func(path string, kind models.Kind, entityID EntityID) {
		if evaluated[path] {
			return
		}
		evaluated[path] = true

		for _, m := range mounts {
			mountPoint := attr(m, "mount_point")
			if mountPoint == "" || !containsPath(path, mountPoint) {
				continue
			}

			flags := attr(m, "mount_options")
			if flags == "" {
				continue
			}

			if containsSuperOption(flags, "nosuid") {
				mountInode := attr(m, "inode")
				relationships = append(relationships, Relationship{
					Source:            entityID,
					Target:            entityID,
					Type:              OBJECT_HAS_PRIVILEGE_METADATA,
					Evidence:          []EntityReference{{Kind: kind, ID: EntityID(mountInode), Path: mountPoint}},
					ScenarioID:        "COR-003",
					EvidenceKind:      models.KindMount,
					EvaluationOutcome: EvaluationPotential,
				})
			}

			if containsSuperOption(flags, "noexec") {
				mountInode := attr(m, "inode")
				relationships = append(relationships, Relationship{
					Source:            entityID,
					Target:            entityID,
					Type:              OBJECT_HAS_PRIVILEGE_METADATA,
					Evidence:          []EntityReference{{Kind: kind, ID: EntityID(mountInode), Path: mountPoint}},
					ScenarioID:        "COR-003",
					EvidenceKind:      models.KindMount,
					EvaluationOutcome: EvaluationPotential,
				})
			}

			if containsSuperOption(flags, "nodev") {
				mountInode := attr(m, "inode")
				relationships = append(relationships, Relationship{
					Source:            entityID,
					Target:            entityID,
					Type:              OBJECT_HAS_PRIVILEGE_METADATA,
					Evidence:          []EntityReference{{Kind: kind, ID: EntityID(mountInode), Path: mountPoint}},
					ScenarioID:        "COR-003",
					EvidenceKind:      models.KindMount,
					EvaluationOutcome: EvaluationPotential,
				})
			}

			if containsSuperOption(flags, "ro") {
				mountInode := attr(m, "inode")
				relationships = append(relationships, Relationship{
					Source:            entityID,
					Target:            entityID,
					Type:              OBJECT_HAS_PRIVILEGE_METADATA,
					Evidence:          []EntityReference{{Kind: kind, ID: EntityID(mountInode), Path: mountPoint}},
					ScenarioID:        "COR-003",
					EvidenceKind:      models.KindMount,
					EvaluationOutcome: EvaluationPotential,
				})
			}

			if containsSuperOption(flags, "rw") {
				mountInode := attr(m, "inode")
				relationships = append(relationships, Relationship{
					Source:            entityID,
					Target:            entityID,
					Type:              PATH_RESOLVES_TO,
					Evidence:          []EntityReference{{Kind: kind, ID: EntityID(mountInode), Path: mountPoint}},
					ScenarioID:        "COR-003",
					EvidenceKind:      models.KindMount,
					EvaluationOutcome: EvaluationInsufficient,
				})
			}
		}
	}

	for _, f := range files {
		path := attr(f, "path")
		if path == "" {
			continue
		}
		evaluatePath(path, models.KindFile, EntityID(""))
	}

	for _, d := range dirs {
		path := attr(d, "path")
		if path == "" {
			continue
		}
		evaluatePath(path, models.KindDirectory, EntityID(""))
	}

	return relationships
}

func evaluateCOR004(processes []models.Observation, files []models.Observation, dirs []models.Observation, mounts []models.Observation) []Relationship {
	var relationships []Relationship

	fileByPath := make(map[string]models.Observation)
	for _, f := range files {
		path := attr(f, "path")
		if path == "" {
			continue
		}
		fileByPath[path] = f
	}

	dirByPath := make(map[string]models.Observation)
	for _, d := range dirs {
		path := attr(d, "path")
		if path == "" {
			continue
		}
		dirByPath[path] = d
	}

	procByExec := make(map[string][]models.Observation)
	for _, p := range processes {
		exec := attr(p, "exe_path")
		if exec == "" {
			continue
		}
		procByExec[exec] = append(procByExec[exec], p)
	}

	for exec, procs := range procByExec {
		if len(procs) < 2 {
			continue
		}
		var exeFile models.Observation
		for _, f := range files {
			filePath := attr(f, "path")
			if filePath == exec {
				exeFile = f
				break
			}
		}
		exeFilePath := attr(exeFile, "path")
		if exeFilePath == "" {
			continue
		}

		for i, p1 := range procs {
			for j := i + 1; j < len(procs); j++ {
				p2 := procs[j]
				uid1 := attr(p1, "process_uid")
				uid2 := attr(p2, "process_uid")
				if uid1 != "" && uid2 != "" {
					relationships = append(relationships, Relationship{
						Source:            EntityID(uid1),
						Target:            EntityID(uid2),
						Type:              PATH_RESOLVES_TO,
						Evidence:          []EntityReference{{Kind: models.KindFile, ID: EntityID(""), Path: exeFilePath}},
						ScenarioID:        "COR-004",
						EvidenceKind:      models.KindFile,
						EvaluationOutcome: EvaluationPotential,
					})
				}
			}
		}
	}

	for dirPath, dirObs := range dirByPath {
		var containedFiles []models.Observation
		for _, f := range files {
			fPath := attr(f, "path")
			if fPath == "" {
				continue
			}
			if len(fPath) > len(dirPath) && fPath[:len(dirPath)] == dirPath && fPath[len(dirPath)] == '/' {
				containedFiles = append(containedFiles, f)
			}
		}

		if len(containedFiles) >= 2 {
			dirInode := attr(dirObs, "inode")
			if dirInode == "" {
				continue
			}
			for i, f1 := range containedFiles {
				for j := i + 1; j < len(containedFiles); j++ {
					f2 := containedFiles[j]
					f1Inode := attr(f1, "inode")
					f2Inode := attr(f2, "inode")
					if f1Inode != "" && f2Inode != "" {
						relationships = append(relationships, Relationship{
							Source:            EntityID(f1Inode),
							Target:            EntityID(f2Inode),
							Type:              DIRECTORY_CONTAINS,
							Evidence:          []EntityReference{{Kind: models.KindDirectory, ID: EntityID(dirInode), Path: getPath(dirObs)}},
							ScenarioID:        "COR-004",
							EvidenceKind:      models.KindDirectory,
							EvaluationOutcome: EvaluationPotential,
						})
					}
				}
			}
		}
	}

	seen := make(map[[2]string]bool)
	for exec, procs := range procByExec {
		if len(procs) < 2 {
			continue
		}
		var exeFile models.Observation
		for _, f := range files {
			filePath := attr(f, "path")
			if filePath == exec {
				exeFile = f
				break
			}
		}
		exeFilePath := attr(exeFile, "path")
		if exeFilePath == "" {
			continue
		}

		for i, p1 := range procs {
			for j := i + 1; j < len(procs); j++ {
				p2 := procs[j]
				uid1 := attr(p1, "process_uid")
				uid2 := attr(p2, "process_uid")
				key := [2]string{uid1, uid2}
				if seen[key] {
					continue
				}
				seen[key] = true
				relationships = append(relationships, Relationship{
					Source:            EntityID(uid1),
					Target:            EntityID(uid2),
					Type:              PATH_RESOLVES_TO,
					Evidence:          []EntityReference{{Kind: models.KindFile, ID: EntityID(""), Path: exeFilePath}},
					ScenarioID:        "COR-004",
					EvidenceKind:      models.KindFile,
					EvaluationOutcome: EvaluationPotential,
				})
			}
		}
	}

	return relationships
}

func evaluateCOR005(processes []models.Observation, files []models.Observation, dirs []models.Observation, mounts []models.Observation) []Relationship {
	var relationships []Relationship

	hasSetUID := false
	hasSetGID := false
	hasWorldWritable := false
	hasACLModification := false
	hasPrivilegedMount := false

	for _, p := range processes {
		exeSetUID := attr(p, "exe_setuid")
		if exeSetUID == "1" {
			hasSetUID = true
		}
		exeSetGID := attr(p, "exe_setgid")
		if exeSetGID == "1" {
			hasSetGID = true
		}
	}

	for _, f := range files {
		acl := attr(f, "acl_access")
		if acl != "" {
			hasACLModification = true
		}
		ww := attr(f, "world_writable")
		if ww == "true" {
			hasWorldWritable = true
		}
	}

	for _, d := range dirs {
		acl := attr(d, "acl_access")
		if acl != "" {
			hasACLModification = true
		}
		ww := attr(d, "world_writable")
		if ww == "true" {
			hasWorldWritable = true
		}
	}

	for _, m := range mounts {
		flags := attr(m, "mount_options")
		if flags != "" {
			if containsSuperOption(flags, "nosuid") || containsSuperOption(flags, "setuid") {
				hasPrivilegedMount = true
			}
			if containsSuperOption(flags, "noexec") || containsSuperOption(flags, "setuid") {
				hasPrivilegedMount = true
			}
		}
	}

	if hasSetUID && hasWorldWritable && hasPrivilegedMount {
		relationships = append(relationships, Relationship{
			Source:            EntityID(""),
			Target:            EntityID(""),
			Type:              OBJECT_HAS_PRIVILEGE_METADATA,
			Evidence:          []EntityReference{},
			ScenarioID:        "COR-005",
			EvidenceKind:      models.KindMount,
			EvaluationOutcome: EvaluationConfirmed,
		})
	}

	if (hasSetUID || hasSetGID) && (hasWorldWritable || hasACLModification) {
		relationships = append(relationships, Relationship{
			Source:            EntityID(""),
			Target:            EntityID(""),
			Type:              OBJECT_OWNED_BY,
			Evidence:          []EntityReference{},
			ScenarioID:        "COR-005",
			EvidenceKind:      models.KindFile,
			EvaluationOutcome: EvaluationPotential,
		})
	}

	if hasACLModification && !hasSetUID && !hasSetGID {
		relationships = append(relationships, Relationship{
			Source:            EntityID(""),
			Target:            EntityID(""),
			Type:              ACL_GRANTS_ACCESS,
			Evidence:          []EntityReference{},
			ScenarioID:        "COR-005",
			EvidenceKind:      models.KindFile,
			EvaluationOutcome: EvaluationInsufficient,
		})
	}

	if !hasSetUID && !hasSetGID && !hasWorldWritable && !hasACLModification {
		relationships = append(relationships, Relationship{
			Source:            EntityID(""),
			Target:            EntityID(""),
			Type:              PATH_RESOLVES_TO,
			Evidence:          []EntityReference{},
			ScenarioID:        "COR-005",
			EvidenceKind:      models.KindFile,
			EvaluationOutcome: EvaluationUnknown,
		})
	}

	if hasSetUID && hasWorldWritable {
		if !(hasSetUID && hasWorldWritable && hasPrivilegedMount) {
			relationships = append(relationships, Relationship{
				Source:            EntityID(""),
				Target:            EntityID(""),
				Type:              OBJECT_HAS_PRIVILEGE_METADATA,
				Evidence:          []EntityReference{},
				ScenarioID:        "COR-005",
				EvidenceKind:      models.KindFile,
				EvaluationOutcome: EvaluationContradicted,
			})
		}
	}

	return relationships
}
