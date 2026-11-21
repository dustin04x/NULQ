package filesystem

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
	"github.com/dustin04x/nulq/internal/platform/linux/acl"
)

type worldWritableRule struct{}

// NewWorldWritableRule constructs the rule.
func NewWorldWritableRule() interfaces.Rule { return worldWritableRule{} }

// Metadata implements interfaces.Rule.
func (r worldWritableRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-FS-002",
		Version:     "2.0.0",
		Name:        "Directory writable by the assessed user without adequate entry protection",
		Description: "A directory accepts create, rename or remove operations from the assessed user in a way that can influence names other processes may consume.",
		Category:    "permissions",
		Module:      "filesystem",
		Severity:    models.SeverityMedium,
		Confidence:  models.ConfidenceMedium,
		Required:    []models.Kind{models.KindDirectory, models.KindFile},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
//
// The escalation rule is deliberately narrow. HIGH requires all of:
//   - the assessed user can replace a directory entry (mode bits or ACL,
//     write+execute, and sticky-bit ownership semantics permit removal);
//   - a root-owned set-user-ID regular executable is a direct child;
//   - the executable's containing mount does not have nosuid, so SUID
//     execution semantics remain relevant on that mount.
//
// Execution is still not observed, so confidence stays MEDIUM. If mount
// metadata is missing, nosuid cannot be ruled out and the relationship is
// reported conservatively as MEDIUM with an explicit limitation.
func (r worldWritableRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	meta := r.Metadata()
	now := time.Now().UTC()
	euid := executionEUID(obs)
	euidNum, haveEUID := parseUID(euid)

	// Direct children only: directory write permission does not allow
	// unlinking entries inside a subdirectory owned by someone else.
	rootSUID := make(map[string]models.Observation)
	for _, file := range obs.ByKind(models.KindFile) {
		owner, ownerKnown := file.Attr(models.AttrOwnerUID)
		if ownerKnown && owner == "0" && file.Bool(models.AttrSetUID) && modeExecutable(file) && isRegularFile(file) {
			rootSUID[file.Resource] = file
		}
	}

	var findings []models.Finding
	for _, dir := range obs.ByKind(models.KindDirectory) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}

		path := dir.Resource
		owner, _ := dir.Attr(models.AttrOwnerUser)
		mode, _ := dir.Attr(models.AttrMode)
		sticky := dir.Bool(models.AttrSticky)
		dirOwner, _ := dir.Attr(models.AttrOwnerUID)
		dirOwnerNum, haveDirOwner := parseUID(dirOwner)
		ownedByAssessed := euid != "" && dirOwner == euid

		// World-writable by mode bit is the M1 exposure signal. A user-owned
		// sticky directory is only reported when it holds a replaceable root
		// SUID child (D2). ACL-only write without that relationship is handled
		// by writable-parent relationship rules.
		worldWritable := dir.Bool(models.AttrWorldWritable)
		if !worldWritable && !(sticky && ownedByAssessed) {
			continue
		}

		contained := containedRootSUIDFiles(path, rootSUID)
		// A sticky directory owned by another account protects existing
		// entries from unprivileged writers.
		if sticky && !ownedByAssessed && !worldWritable {
			continue
		}
		if sticky && !ownedByAssessed {
			// Root-owned (or other-owned) sticky world-writable directory: the
			// sticky bit protects entries. This remains not a finding.
			continue
		}
		if sticky && len(contained) == 0 {
			continue
		}
		if sticky && !ownedByAssessed {
			continue
		}
		if !sticky && !worldWritable {
			continue
		}

		severity := models.SeverityMedium
		confidence := models.ConfidenceMedium
		title := "World-writable directory without the sticky bit"
		if sticky {
			title = "User-owned sticky directory contains a replaceable root-owned privileged executable"
		}

		replaceableHigh := []models.Observation{}
		nosuidChildren := []models.Observation{}
		unknownMountChildren := []models.Observation{}
		for _, file := range contained {
			canReplace := canReplaceObservation(haveEUID, euidNum, haveDirOwner, dirOwnerNum, sticky, dir)
			entryOwner, haveEntryOwner := parseUID(attr(file, models.AttrOwnerUID))
			if haveEUID && haveEntryOwner && haveDirOwner {
				canReplace = acl.CanReplaceEntry(euidNum, entryOwner, dirOwnerNum, sticky, dirPerm(dir))
			}
			if canReplace != acl.Allowed {
				continue
			}
			nosuid, hasNosuid := file.Attr(models.AttrNosuid)
			switch {
			case hasNosuid && nosuid == "true":
				nosuidChildren = append(nosuidChildren, file)
			case !hasNosuid:
				// Mount metadata absent: preserve M1.5 escalation behavior but
				// record the limitation explicitly. This avoids a false-negative
				// regression while not claiming nosuid was observed absent.
				replaceableHigh = append(replaceableHigh, file)
				unknownMountChildren = append(unknownMountChildren, file)
			default:
				replaceableHigh = append(replaceableHigh, file)
			}
		}

		reasons := []string{}
		if len(replaceableHigh) > 0 {
			severity = models.SeverityHigh
			reasons = append(reasons, fmt.Sprintf(
				"The directory directly contains a root-owned set-user-ID executable that the assessed user can replace on a mount where nosuid is not set: %s.",
				strings.Join(resourcePaths(replaceableHigh), ", ")))
		} else if len(unknownMountChildren) > 0 {
			reasons = append(reasons, fmt.Sprintf(
				"The directory directly contains a replaceable root-owned set-user-ID executable but mount nosuid state is unknown: %s. SUID escalation on that mount cannot be confirmed or excluded.",
				strings.Join(resourcePaths(unknownMountChildren), ", ")))
		} else if len(nosuidChildren) > 0 {
			reasons = append(reasons, fmt.Sprintf(
				"The directory directly contains a replaceable root-owned set-user-ID executable on a nosuid mount: %s. Replacing the path is possible, but nosuid prevents SUID/SGID bits from granting their usual execution privileges on that mount.",
				strings.Join(resourcePaths(nosuidChildren), ", ")))
		}

		finding := models.NewFinding(meta, path, models.ResourceDirectory, severity, confidence, title, now)
		if sticky {
			finding.Explanation = fmt.Sprintf(
				"%s has mode %s (owner %s). The sticky bit protects entries owned by other accounts, but the assessed user owns the directory and can remove any entry in it.",
				path, mode, owner)
		} else {
			finding.Explanation = fmt.Sprintf(
				"%s has mode %s (owner %s) and accepts entries from unprivileged accounts. Any local user can create, rename or remove entries the sticky bit does not protect.",
				path, mode, owner)
		}
		if len(reasons) > 0 {
			finding.Explanation += " " + strings.Join(reasons, " ")
		}

		switch {
		case severity == models.SeverityHigh:
			finding.Impact = "Replacing a root-owned set-user-ID executable would make any later execution of that path from this mount context run attacker-controlled code with root authority. Execution of the binary is not observed, so the finding is an exposure, not a demonstrated exploit."
		case len(nosuidChildren) > 0:
			finding.Impact = "The directory entry is replaceable, but nosuid constrains SUID/SGID execution semantics on that mount. This is a path-integrity exposure, not confirmed SUID escalation."
		default:
			finding.Impact = "A privileged process or administrator that consumes files from this directory by name can be made to consume attacker-controlled content. Exposure depends on whether such a consumer exists, which this rule does not establish."
		}

		finding.Remediation = "Remove world-write access or set the sticky bit with a trusted owner. Audit processes that read from the directory and keep privileged executables outside user-writable paths."
		finding.Limitations = []string{
			"Consumers of the directory are not enumerated; execution of a contained binary is not observed.",
			"Only root-owned set-user-ID executables on mounts without nosuid escalate to HIGH; user-owned SUID and root SGID executables do not grant root.",
			"A sticky directory owned by another account protects its entries and is not reported by this rule.",
			"POSIX ACLs are evaluated when normalized ACL state is available; unreadable or malformed ACLs are treated as unknown and do not create a replaceability claim.",
		}
		finding.AddEvidence(
			builder.Add(dir, models.AttrMode, "Observed directory permission bits."),
			builder.Add(dir, models.AttrSticky, "Whether the sticky bit is set."),
			builder.Add(dir, models.AttrWorldWritable, "Whether the directory is writable by other."),
			builder.Add(dir, models.AttrOwnerUser, "Owner of the directory."),
			builder.Add(dir, models.AttrOwnerUID, "Numeric directory owner compared with the assessed effective UID."),
			builder.Add(dir, models.AttrEffectiveWrite, "Effective write permission for the assessed identity."),
		)
		for index, file := range append(append([]models.Observation{}, replaceableHigh...), append(unknownMountChildren, nosuidChildren...)...) {
			if index == 4 {
				break
			}
			finding.AddEvidence(
				builder.Add(file, models.AttrMode, "Permission bits of the directly replaceable root-owned SUID executable."),
				builder.Add(file, models.AttrOwnerUser, "Owner whose authority execution receives."),
				builder.Add(file, models.AttrOwnerUID, "Numeric owner; escalation requires root."),
				builder.Add(file, models.AttrNosuid, "Mount nosuid flag affecting SUID/SGID execution semantics."),
				builder.Add(file, models.AttrMountPoint, "Resolved containing mount for the executable."),
			)
		}
		findings = append(findings, finding)
	}
	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}

func dirPerm(dir models.Observation) acl.Perm {
	write := effectiveAccess(dir, models.AttrEffectiveWrite, models.AttrWritableByCurrentUser)
	exec := effectiveAccess(dir, models.AttrEffectiveExec, "")
	if exec == acl.Unknown {
		// Legacy observations predate effective_exec. For a directory where
		// write is known, directory traversal is required for create/rename but
		// the old model did not record it; assume Allowed when mode/legacy says
		// writable to preserve M1.5 behavior, and stay Unknown only when write
		// itself is unknown.
		if write == acl.Allowed {
			exec = acl.Allowed
		} else if write == acl.Denied {
			exec = acl.Denied
		}
	}
	return acl.Perm{Write: write, Exec: exec}
}

func effectiveAccess(obs models.Observation, effectiveAttr, legacyAttr string) acl.Access {
	if value, ok := obs.Attr(effectiveAttr); ok {
		switch value {
		case string(acl.Allowed):
			return acl.Allowed
		case string(acl.Denied):
			return acl.Denied
		case string(acl.Unknown):
			return acl.Unknown
		}
	}
	if legacyAttr == "" {
		return acl.Unknown
	}
	if value, ok := obs.Attr(legacyAttr); ok {
		switch value {
		case "true":
			return acl.Allowed
		case "false":
			return acl.Denied
		case "unknown":
			return acl.Unknown
		}
	}
	return acl.Unknown
}

func canReplaceObservation(haveEUID bool, euid uint32, haveDirOwner bool, dirOwner uint32, sticky bool, dir models.Observation) acl.Access {
	write := effectiveAccess(dir, models.AttrEffectiveWrite, models.AttrWritableByCurrentUser)
	if write == acl.Allowed {
		if sticky && haveEUID && haveDirOwner && euid != 0 && euid != dirOwner {
			return acl.Denied
		}
		return acl.Allowed
	}
	if write == acl.Unknown {
		return acl.Unknown
	}
	return acl.Denied
}

func parseUID(value string) (uint32, bool) {
	if value == "" {
		return 0, false
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(parsed), true
}

func attr(obs models.Observation, key string) string {
	value, _ := obs.Attr(key)
	return value
}

func isRegularFile(file models.Observation) bool {
	// Collector only emits KindFile for regular files, but keep the guard
	// explicit for relationship claims.
	_, ok := file.Attr(models.AttrMode)
	return ok
}

// containedRootSUIDFiles returns root-owned SUID executables that are direct
// children of dir. Symlinks are not resolved, matching the collector.
func containedRootSUIDFiles(dir string, files map[string]models.Observation) []models.Observation {
	cleanDir := filepath.Clean(dir)
	var out []models.Observation
	for path, file := range files {
		if filepath.Dir(filepath.Clean(path)) == cleanDir {
			out = append(out, file)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Resource < out[j].Resource })
	return out
}

func resourcePaths(observations []models.Observation) []string {
	paths := make([]string, 0, len(observations))
	for _, observation := range observations {
		paths = append(paths, observation.Resource)
	}
	return paths
}
