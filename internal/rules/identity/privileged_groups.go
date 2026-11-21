// Package identity contains rules about user and group authority.
package identity

import (
	"context"
	"fmt"
	"time"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/evidence"
)

// privilegeGroupRule reports group memberships that carry — or can be used to
// obtain — authority beyond that of an ordinary user.
type privilegeGroupRule struct{}

// NewPrivilegedGroupRule constructs the rule.
func NewPrivilegedGroupRule() interfaces.Rule { return privilegeGroupRule{} }

type groupRisk struct {
	severity    models.Severity
	explanation string
	impact      string
	remediation string
	references  []models.Reference
}

// privilegedGroups is a conservative, documented mapping from group name to
// the authority that membership typically confers. Groups not listed here
// produce no finding: NULQ does not guess at site-specific semantics.
var privilegedGroups = map[string]groupRisk{
	"docker": {
		severity: models.SeverityHigh,
		explanation: "Membership in the docker group grants access to the Docker daemon socket. " +
			"The daemon runs as root and accepts instructions to start containers with host bind mounts, " +
			"so a member can read or modify host files with root authority.",
		impact:      "Effectively equivalent to root on the host for any account in this group.",
		remediation: "Remove the account from the group. Use rootless containers or a restricted daemon proxy if container access is genuinely required.",
		references: []models.Reference{
			{Title: "Docker Engine security: daemon attack surface", URL: "https://docs.docker.com/engine/security/"},
		},
	},
	"podman": {
		severity: models.SeverityHigh,
		explanation: "Membership in the podman group can grant access to a privileged container runtime socket or storage, " +
			"which allows manipulating host files through container mounts.",
		impact:      "A member may obtain root-equivalent access to the host filesystem.",
		remediation: "Prefer rootless Podman. Remove the account from the group when socket access is not required.",
		references: []models.Reference{
			{Title: "Podman rootless mode", URL: "https://docs.podman.io/en/latest/markdown/podman.1.html"},
		},
	},
	"lxd": {
		severity: models.SeverityHigh,
		explanation: "Membership in the lxd group grants control of the LXD daemon, including privileged containers " +
			"and host path mounts.",
		impact:      "Effectively equivalent to root on the host.",
		remediation: "Remove the account from the group and scope LXD access through a restricted API.",
		references: []models.Reference{
			{Title: "LXD security", URL: "https://documentation.ubuntu.com/lxd/en/latest/explanation/security/"},
		},
	},
	"lxc": {
		severity:    models.SeverityHigh,
		explanation: "Membership in the lxc group may allow starting containers with host filesystem access.",
		impact:      "May be equivalent to root depending on container configuration.",
		remediation: "Remove the account from the group unless container administration is part of its role.",
	},
	"libvirt": {
		severity: models.SeverityHigh,
		explanation: "Membership in the libvirt group grants control over virtual machines and their storage. " +
			"A VM definition can attach host block devices or paths.",
		impact:      "May provide root-equivalent host access.",
		remediation: "Remove the account from the group; use read-only connections for monitoring.",
	},
	"disk": {
		severity:    models.SeverityHigh,
		explanation: "Membership in the disk group grants raw block device access. Block device access bypasses filesystem permissions entirely and is not mediated by mount options.",
		impact:      "A member can read or rewrite any filesystem, including setuid binaries and credential databases.",
		remediation: "Remove the account from the group. Grant scoped access to specific devices only when unavoidable.",
	},
	"wheel": {
		severity: models.SeverityLow,
		explanation: "The wheel group conventionally authorises sudo on many distributions. " +
			"Actual authority depends on the sudoers policy, which this scan does not evaluate.",
		impact:      "If the sudo policy authorises this group, the account can become root. The policy is not evaluated, so this is a conditional concern.",
		remediation: "Review the sudo policy for this account and remove the membership if elevation is not required.",
	},
	"sudo": {
		severity:    models.SeverityLow,
		explanation: "The sudo group conventionally authorises sudo. Actual authority depends on the sudoers policy, which this scan does not evaluate.",
		impact:      "If the sudo policy authorises this group, the account can become root. The policy is not evaluated, so this is a conditional concern.",
		remediation: "Review the sudo policy for this account and remove the membership if elevation is not required.",
	},
	"admin": {
		severity:    models.SeverityLow,
		explanation: "The admin group conventionally authorises sudo on Debian-family systems. Actual authority depends on the sudoers policy.",
		impact:      "If the sudo policy authorises this group, the account can become root. The policy is not evaluated, so this is a conditional concern.",
		remediation: "Review the sudo policy for this account and remove the membership if elevation is not required.",
	},
	"root": {
		severity:    models.SeverityLow,
		explanation: "The account is a member of the root group, which often owns privileged configuration and device nodes.",
		impact:      "May allow modifying security-relevant files depending on their group ownership and mode.",
		remediation: "Remove the membership unless group-owned configuration genuinely requires it.",
	},
	"adm": {
		severity:    models.SeverityLow,
		explanation: "Membership in adm conventionally grants read access to system logs and accounting data.",
		impact:      "Sensitive operational data may be exposed; this is not direct root authority.",
		remediation: "Review whether log access is still required for this account.",
	},
	"input": {
		severity: models.SeverityMedium,
		explanation: "Membership in the input group grants access to input device event streams. " +
			"On a workstation this permits observing keystrokes, including passwords, from other sessions.",
		impact:      "Credential and data capture from local input devices.",
		remediation: "Remove the account from the group unless it runs a legitimate input-handling service.",
	},
}

// Metadata implements interfaces.Rule.
func (r privilegeGroupRule) Metadata() models.RuleMetadata {
	return models.RuleMetadata{
		ID:          "NULQ-ID-001",
		Version:     "1.0.0",
		Name:        "Privileged group membership",
		Description: "The current user holds a group membership that confers, or can be used to obtain, authority beyond an ordinary user account.",
		Category:    "privileged-membership",
		Module:      "identity",
		Severity:    models.SeverityLow,
		Confidence:  models.ConfidenceHigh,
		Required:    []models.Kind{models.KindGroupMembership},
		Platforms:   []string{"linux"},
	}
}

// Evaluate implements interfaces.Rule.
func (r privilegeGroupRule) Evaluate(ctx context.Context, obs interfaces.ObservationSet) (models.RuleResult, error) {
	builder := evidence.New()
	var findings []models.Finding

	for _, membership := range obs.ByKind(models.KindGroupMembership) {
		if err := ctx.Err(); err != nil {
			return models.RuleResult{}, err
		}
		name, _ := membership.Attr(models.AttrGroupName)
		risk, known := privilegedGroups[name]
		if !known {
			continue
		}
		gid, _ := membership.Attr(models.AttrGroupGID)
		source, _ := membership.Attr(models.AttrSource)
		username, _ := membership.Attr(models.AttrUsername)

		finding := models.NewFinding(
			r.Metadata(),
			"group:"+name,
			models.ResourceGroup,
			risk.severity,
			models.ConfidenceHigh,
			"Privileged group membership: "+name,
			time.Now().UTC(),
		)
		finding.Explanation = fmt.Sprintf(
			"Account %q is a member of group %q (gid %s, %s membership). %s",
			username, name, gid, source, risk.explanation)
		finding.Impact = risk.impact
		finding.Remediation = risk.remediation
		finding.References = risk.references
		finding.Limitations = []string{
			"Membership is observed; the practical effect depends on the authority granted to the group and on policy this scan does not evaluate.",
			"Supplementary group order and nested group resolution are not modelled.",
		}
		finding.AddEvidence(
			builder.Add(membership, models.AttrGroupName, "The group is present in the effective group set of the running process."),
			builder.Add(membership, models.AttrGroupGID, "Numeric group identifier of the membership."),
			builder.Add(membership, models.AttrSource, "Whether the group is the primary group or supplementary."),
		)
		findings = append(findings, finding)
	}
	return models.RuleResult{Findings: findings, Evidence: builder.Items()}, nil
}
