package identity

import (
	"context"
	"testing"
	"time"

	"github.com/dustin04x/nulq/internal/core/models"
	"github.com/dustin04x/nulq/internal/engine/store"
)

func groupMembership(name, gid, source string) models.Observation {
	obs := models.NewObservation(models.KindGroupMembership, "group:"+name, "test", time.Now(), nil)
	obs.Set(models.AttrGroupName, name)
	obs.Set(models.AttrGroupGID, gid)
	obs.Set(models.AttrSource, source)
	obs.Set(models.AttrUsername, "tester")
	return obs
}

func TestPrivilegedGroupRuleClassifiesMemberships(t *testing.T) {
	rule := NewPrivilegedGroupRule()
	if err := rule.Metadata().Validate(); err != nil {
		t.Fatalf("rule metadata must be valid: %v", err)
	}

	cases := []struct {
		group        string
		wantFindings int
		wantSeverity models.Severity
	}{
		{"docker", 1, models.SeverityHigh},
		{"wheel", 1, models.SeverityLow},
		{"sudo", 1, models.SeverityLow},
		{"root", 1, models.SeverityLow},
		{"adm", 1, models.SeverityLow},
		{"video", 0, ""},
	}

	for _, tc := range cases {
		t.Run(tc.group, func(t *testing.T) {
			obs := store.New([]models.Observation{groupMembership(tc.group, "100", "supplementary")})
			result, err := rule.Evaluate(context.Background(), obs)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Findings) != tc.wantFindings {
				t.Fatalf("want %d findings, got %d", tc.wantFindings, len(result.Findings))
			}
			if tc.wantFindings == 0 {
				return
			}
			finding := result.Findings[0]
			if finding.Severity != tc.wantSeverity {
				t.Fatalf("severity = %s, want %s", finding.Severity, tc.wantSeverity)
			}
			if finding.Resource != "group:"+tc.group {
				t.Fatalf("resource = %q", finding.Resource)
			}
			if len(finding.Evidence) == 0 {
				t.Fatal("finding must cite evidence")
			}
			if err := finding.Validate(); err != nil {
				t.Fatalf("finding must be valid: %v", err)
			}
			if finding.Impact == "" || finding.Remediation == "" || finding.Explanation == "" {
				t.Fatal("finding must explain itself and propose remediation")
			}
		})
	}
}

func TestPrivilegedGroupRuleIgnoresUnknownGroups(t *testing.T) {
	obs := store.New([]models.Observation{groupMembership("developers", "4242", "supplementary")})
	result, err := NewPrivilegedGroupRule().Evaluate(context.Background(), obs)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("unknown groups must not be guessed at, got %+v", result.Findings)
	}
}
