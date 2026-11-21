//go:build linux

package identity

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/dustin04x/nulq/internal/core/models"
)

func TestCollectorReportsExecutionContext(t *testing.T) {
	observations, err := NewCollector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var contextObs models.Observation
	var memberships int
	for _, obs := range observations {
		switch obs.Kind {
		case models.KindExecutionContext:
			contextObs = obs
		case models.KindGroupMembership:
			memberships++
		}
	}
	if contextObs.ID == "" {
		t.Fatal("execution context observation is missing")
	}
	if euid, _ := contextObs.Attr(models.AttrEUID); euid != strconv.Itoa(os.Geteuid()) {
		t.Fatalf("EUID = %q, want %d", euid, os.Geteuid())
	}
	if username, _ := contextObs.Attr(models.AttrUsername); username == "" {
		t.Fatal("username should be recorded")
	}
	if memberships == 0 {
		t.Fatal("at least the primary group membership must be recorded")
	}
	for _, obs := range observations {
		if obs.Kind != models.KindGroupMembership {
			continue
		}
		if name, _ := obs.Attr(models.AttrGroupName); name == "" {
			t.Fatal("group membership must carry a group name")
		}
		if _, ok := obs.Int(models.AttrGroupGID); !ok {
			t.Fatal("group membership must carry a numeric group ID")
		}
	}
}
