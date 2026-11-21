//go:build linux

package system

import (
	"context"
	"testing"

	"github.com/dustin04x/nulq/internal/core/models"
)

func TestCollectorPublishesHostAndSecurityFacts(t *testing.T) {
	observations, err := NewCollector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var info models.Observation
	var sysctlCount int
	var lsmCount int
	for _, obs := range observations {
		switch obs.Kind {
		case models.KindSystemInfo:
			info = obs
		case models.KindSysctl:
			sysctlCount++
			if obs.Status == models.StatusComplete {
				if value, ok := obs.Attr(models.AttrValue); !ok || value == "" {
					t.Errorf("complete sysctl %s has no value", obs.Resource)
				}
			} else if obs.Error == nil {
				t.Errorf("unavailable sysctl %s carries no error", obs.Resource)
			}
		case models.KindSecurityControl:
			if len(obs.Resource) > 4 && obs.Resource[:4] == "lsm:" && obs.Resource != "lsm:list" {
				lsmCount++
				if !obs.Bool(models.AttrActive) {
					t.Errorf("advertised LSM %s is not marked active", obs.Resource)
				}
			}
		}
	}

	if info.ID == "" {
		t.Fatal("system.info observation is missing")
	}
	if release, _ := info.Attr(models.AttrKernelRelease); release == "" {
		t.Fatal("kernel release must be recorded")
	}
	if arch, _ := info.Attr(models.AttrArchitecture); arch == "" {
		t.Fatal("architecture must be recorded")
	}
	if sysctlCount != len(sysctlKeys) {
		t.Fatalf("want %d sysctl observations, got %d", len(sysctlKeys), sysctlCount)
	}
	if lsmCount == 0 {
		t.Log("no LSM modules were advertised; this is valid but reduces the MAC rule's evidence")
	}
}
