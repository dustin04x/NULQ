//go:build linux

package container

import (
	"context"
	"testing"

	"github.com/dustin04x/nulq/internal/core/models"
)

func TestContainerCollectorNoIndicatorsOnHost(t *testing.T) {
	obs, err := NewCollector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	for _, o := range obs {
		if o.Kind != models.KindContainerIndicator {
			t.Fatalf("unexpected observation kind %q", o.Kind)
		}
		if o.Status != models.StatusComplete {
			t.Fatalf("container indicator should be complete, got %q", o.Status)
		}
	}
}
