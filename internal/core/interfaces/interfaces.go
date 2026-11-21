// Package interfaces defines the contracts between the collection layer, the
// detection layer and the engine.
package interfaces

import (
	"context"

	"github.com/dustin04x/nulq/internal/core/models"
)

// Collector inspects one slice of the Linux environment and publishes
// normalized observations.
//
// Collectors must be read-only, must respect context cancellation and must
// never terminate the process. Returning observations together with an error
// is allowed and means the collection was partial: the engine records the
// error and still publishes what was collected.
type Collector interface {
	Name() string
	Collect(ctx context.Context) ([]models.Observation, error)
}

// ObservationSet is the read-only view of collected observations that rules
// receive. It is immutable for the duration of a rule evaluation, which
// removes a class of concurrency hazards from rule authors.
type ObservationSet interface {
	ByKind(kind models.Kind) []models.Observation
	All() []models.Observation
	Get(id string) (models.Observation, bool)
	Has(kind models.Kind) bool
	HasAll(kinds ...models.Kind) bool
}

// Rule is a detection module. Rules interpret observations; they never
// collect, print or mutate system state.
type Rule interface {
	Metadata() models.RuleMetadata
	Evaluate(ctx context.Context, observations ObservationSet) (models.RuleResult, error)
}
