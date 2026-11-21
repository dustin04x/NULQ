// Package evidence builds evidence records that cite observations.
//
// A builder collapses duplicate citations and keeps findings and evidence
// consistent: a finding may only reference evidence that the same rule
// returned to the engine.
package evidence

import (
	"github.com/dustin04x/nulq/internal/core/models"
)

// AbsentValue is recorded when a rule cites an attribute the collector did
// not publish. It is explicit so a reviewer can see the gap instead of
// silently reading an empty string.
const AbsentValue = "<not observed>"

// Builder collects evidence for one rule evaluation.
type Builder struct {
	items []models.Evidence
	seen  map[string]struct{}
}

// New returns an empty builder.
func New() *Builder {
	return &Builder{seen: make(map[string]struct{})}
}

// Add cites one attribute of an observation. An empty field cites the
// observation's resource identifier itself (useful for existence facts).
func (b *Builder) Add(obs models.Observation, field, explanation string) string {
	return b.add(obs, field, "", explanation)
}

// AddExpected cites one attribute together with the value the rule expected.
func (b *Builder) AddExpected(obs models.Observation, field, expected, explanation string) string {
	return b.add(obs, field, expected, explanation)
}

func (b *Builder) add(obs models.Observation, field, expected, explanation string) string {
	observed := obs.Resource
	if field != "" {
		value, ok := obs.Attributes[field]
		if !ok || value == "" {
			observed = AbsentValue
		} else {
			observed = value
		}
	}
	id := models.EvidenceID(obs.ID, field)
	if _, ok := b.seen[id]; ok {
		return id
	}
	b.seen[id] = struct{}{}
	b.items = append(b.items, models.Evidence{
		ID:            id,
		ObservationID: obs.ID,
		Resource:      obs.Resource,
		ResourceKind:  resourceKind(obs.Kind),
		Collector:     obs.Collector,
		Field:         field,
		ObservedValue: observed,
		ExpectedValue: expected,
		Explanation:   explanation,
		CollectedAt:   obs.CollectedAt,
	})
	return id
}

// Items returns the collected evidence. The slice is owned by the builder;
// callers must not mutate it.
func (b *Builder) Items() []models.Evidence {
	return b.items
}

func resourceKind(kind models.Kind) string {
	switch kind {
	case models.KindFile:
		return models.ResourceFile
	case models.KindDirectory:
		return models.ResourceDirectory
	case models.KindPathEntry:
		return models.ResourcePathEntry
	case models.KindGroupMembership:
		return models.ResourceGroup
	case models.KindExecutionContext:
		return models.ResourceUser
	case models.KindSysctl:
		return models.ResourceSysctl
	case models.KindSecurityControl:
		return models.ResourceSecurityControl
	case models.KindMount:
		return models.ResourceFilesystem
	case models.KindProcess:
		return models.ResourceProcess
	default:
		return models.ResourceSystem
	}
}
