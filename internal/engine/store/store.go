// Package store provides the immutable observation store used during a scan.
package store

import (
	"sort"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
)

// Memory is an in-memory observation store. It is written once during
// collection and read concurrently by rule evaluations afterwards.
type Memory struct {
	byID   map[string]models.Observation
	byKind map[models.Kind][]models.Observation
	all    []models.Observation
}

var _ interfaces.ObservationSet = (*Memory)(nil)

// New builds a store from observations, deduplicating by ID and ordering
// entries deterministically. When two observations share an ID the more
// complete one wins.
func New(observations []models.Observation) *Memory {
	sorted := make([]models.Observation, len(observations))
	copy(sorted, observations)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Kind != sorted[j].Kind {
			return sorted[i].Kind < sorted[j].Kind
		}
		if sorted[i].Resource != sorted[j].Resource {
			return sorted[i].Resource < sorted[j].Resource
		}
		return sorted[i].ID < sorted[j].ID
	})

	m := &Memory{
		byID:   make(map[string]models.Observation, len(sorted)),
		byKind: make(map[models.Kind][]models.Observation),
	}
	for _, obs := range sorted {
		existing, ok := m.byID[obs.ID]
		if ok {
			if statusRank(obs.Status) <= statusRank(existing.Status) {
				continue
			}
			// Replace: remove the older entry from its kind slice.
			m.removeKind(existing)
		}
		obs = obs.Clone()
		m.byID[obs.ID] = obs
		m.byKind[obs.Kind] = append(m.byKind[obs.Kind], obs)
		m.all = append(m.all, obs)
	}
	return m
}

func (m *Memory) removeKind(obs models.Observation) {
	items := m.byKind[obs.Kind]
	for i := range items {
		if items[i].ID == obs.ID {
			m.byKind[obs.Kind] = append(items[:i], items[i+1:]...)
			break
		}
	}
	for i := range m.all {
		if m.all[i].ID == obs.ID {
			m.all = append(m.all[:i], m.all[i+1:]...)
			break
		}
	}
}

func statusRank(status models.Status) int {
	switch status {
	case models.StatusComplete:
		return 3
	case models.StatusPartial:
		return 2
	case models.StatusUnavailable:
		return 1
	default:
		return 0
	}
}

// ByKind returns every observation of a kind, ordered by resource.
func (m *Memory) ByKind(kind models.Kind) []models.Observation {
	return m.byKind[kind]
}

// All returns every observation in deterministic order.
func (m *Memory) All() []models.Observation {
	out := make([]models.Observation, len(m.all))
	copy(out, m.all)
	return out
}

// Get looks up an observation by ID.
func (m *Memory) Get(id string) (models.Observation, bool) {
	obs, ok := m.byID[id]
	return obs, ok
}

// Has reports whether at least one observation of a kind exists.
func (m *Memory) Has(kind models.Kind) bool {
	return len(m.byKind[kind]) > 0
}

// HasAll reports whether every kind is present.
func (m *Memory) HasAll(kinds ...models.Kind) bool {
	for _, kind := range kinds {
		if !m.Has(kind) {
			return false
		}
	}
	return true
}

// Len returns the number of stored observations.
func (m *Memory) Len() int {
	return len(m.all)
}
