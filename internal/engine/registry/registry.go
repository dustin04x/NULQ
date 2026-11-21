// Package registry manages rule registration and selection.
package registry

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/core/models"
)

// Registry is an ordered, validated collection of rules.
type Registry struct {
	byID map[string]interfaces.Rule
}

// New validates and registers rules. Duplicate IDs and incomplete metadata
// are rejected: a rule that cannot describe itself cannot be published.
func New(rules []interfaces.Rule) (*Registry, error) {
	r := &Registry{byID: make(map[string]interfaces.Rule, len(rules))}
	for _, rule := range rules {
		if err := r.Register(rule); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// Register adds a rule.
func (r *Registry) Register(rule interfaces.Rule) error {
	if rule == nil {
		return fmt.Errorf("registry: nil rule")
	}
	meta := rule.Metadata()
	if err := meta.Validate(); err != nil {
		return fmt.Errorf("registry: %w", err)
	}
	if _, exists := r.byID[meta.ID]; exists {
		return fmt.Errorf("registry: duplicate rule ID %q", meta.ID)
	}
	r.byID[meta.ID] = rule
	return nil
}

// List returns every rule ordered by rule ID.
func (r *Registry) List() []interfaces.Rule {
	ids := make([]string, 0, len(r.byID))
	for id := range r.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]interfaces.Rule, 0, len(ids))
	for _, id := range ids {
		out = append(out, r.byID[id])
	}
	return out
}

// Metadata returns every rule's metadata ordered by rule ID.
func (r *Registry) Metadata() []models.RuleMetadata {
	rules := r.List()
	out := make([]models.RuleMetadata, 0, len(rules))
	for _, rule := range rules {
		out = append(out, rule.Metadata())
	}
	return out
}

// Get returns a rule by ID.
func (r *Registry) Get(id string) (interfaces.Rule, bool) {
	rule, ok := r.byID[id]
	return rule, ok
}

// Modules returns the sorted set of known module names.
func (r *Registry) Modules() []string {
	seen := make(map[string]struct{})
	for _, rule := range r.byID {
		seen[rule.Metadata().Module] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for module := range seen {
		out = append(out, module)
	}
	sort.Strings(out)
	return out
}

// Select returns the rules matching the requested modules and rule IDs.
//
// An empty module list means "all modules"; an empty ID list means "every
// rule in the selected modules". When both are provided the selection is the
// intersection. Unknown modules or IDs are an error rather than silently
// ignored, so a typo cannot quietly narrow a scan.
func (r *Registry) Select(modules, ids []string) ([]interfaces.Rule, error) {
	moduleSet := make(map[string]struct{}, len(modules))
	for _, module := range modules {
		module = strings.TrimSpace(module)
		if module == "" {
			continue
		}
		if !contains(r.Modules(), module) {
			return nil, fmt.Errorf("unknown module %q (available: %s)", module, strings.Join(r.Modules(), ", "))
		}
		moduleSet[module] = struct{}{}
	}

	idSet := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := r.byID[id]; !ok {
			return nil, fmt.Errorf("unknown rule %q (see `nulq rules list`)", id)
		}
		idSet[id] = struct{}{}
	}

	selected := make([]interfaces.Rule, 0, len(r.byID))
	for _, rule := range r.List() {
		meta := rule.Metadata()
		if len(moduleSet) > 0 {
			if _, ok := moduleSet[meta.Module]; !ok {
				continue
			}
		}
		if len(idSet) > 0 {
			if _, ok := idSet[meta.ID]; !ok {
				continue
			}
		}
		selected = append(selected, rule)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("rule selection matched no rules")
	}
	return selected, nil
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
