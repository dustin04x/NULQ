// Package rules assembles the detection rule set.
//
// Registration is explicit rather than discovery-based: the binary should
// contain exactly the rules its documentation describes.
package rules

import (
	"github.com/dustin04x/nulq/internal/core/interfaces"
	"github.com/dustin04x/nulq/internal/engine/registry"
	fsrules "github.com/dustin04x/nulq/internal/rules/filesystem"
	identityrules "github.com/dustin04x/nulq/internal/rules/identity"
	processrules "github.com/dustin04x/nulq/internal/rules/process"
	sysrules "github.com/dustin04x/nulq/internal/rules/system"
)

// All returns every registered rule.
func All() []interfaces.Rule {
	return []interfaces.Rule{
		identityrules.NewPrivilegedGroupRule(),
		fsrules.NewSUIDRule(),
		fsrules.NewWorldWritableRule(),
		fsrules.NewPathEntryRule(),
		fsrules.NewMountFlagsRule(),
		processrules.NewWritableParentRule(),
		sysrules.NewSysctlRule(),
		sysrules.NewMACRule(),
		sysrules.NewCapabilitiesRule(),
		sysrules.NewSeccompRule(),
		sysrules.NewSystemdRule(),
		sysrules.NewUsernsRule(),
	}
}

// Registry builds a validated registry of the built-in rules.
func Registry() (*registry.Registry, error) {
	return registry.New(All())
}
