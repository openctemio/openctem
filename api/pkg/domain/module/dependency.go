// Package module provides public types and helpers reusable across the codebase.
package module

import "strings"

// Module dependency graph — PLATFORM-WIDE STATIC SPEC.
//
// The edges ("module X requires module Y") are declared in the module
// registry, configs/modules/<id>.yaml (`depends`), and derived into
// ModuleDependencies (registry.go). This file holds the toggle rules that
// read them.
//
// Two edge kinds:
//
//   - DependencyHard — tenant cannot disable the dependency while any
//     module that hard-requires it is still enabled. Example: cannot
//     disable `findings` while `ai_triage` is enabled — there would be
//     nothing to triage. Enforcement: ValidateToggle returns a blocker.
//
//   - DependencySoft — tenant CAN disable, but the UX/behaviour of the
//     dependent module degrades. Example: disabling `threat_intel` while
//     `priority_rules` stays on — rules still run, but KEV/EPSS-derived
//     conditions always return false. Enforcement: ValidateToggle
//     returns a warning for the UI to surface.
//
// The graph is validated by a unit test (DetectCycle + ReferencedModuleIDsExist)
// so CI catches broken edges before deploy.

// DependencyType classifies an edge in the module dependency graph.
type DependencyType string

const (
	// DependencyHard means the dependent module cannot function without the target.
	DependencyHard DependencyType = "hard"
	// DependencySoft means the dependent module works but has degraded features.
	DependencySoft DependencyType = "soft"
)

// Dependency is one edge: "moduleID of the containing map key requires ModuleID".
type Dependency struct {
	ModuleID string
	Type     DependencyType
	Reason   string
}


// ToggleBlocker describes a module that cannot be disabled because
// another still-enabled module hard-depends on it.
type ToggleBlocker struct {
	// BlockedModuleID is the module the caller attempted to disable.
	BlockedModuleID string
	// DependentModuleID is the module that depends on BlockedModuleID
	// and is still enabled, hence blocks the toggle.
	DependentModuleID string
	// Reason is the human-readable sentence from the dependency spec.
	Reason string
}

// ToggleWarning describes soft degradation — the toggle goes through,
// but the dependent module will run with reduced functionality.
type ToggleWarning struct {
	DisabledModuleID  string
	DependentModuleID string
	Reason            string
}

// parentModuleID extracts the parent module for a sub-module ID.
// Sub-modules use the convention "<parent>.<sub>" (e.g. "ai_triage.agent",
// "ai_triage.bulk", "integrations.scm"). Returns empty string when the
// ID has no dot, i.e. is already a top-level module.
func parentModuleID(moduleID string) string {
	if i := strings.Index(moduleID, "."); i > 0 {
		return moduleID[:i]
	}
	return ""
}

// CanDisable checks whether moduleID can be disabled given the set of
// currently-enabled modules. The function walks ModuleDependencies
// backwards: for every module that depends on moduleID, if that
// dependent is enabled, the edge type decides blocker vs warning.
//
// Implicit sub-module cascade: every sub-module "<parent>.<sub>" is
// treated as hard-depending on its parent. Disabling `integrations`
// therefore auto-blocks on every enabled `integrations.*` sub-module without needing
// explicit edges per sub-module in ModuleDependencies. The inverse
// direction (disabling a sub-module) does NOT cascade — sub-modules
// are leaf toggles.
//
// enabledModules MUST already reflect the *current* tenant state (before
// the toggle). A module listed in enabledModules with value false is
// treated as disabled.
//
// Returns two disjoint slices: blockers (hard) and warnings (soft).
// Empty blockers = toggle is allowed.
func CanDisable(moduleID string, enabledModules map[string]bool) (blockers []ToggleBlocker, warnings []ToggleWarning) {
	// Explicit edges from the static graph.
	for dependent, deps := range ModuleDependencies {
		if !enabledModules[dependent] {
			continue
		}
		for _, d := range deps {
			if d.ModuleID != moduleID {
				continue
			}
			switch d.Type {
			case DependencyHard:
				blockers = append(blockers, ToggleBlocker{
					BlockedModuleID:   moduleID,
					DependentModuleID: dependent,
					Reason:            d.Reason,
				})
			case DependencySoft:
				warnings = append(warnings, ToggleWarning{
					DisabledModuleID:  moduleID,
					DependentModuleID: dependent,
					Reason:            d.Reason,
				})
			}
		}
	}
	// Implicit sub-module → parent cascade. If moduleID is a top-level
	// module (no dot), scan every enabled sub-module whose prefix
	// matches and report it as a hard blocker.
	if parentModuleID(moduleID) == "" {
		prefix := moduleID + "."
		for dependent, on := range enabledModules {
			if !on {
				continue
			}
			if !strings.HasPrefix(dependent, prefix) {
				continue
			}
			blockers = append(blockers, ToggleBlocker{
				BlockedModuleID:   moduleID,
				DependentModuleID: dependent,
				Reason:            "sub-module of " + moduleID + " is still enabled",
			})
		}
	}
	return blockers, warnings
}

// RequiredToEnable returns the hard dependencies of moduleID that are
// currently NOT enabled. The caller must enable these first (or enable
// moduleID + its missing hard deps atomically).
func RequiredToEnable(moduleID string, enabledModules map[string]bool) []Dependency {
	deps, ok := ModuleDependencies[moduleID]
	if !ok {
		return nil
	}
	var missing []Dependency
	for _, d := range deps {
		if d.Type != DependencyHard {
			continue
		}
		if !enabledModules[d.ModuleID] {
			missing = append(missing, d)
		}
	}
	return missing
}

// TransitiveDependencies walks hard edges recursively from moduleID and
// returns every module moduleID ultimately needs. The result excludes
// moduleID itself. Stable order for reproducible output. Soft edges are
// intentionally skipped — they describe degradation, not requirement.
func TransitiveDependencies(moduleID string) []string {
	visited := make(map[string]bool)
	var out []string
	var walk func(id string)
	walk = func(id string) {
		for _, d := range ModuleDependencies[id] {
			if d.Type != DependencyHard {
				continue
			}
			if visited[d.ModuleID] {
				continue
			}
			visited[d.ModuleID] = true
			out = append(out, d.ModuleID)
			walk(d.ModuleID)
		}
	}
	walk(moduleID)
	return out
}

// DetectCycle returns the first cycle found in the hard-edge subgraph,
// or nil if acyclic. Cycle is returned as a slice of module IDs in
// traversal order — the last element repeats the first. Used by the
// CI unit test to guarantee the spec is sane; a cycle here would mean
// "A requires B, B requires A" which is a product-design bug.
func DetectCycle() []string {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := make(map[string]int)
	var path []string
	var visit func(id string) []string
	visit = func(id string) []string {
		color[id] = gray
		path = append(path, id)
		for _, d := range ModuleDependencies[id] {
			if d.Type != DependencyHard {
				continue
			}
			switch color[d.ModuleID] {
			case white:
				if c := visit(d.ModuleID); c != nil {
					return c
				}
			case gray:
				// Cycle: slice path from the first occurrence of d.ModuleID.
				for i, p := range path {
					if p == d.ModuleID {
						cycle := append([]string{}, path[i:]...)
						cycle = append(cycle, d.ModuleID)
						return cycle
					}
				}
			}
		}
		path = path[:len(path)-1]
		color[id] = black
		return nil
	}
	for id := range ModuleDependencies {
		if color[id] == white {
			if c := visit(id); c != nil {
				return c
			}
		}
	}
	return nil
}
