package module

// Module dependency graph — PLATFORM-WIDE STATIC SPEC.
//
// This file is the single source of truth for "module X requires module
// Y". Dependencies describe how features relate structurally — they
// change only when a feature is added or reshaped, which means a code
// commit. So they belong in Go, not the DB. The pattern mirrors
// RolePermissions in pkg/domain/permission/role_mapping.go and the
// ModulePermissionMapping map below in module.go.
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

// ModuleDependencies is the platform-wide dependency graph, keyed by
// the dependent module ID. Core modules (dashboard, assets, findings,
// scans, team, roles, audit, settings) are never listed as keys here
// because the core-module check short-circuits ValidateToggle before
// dependency logic runs — they are structurally un-disable-able.
//
// When adding a new feature, add its entry here. When removing, delete
// the entry AND search for references in values. The unit test
// TestReferencedModulesExist enforces both sides.
var ModuleDependencies = map[string][]Dependency{
	// Scoping cluster ------------------------------------------------------
	"attack_surface": {
		{ModuleID: "assets", Type: DependencyHard, Reason: "attack surface is computed from assets"},
	},
	"scope_config": {
		{ModuleID: "assets", Type: DependencyHard, Reason: "scope rules select assets"},
	},
	"business_services": {
		{ModuleID: "assets", Type: DependencyHard, Reason: "services map to underlying assets"},
	},
	"ctem_cycles": {
		{ModuleID: "scope_config", Type: DependencyHard, Reason: "cycles operate on a defined scope"},
		{ModuleID: "findings", Type: DependencySoft, Reason: "cycle phases reference findings progress"},
	},
	"relationships": {
		{ModuleID: "assets", Type: DependencyHard, Reason: "relationships are between assets"},
	},

	// Discovery ------------------------------------------------------------
	"credentials": {
		{ModuleID: "assets", Type: DependencyHard, Reason: "leaked credentials are scoped to assets"},
	},
	"components": {
		{ModuleID: "assets", Type: DependencyHard, Reason: "components belong to assets (repos, images, runtimes)"},
	},
	"branches": {
		{ModuleID: "assets", Type: DependencyHard, Reason: "branches belong to repository assets"},
	},
	"vulnerabilities": {
		{ModuleID: "findings", Type: DependencyHard, Reason: "vulnerability views list findings of type=vulnerability"},
	},

	// Prioritisation cluster -----------------------------------------------
	"threat_intel": {
		{ModuleID: "findings", Type: DependencyHard, Reason: "threat intel enriches findings"},
	},
	"exposures": {
		{ModuleID: "findings", Type: DependencyHard, Reason: "an exposure is a finding in a specific lifecycle state"},
	},
	"ai_triage": {
		{ModuleID: "findings", Type: DependencyHard, Reason: "triage operates on findings"},
		{ModuleID: "threat_intel", Type: DependencySoft, Reason: "triage uses KEV/EPSS context when scoring"},
	},
	"priority_rules": {
		{ModuleID: "findings", Type: DependencyHard, Reason: "rules classify findings"},
		{ModuleID: "threat_intel", Type: DependencySoft, Reason: "rule conditions often reference KEV/EPSS"},
	},
	"risk_analysis": {
		{ModuleID: "findings", Type: DependencyHard, Reason: "risk scoring reads finding severity + exposure"},
		{ModuleID: "assets", Type: DependencyHard, Reason: "per-asset risk requires the asset inventory"},
	},
	"business_impact": {
		{ModuleID: "business_services", Type: DependencyHard, Reason: "impact scoring is weighted by business-service mapping"},
	},
	"risk_scoring": {
		{ModuleID: "findings", Type: DependencyHard, Reason: "risk scoring operates on findings"},
	},

	// Validation cluster ---------------------------------------------------
	"pentest": {
		{ModuleID: "findings", Type: DependencyHard, Reason: "pentest campaigns produce findings"},
	},
	"attack_simulation": {
		{ModuleID: "attacker_profiles", Type: DependencyHard, Reason: "simulation requires an attacker profile to emulate"},
		{ModuleID: "assets", Type: DependencyHard, Reason: "simulation needs target assets"},
	},
	"control_testing": {
		{ModuleID: "compensating_controls", Type: DependencyHard, Reason: "control testing validates compensating controls"},
	},
	"compensating_controls": {
		{ModuleID: "findings", Type: DependencyHard, Reason: "compensating controls reduce severity of findings"},
	},

	// Mobilisation cluster -------------------------------------------------
	"remediation": {
		{ModuleID: "findings", Type: DependencyHard, Reason: "remediation closes findings"},
	},
	"remediation_tasks": {
		{ModuleID: "remediation", Type: DependencyHard, Reason: "tasks are the operator-facing queue of the remediation engine"},
	},
	"workflows": {
		{ModuleID: "findings", Type: DependencyHard, Reason: "workflow triggers fire on finding lifecycle events"},
		{ModuleID: "integrations", Type: DependencySoft, Reason: "most workflow actions route through integrations (Jira, Slack)"},
	},
	"suppressions": {
		{ModuleID: "findings", Type: DependencyHard, Reason: "suppressions suppress findings"},
	},

	// Insights cluster -----------------------------------------------------
	"reports": {
		{ModuleID: "findings", Type: DependencySoft, Reason: "most report types render finding data"},
	},
	"executive_summary": {
		{ModuleID: "findings", Type: DependencyHard, Reason: "exec summary rolls up finding metrics"},
		{ModuleID: "scans", Type: DependencySoft, Reason: "scan coverage metrics appear on the summary"},
	},
	"ctem_maturity": {
		{ModuleID: "ctem_cycles", Type: DependencyHard, Reason: "maturity is computed across CTEM cycles"},
		{ModuleID: "findings", Type: DependencySoft, Reason: "F3/B4 invariants rely on finding SLA data"},
	},
	"mitre_coverage": {
		{ModuleID: "threat_intel", Type: DependencyHard, Reason: "coverage maps detections to MITRE techniques"},
		{ModuleID: "compensating_controls", Type: DependencySoft, Reason: "control coverage appears on the heatmap"},
	},
	"sbom_export": {
		{ModuleID: "components", Type: DependencyHard, Reason: "SBOM is generated from the component inventory"},
	},

	// Settings -> scanner orchestration ------------------------------------
	"scanner_templates": {
		{ModuleID: "scans", Type: DependencyHard, Reason: "templates are consumed by scans"},
	},
	"template_sources": {
		{ModuleID: "scanner_templates", Type: DependencyHard, Reason: "sources feed the template catalogue"},
	},
	"scan_pipelines": {
		{ModuleID: "scans", Type: DependencyHard, Reason: "pipelines orchestrate scan runs"},
		{ModuleID: "scanner_templates", Type: DependencySoft, Reason: "pipelines typically invoke templates"},
	},
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

// CanDisable checks whether moduleID can be disabled given the set of
// currently-enabled modules. The function walks ModuleDependencies
// backwards: for every module that depends on moduleID, if that
// dependent is enabled, the edge type decides blocker vs warning.
//
// enabledModules MUST already reflect the *current* tenant state (before
// the toggle). A module listed in enabledModules with value false is
// treated as disabled.
//
// Returns two disjoint slices: blockers (hard) and warnings (soft).
// Empty blockers = toggle is allowed.
func CanDisable(moduleID string, enabledModules map[string]bool) (blockers []ToggleBlocker, warnings []ToggleWarning) {
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
