package module

import (
	"sort"
	"testing"
)

// TestDetectCycle_GraphIsAcyclic is the CI safety net. A cycle in the
// hard-edge subgraph is a product-design bug — "A requires B which
// requires A" is impossible to satisfy. If this test ever fails, the
// most recent edit to ModuleDependencies introduced the cycle; delete
// or flip the offending edge.
func TestDetectCycle_GraphIsAcyclic(t *testing.T) {
	if cycle := DetectCycle(); cycle != nil {
		t.Fatalf("dependency graph has a hard-edge cycle: %v", cycle)
	}
}

// TestReferencedModulesExist guarantees every module ID mentioned in
// ModuleDependencies (both as a key and as a target) appears in the
// static catalogue used elsewhere in this package (CoreModuleIDs,
// UserFacingModuleIDs, ModulePermissionMapping). Without this, a typo
// in a new edge would silently pass code review and only blow up at
// runtime when a tenant tried to toggle.
func TestReferencedModulesExist(t *testing.T) {
	catalogue := knownModuleIDs()

	missing := make(map[string]bool)
	for dependent, deps := range ModuleDependencies {
		if !catalogue[dependent] {
			missing[dependent] = true
		}
		for _, d := range deps {
			if !catalogue[d.ModuleID] {
				missing[d.ModuleID] = true
			}
		}
	}

	if len(missing) == 0 {
		return
	}
	ids := make([]string, 0, len(missing))
	for id := range missing {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	t.Fatalf("dependency graph references module IDs absent from the in-memory catalogue: %v\n"+
		"(add them to CoreModuleIDs / UserFacingModuleIDs / ModulePermissionMapping in module.go, or fix the typo)",
		ids)
}

// knownModuleIDs unions every module ID enumerated elsewhere in the
// package. ModulePermissionMapping is the most exhaustive list (it
// binds every user-facing module to a read permission); CoreModuleIDs
// and UserFacingModuleIDs are cross-references for safety.
func knownModuleIDs() map[string]bool {
	out := make(map[string]bool)
	for id := range CoreModuleIDs {
		out[id] = true
	}
	for id := range UserFacingModuleIDs {
		out[id] = true
	}
	for id := range ModulePermissionMapping {
		out[id] = true
	}
	return out
}

// TestCanDisable_HardBlockerReturned — disabling `findings` while
// `ai_triage` is enabled must surface ai_triage as a hard blocker.
func TestCanDisable_HardBlockerReturned(t *testing.T) {
	enabled := map[string]bool{
		"findings":  true,
		"ai_triage": true,
	}
	blockers, _ := CanDisable("findings", enabled)
	if len(blockers) == 0 {
		t.Fatal("expected at least one hard blocker; got none")
	}
	found := false
	for _, b := range blockers {
		if b.DependentModuleID == "ai_triage" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ai_triage should be in blockers; got %+v", blockers)
	}
}

// TestCanDisable_NoBlockersWhenDependentDisabled — same setup, but
// ai_triage is disabled — blockers must be empty.
func TestCanDisable_NoBlockersWhenDependentDisabled(t *testing.T) {
	enabled := map[string]bool{
		"findings":  true,
		"ai_triage": false,
	}
	blockers, _ := CanDisable("findings", enabled)
	for _, b := range blockers {
		if b.DependentModuleID == "ai_triage" {
			t.Fatalf("ai_triage is disabled — should not block; got %+v", b)
		}
	}
}

// TestCanDisable_SoftWarning — `priority_rules` depends softly on
// `threat_intel`. Disabling threat_intel while priority_rules is on
// should WARN but not BLOCK.
func TestCanDisable_SoftWarning(t *testing.T) {
	enabled := map[string]bool{
		"findings":       true,
		"threat_intel":   true,
		"priority_rules": true,
	}
	blockers, warnings := CanDisable("threat_intel", enabled)
	for _, b := range blockers {
		if b.DependentModuleID == "priority_rules" {
			t.Fatalf("priority_rules soft-depends on threat_intel, must not block; got %+v", b)
		}
	}
	found := false
	for _, w := range warnings {
		if w.DependentModuleID == "priority_rules" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected soft warning for priority_rules; got warnings=%+v", warnings)
	}
}

// TestRequiredToEnable_MissingHardDeps — enabling `ai_triage` while
// `findings` is off must name findings as required.
func TestRequiredToEnable_MissingHardDeps(t *testing.T) {
	enabled := map[string]bool{
		"findings": false,
	}
	missing := RequiredToEnable("ai_triage", enabled)
	found := false
	for _, d := range missing {
		if d.ModuleID == "findings" && d.Type == DependencyHard {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("findings should be reported as missing hard dep; got %+v", missing)
	}
}

// TestRequiredToEnable_SoftDepsNotReported — soft deps must NOT show
// up as "required" — they only appear in warnings from CanDisable.
func TestRequiredToEnable_SoftDepsNotReported(t *testing.T) {
	enabled := map[string]bool{
		"findings":     true,
		"threat_intel": false, // soft dep of ai_triage
	}
	missing := RequiredToEnable("ai_triage", enabled)
	for _, d := range missing {
		if d.ModuleID == "threat_intel" {
			t.Fatalf("threat_intel is a SOFT dep, must not be required to enable; got %+v", d)
		}
	}
}

// TestTransitiveDependencies_WalksHardEdges — enabling
// `business_impact` transitively requires business_services then
// assets (business_services hard-deps assets).
func TestTransitiveDependencies_WalksHardEdges(t *testing.T) {
	deps := TransitiveDependencies("business_impact")
	want := map[string]bool{"business_services": true, "assets": true}
	for _, d := range deps {
		delete(want, d)
	}
	if len(want) != 0 {
		t.Fatalf("transitive deps missing: %v (got %v)", want, deps)
	}
}

// TestTransitiveDependencies_SkipsSoftEdges — soft deps must NOT appear
// in the transitive closure (they are advisory, not required).
func TestTransitiveDependencies_SkipsSoftEdges(t *testing.T) {
	// ai_triage → findings (hard), ai_triage → threat_intel (soft).
	// Transitive from ai_triage must include findings but NOT threat_intel.
	deps := TransitiveDependencies("ai_triage")
	hasFindings, hasThreat := false, false
	for _, d := range deps {
		switch d {
		case "findings":
			hasFindings = true
		case "threat_intel":
			hasThreat = true
		}
	}
	if !hasFindings {
		t.Fatal("findings must appear in transitive closure of ai_triage")
	}
	if hasThreat {
		t.Fatal("threat_intel is SOFT — must not appear in transitive closure")
	}
}
