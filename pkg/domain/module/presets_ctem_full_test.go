package module

import "testing"

// gatedModuleIDs mirrors every module id used in a RequireModule(...) route gate
// (internal/infra/http/routes). Keep in sync with those call sites.
//
// Invariant (TestRouteGatesAreGrantableByCTEMFull): a route gated on a module
// that CTEM Full — the "everything" bundle — does NOT grant would return 403 for
// EVERY subscribed tenant, since no bundle enables more than CTEM Full. That is
// exactly the bug where the pipeline gate used bare "pipelines" while presets
// grant "scan_pipelines" (fixed api #305). This guard fails CI if a gate points
// at an id outside the grantable set.
var gatedModuleIDs = []string{
	ModuleCompliance,
	ModuleAttackSimulation,
	ModulePentest,
	ModuleRemediation,
	ModuleScanPipelines,
	ModuleThreatIntel,
	ModuleWorkflows,
}

func TestRouteGatesAreGrantableByCTEMFull(t *testing.T) {
	full := ResolvePresetModules(FindPreset("ctem_full"))
	for _, id := range gatedModuleIDs {
		if CoreModuleIDs[id] || full[id] {
			continue
		}
		t.Errorf("route gate RequireModule(%q) is not granted by CTEM Full nor core — "+
			"subscribed tenants would get 403; align the gate to the id presets grant", id)
	}
}

// legacyDuplicateModuleIDs are single-word module IDs from the original
// migration 000004 seed that were later superseded by a more specific
// vocabulary the presets + dependency graph actually use:
//
//	scope      → scope_config
//	sources    → template_sources
//	pipelines  → scan_pipelines
//	webhooks   → integrations.webhooks
//	secrets    → credentials
//
// They remain seeded as `released` (never deprecated), so they are catalog
// cruft. They are excluded from the "CTEM Full = everything" invariant below
// until they are marked deprecated in the seed. Tracked as a cleanup item; do
// NOT add them to presets (that would surface a second, redundant nav entry).
var legacyDuplicateModuleIDs = map[string]bool{
	"scope":     true,
	"sources":   true,
	"pipelines": true,
	"webhooks":  true,
	"secrets":   true,
}

// TestCTEMFullEnablesEveryRealModule is the drift-guard that would have caught
// the "CTEM Full disables Exposures" bug: the CTEM Full bundle claims "all 5
// phases" / everything, so it must resolve to enable every real (non-core,
// non-legacy-duplicate) module in the catalog. A future module added to the
// catalog but forgotten in presetCTEMFull.EnabledModules fails this test.
func TestCTEMFullEnablesEveryRealModule(t *testing.T) {
	resolved := ResolvePresetModules(FindPreset("ctem_full"))
	for id := range ModulePermissionMapping {
		if CoreModuleIDs[id] || legacyDuplicateModuleIDs[id] {
			continue
		}
		if !resolved[id] {
			t.Errorf("CTEM Full bundle (\"all modules\") omits real module %q — "+
				"add it to presetCTEMFull.EnabledModules, or, if it is legacy "+
				"cruft, deprecate it in the seed and add it to legacyDuplicateModuleIDs", id)
		}
	}
}
