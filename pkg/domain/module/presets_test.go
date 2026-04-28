package module

import (
	"sort"
	"strings"
	"testing"
)

// TestPresetsUnique — two presets sharing an ID break the apply endpoint
// (FindPreset returns the first match, silently misrouting the second).
func TestPresetsUnique(t *testing.T) {
	seen := make(map[string]int)
	for _, p := range ModulePresets {
		seen[p.ID]++
	}
	for id, n := range seen {
		if n > 1 {
			t.Errorf("preset id %q defined %d times", id, n)
		}
	}
}

// TestPresetsHaveRequiredFields — surface incomplete definitions before
// they ship to the UI.
func TestPresetsHaveRequiredFields(t *testing.T) {
	for _, p := range ModulePresets {
		if p.ID == "" {
			t.Errorf("preset has empty ID: %+v", p)
		}
		if p.Name == "" {
			t.Errorf("preset %q has no Name", p.ID)
		}
		if p.Description == "" {
			t.Errorf("preset %q has no Description", p.ID)
		}
		if p.TargetPersona == "" {
			t.Errorf("preset %q has no TargetPersona", p.ID)
		}
		if p.Icon == "" {
			t.Errorf("preset %q has no Icon", p.ID)
		}
		if len(p.KeyOutcomes) == 0 && p.ID != "minimal" {
			// Minimal is allowed to have a short description only.
			t.Errorf("preset %q has no KeyOutcomes", p.ID)
		}
	}
}

// TestPresetsReferenceKnownModules — every module in EnabledModules
// must exist in the in-memory catalogue. A typo here would silently
// skip the module when the preset is applied.
func TestPresetsReferenceKnownModules(t *testing.T) {
	catalogue := knownModuleIDs()
	for _, p := range ModulePresets {
		unknown := make([]string, 0)
		for _, id := range p.EnabledModules {
			// Sub-modules (id contains ".") are implicitly known if
			// their parent is in the catalogue — they don't have
			// individual entries in ModulePermissionMapping.
			if strings.Contains(id, ".") {
				parent := id[:strings.Index(id, ".")]
				if catalogue[parent] {
					continue
				}
			}
			if !catalogue[id] {
				unknown = append(unknown, id)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			t.Errorf("preset %q references unknown module IDs: %v", p.ID, unknown)
		}
	}
}

// TestPresetsSatisfyHardDeps — if a preset enables X, every hard
// transitive dep of X must also be enabled (implicitly via core or
// explicitly in EnabledModules). Otherwise ApplyPreset would produce
// a tenant state the ValidateToggle endpoint immediately rejects.
func TestPresetsSatisfyHardDeps(t *testing.T) {
	for _, p := range ModulePresets {
		p := p
		t.Run(p.ID, func(t *testing.T) {
			resolved := ResolvePresetModules(&p)
			missing := make([]string, 0)
			for mid := range resolved {
				for _, d := range ModuleDependencies[mid] {
					if d.Type != DependencyHard {
						continue
					}
					if !resolved[d.ModuleID] {
						missing = append(missing, mid+" needs "+d.ModuleID)
					}
				}
			}
			if len(missing) > 0 {
				sort.Strings(missing)
				t.Errorf("preset %q has unsatisfied hard deps:\n  %s",
					p.ID, strings.Join(missing, "\n  "))
			}
		})
	}
}

// TestPresetsIncludeCore — every preset must include all core modules,
// even if EnabledModules doesn't list them. ResolvePresetModules
// guarantees this; the test is a belt-and-braces check.
func TestPresetsIncludeCore(t *testing.T) {
	for _, p := range ModulePresets {
		resolved := ResolvePresetModules(&p)
		for coreID := range CoreModuleIDs {
			if !resolved[coreID] {
				t.Errorf("preset %q does not include core module %s", p.ID, coreID)
			}
		}
	}
}

// TestPresetsIncludeMandatory — every preset must auto-include the
// "operational essentials" tier (notification config, integrations
// baseline, RBAC groups, api_keys). ResolvePresetModules guarantees
// this — guard against drift if MandatoryModuleIDs ever changes.
func TestPresetsIncludeMandatory(t *testing.T) {
	for _, p := range ModulePresets {
		resolved := ResolvePresetModules(&p)
		for mandID := range MandatoryModuleIDs {
			if !resolved[mandID] {
				t.Errorf("preset %q does not include mandatory module %s",
					p.ID, mandID)
			}
		}
	}
}

// TestMandatoryModulesExistInCatalog — every ID in MandatoryModuleIDs
// must be a real catalogue entry. A typo or rename would silently
// break every preset apply.
func TestMandatoryModulesExistInCatalog(t *testing.T) {
	cat := knownModuleIDs()
	for id := range MandatoryModuleIDs {
		// Sub-modules (e.g. integrations.notifications) are implicitly
		// known if their parent is in the catalogue.
		if i := indexOfDot(id); i > 0 {
			if cat[id[:i]] {
				continue
			}
		}
		if !cat[id] {
			t.Errorf("MandatoryModuleIDs references unknown module: %s", id)
		}
	}
}

func indexOfDot(s string) int {
	for i, r := range s {
		if r == '.' {
			return i
		}
	}
	return -1
}

// TestFindPreset_Hit — sanity check on the lookup helper.
func TestFindPreset_Hit(t *testing.T) {
	p := FindPreset("vm_essentials")
	if p == nil {
		t.Fatal("vm_essentials preset should exist")
	}
	if p.ID != "vm_essentials" {
		t.Errorf("got preset ID %q, want vm_essentials", p.ID)
	}
}

// TestFindPreset_Miss — unknown IDs return nil (not a zero-value).
func TestFindPreset_Miss(t *testing.T) {
	if FindPreset("does_not_exist") != nil {
		t.Fatal("FindPreset should return nil for unknown preset IDs")
	}
}

// TestDefaultPresetExists — the fallback applied at tenant creation
// when no preset is picked must itself be a valid preset.
func TestDefaultPresetExists(t *testing.T) {
	if FindPreset(DefaultPresetID) == nil {
		t.Fatalf("DefaultPresetID %q does not match any preset", DefaultPresetID)
	}
}

// TestMinimalPresetOnlyCoreAndMandatory — the "minimal" preset is
// supposed to keep its EnabledModules empty so it relies entirely on
// the auto-included tiers (core + mandatory). Drift here (someone
// adds a feature module "because it's useful") would turn the
// sandbox preset into an unintentional default.
func TestMinimalPresetOnlyCoreAndMandatory(t *testing.T) {
	p := FindPreset("minimal")
	if p == nil {
		t.Fatal("minimal preset missing")
	}
	if len(p.EnabledModules) != 0 {
		t.Errorf("minimal preset should have empty EnabledModules; got %v", p.EnabledModules)
	}
	resolved := ResolvePresetModules(p)
	for id := range resolved {
		if CoreModuleIDs[id] || MandatoryModuleIDs[id] {
			continue
		}
		// Sub-modules of a mandatory parent are OK — they're pulled
		// in by sub-module inheritance in service.buildPresetDiff,
		// not by ResolvePresetModules. But ResolvePresetModules also
		// pulls hard transitive deps; those are fine too.
		t.Errorf("minimal preset resolved unexpected non-core, non-mandatory module: %s", id)
	}
}
