package module

import "testing"

func TestInheritOffFromHardDependencies(t *testing.T) {
	off := map[string]string{
		ModuleScopeConfig:      "not_entitled",
		ModuleScannerTemplates: "read_only_grace",
	}
	from := InheritOffFromHardDependencies(off)

	want := map[string]struct{ reason, from string }{
		// scope_config -> ctem_cycles -> ctem_maturity: the chain takes the root's reason.
		ModuleCTEMCycles:      {"not_entitled", ModuleScopeConfig},
		ModuleCTEMMaturity:    {"not_entitled", ModuleScopeConfig},
		ModuleTemplateSources: {"read_only_grace", ModuleScannerTemplates},
	}
	for id, w := range want {
		if off[id] != w.reason || from[id] != w.from {
			t.Errorf("%s: reason %q from %q, want %q from %q", id, off[id], from[id], w.reason, w.from)
		}
	}
	for _, d := range Registry {
		if d.Core && off[d.ID] != "" {
			t.Errorf("core %s marked off", d.ID)
		}
	}
	// A soft dependency does not switch a module off: priority_rules only
	// softly needs threat_intel, mitre_coverage hard-needs it.
	off2 := map[string]string{ModuleThreatIntel: "not_entitled"}
	InheritOffFromHardDependencies(off2)
	if off2[ModulePriorityRules] != "" {
		t.Errorf("priority_rules off through a soft dependency: %q", off2[ModulePriorityRules])
	}
	if off2[ModuleMITRECoverage] != "not_entitled" {
		t.Errorf("mitre_coverage: %q, want not_entitled", off2[ModuleMITRECoverage])
	}
}

// Every module on: nothing changes.
func TestInheritOffFromHardDependencies_AllOn(t *testing.T) {
	off := map[string]string{}
	if from := InheritOffFromHardDependencies(off); len(from) != 0 || len(off) != 0 {
		t.Fatalf("marked %v", off)
	}
}
