package cirun

import "testing"

func TestStrictestPolicy(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	base := DefaultGatePolicy()
	stricter := base
	stricter.FailOnSeverity, stricter.NewFindingsOnly, stricter.EPSSThreshold = "medium", false, f(0.1)
	if !stricter.AtLeastAsStrictAs(base) || base.AtLeastAsStrictAs(stricter) {
		t.Fatal("severity/new-only/EPSS ordering")
	}
	if !base.AtLeastAsStrictAs(base) {
		t.Fatal("a policy is as strict as itself")
	}
	for name, mut := range map[string]func(*GatePolicy){
		"warn":          func(p *GatePolicy) { p.Mode = ModeWarn },
		"disabled":      func(p *GatePolicy) { p.Enabled = false },
		"no kev":        func(p *GatePolicy) { p.FailOnKEV = false },
		"fixable only":  func(p *GatePolicy) { p.FixableOnly = true },
		"severity none": func(p *GatePolicy) { p.FailOnSeverity = SeverityNone },
		"monitor sast": func(p *GatePolicy) {
			p.Modes = PolicyModes{Capabilities: map[string]string{"sast": FindingModeMonitor}}
		},
		"comment rule": func(p *GatePolicy) { p.Modes = PolicyModes{Rules: map[string]string{"r1": FindingModeComment}} },
	} {
		lax := base
		mut(&lax)
		if lax.AtLeastAsStrictAs(base) || !base.AtLeastAsStrictAs(lax) {
			t.Fatalf("%s: not looser", name)
		}
	}
	if i, ok := StrictestPolicy([]GatePolicy{base, stricter}); !ok || i != 1 {
		t.Fatalf("strictest = %d %v", i, ok)
	}
	// Stricter on different settings: none dominates.
	a, b := base, base
	a.FailOnSeverity = "low"
	b.Mode, b.FailOnSeverity = ModeEnforce, "critical"
	b.NewFindingsOnly = false
	if _, ok := StrictestPolicy([]GatePolicy{a, b}); ok {
		t.Fatal("incomparable policies resolved")
	}
}
