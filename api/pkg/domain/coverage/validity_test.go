package coverage

import "testing"

func TestIsPlatformSide(t *testing.T) {
	for _, c := range []struct {
		outcome  string
		platform bool
	}{
		// Observations of the target or what stands in front of it.
		{"unreachable", false},
		{"timeout", false},
		{"edge_blocked", false},
		{"edge_challenged", false},
		{"rate_limited", false},
		// The check did not run: platform or sensor side.
		{OutcomeNotDispatched, true},
		{OutcomeStalled, true},
		{OutcomeFailed, true},
		{OutcomeUnfinished, true},
		{"tool_error", true},
		{"egress_refused", true},
		{"sensor_network_fault", true},
		// Fail closed: anything unknown is never a fact about the target.
		{"", true},
		{"UNREACHABLE", true},
		{"proxy_unavailable", true},
		{"something_new", true},
	} {
		if got := IsPlatformSide(c.outcome); got != c.platform {
			t.Errorf("IsPlatformSide(%q) = %v, want %v", c.outcome, got, c.platform)
		}
	}
}

// The two lists never overlap, and every known platform-side outcome is
// platform side.
func TestPlatformSideAndObservedAreDisjoint(t *testing.T) {
	observed := map[string]bool{}
	for _, o := range ObservedFailureOutcomes() {
		observed[o] = true
		if IsPlatformSide(o) {
			t.Errorf("observed outcome %q is platform side", o)
		}
	}
	for _, o := range PlatformSideOutcomes() {
		if observed[o] || !IsPlatformSide(o) {
			t.Errorf("platform outcome %q: observed %v, platform side %v", o, observed[o], IsPlatformSide(o))
		}
	}
}

// A sensor-chosen outcome never becomes a metric label.
func TestPlatformOutcomeLabel(t *testing.T) {
	if got := PlatformOutcomeLabel("tool_error"); got != "tool_error" {
		t.Fatalf("known outcome label %q", got)
	}
	for _, o := range []string{"", "x\"}evil", "unreachable", "a-new-class"} {
		if got := PlatformOutcomeLabel(o); got != PlatformOutcomeOther {
			t.Errorf("PlatformOutcomeLabel(%q) = %q, want %q", o, got, PlatformOutcomeOther)
		}
	}
}

// The asset page marks a failed pair whose last outcome is platform side
// (never a target-side or edge outcome, never a pair in another state).
func TestViewMarksPlatformSide(t *testing.T) {
	for _, c := range []struct {
		state   State
		outcome string
		want    bool
	}{
		{StateFailed, OutcomeNotDispatched, true},
		{StateFailed, "tool_error", true},
		{StateFailed, "edge_blocked", false},
		{StateFailed, "rate_limited", false},
		{StatePaused, "unreachable", false},
		{StateCovered, OutcomeOK, false},
		{StateDue, OutcomeNotDispatched, false},
	} {
		var e Entry
		fill(&e, &Row{State: c.state, LastOutcome: c.outcome})
		if e.PlatformSide != c.want {
			t.Errorf("%s/%s: platform_side %v, want %v", c.state, c.outcome, e.PlatformSide, c.want)
		}
	}
}
