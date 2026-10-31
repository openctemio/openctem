package asset

import "testing"

func TestMonitoringStatePrecedence(t *testing.T) {
	cases := []struct {
		name string
		in   MonitoringInputs
		want MonitoringState
	}{
		{"legacy asset in scope", MonitoringInputs{Status: "active", ScopeStatus: "in_scope"}, MonitoringMonitored},
		{"confirmed, unclassified, scanned", MonitoringInputs{AttributionState: "confirmed", Status: "active", ScopeStatus: "not_covered", UnclassifiedScanned: true}, MonitoringMonitored},
		{"unclassified, not scanned", MonitoringInputs{AttributionState: "confirmed", Status: "active", ScopeStatus: "not_covered"}, MonitoringNotMonitored},
		{"internal is governed by zones", MonitoringInputs{Status: "active", ScopeStatus: "internal"}, MonitoringMonitored},
		{"monitor only", MonitoringInputs{AttributionState: "monitor_only", Status: "active", ScopeStatus: "in_scope"}, MonitoringNotMonitored},
		{"candidate", MonitoringInputs{AttributionState: "candidate", Status: "active", ScopeStatus: "in_scope"}, MonitoringUnvalidated},
		{"discovered below the bar", MonitoringInputs{AttributionState: "discovered", Confidence: 89, Status: "active", ScopeStatus: "in_scope"}, MonitoringUnvalidated},
		{"discovered at the bar", MonitoringInputs{AttributionState: "discovered", Confidence: 90, Status: "active", ScopeStatus: "in_scope"}, MonitoringMonitored},
		{"needs review beats unvalidated", MonitoringInputs{AttributionState: "needs_review", Confidence: 10, Status: "active"}, MonitoringPendingDecision},
		{"inactive beats pending", MonitoringInputs{AttributionState: "needs_review", Status: "inactive"}, MonitoringInactive},
		{"archived", MonitoringInputs{Status: "archived", ScopeStatus: "in_scope"}, MonitoringInactive},
		{"do not scan beats inactive", MonitoringInputs{Status: "inactive", ExclusionKinds: []string{"do_not_scan"}}, MonitoringOutOfScope},
		{"retired", MonitoringInputs{Status: "active", ExclusionKinds: []string{"retired"}}, MonitoringOutOfScope},
		{"not ours beats out of scope", MonitoringInputs{Status: "active", ExclusionKinds: []string{"retired", "not_ours"}}, MonitoringIrrelevant},
		{"rejected", MonitoringInputs{AttributionState: "rejected", Status: "active", ScopeStatus: "in_scope"}, MonitoringIrrelevant},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MonitoringStateOf(tc.in); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestValidMonitoringState(t *testing.T) {
	for _, s := range MonitoringStates() {
		if !ValidMonitoringState(string(s)) {
			t.Errorf("%s must be valid", s)
		}
	}
	if ValidMonitoringState("monitored'") {
		t.Error("garbage accepted")
	}
}
