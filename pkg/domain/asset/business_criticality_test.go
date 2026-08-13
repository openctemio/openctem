package asset

import (
	"strings"
	"testing"
)

// TestEffectiveCriticality covers the floor/MAX semantics of the shared
// resolver in isolation: it only ever RAISES (floor), an empty/absent business
// signal ranks lowest and never wins, and the higher of BU vs service wins with
// the reason naming that source. This is the rule both finding-priority and
// asset risk-scoring share, so it is pinned here at the source.
func TestEffectiveCriticality(t *testing.T) {
	cases := []struct {
		name       string
		own        Criticality
		bctx       BusinessContext
		wantCrit   Criticality
		wantReason string // substring; "" = no raise
	}{
		{
			name:     "no business context leaves own criticality",
			own:      CriticalityMedium,
			bctx:     BusinessContext{},
			wantCrit: CriticalityMedium,
		},
		{
			name:       "critical BU raises a medium asset",
			own:        CriticalityMedium,
			bctx:       BusinessContext{BusinessUnitCriticality: CriticalityCritical, BusinessUnitName: "Payments"},
			wantCrit:   CriticalityCritical,
			wantReason: "criticality raised to critical by business unit 'Payments'",
		},
		{
			name:       "critical service raises a medium asset",
			own:        CriticalityMedium,
			bctx:       BusinessContext{BusinessServiceCriticality: CriticalityCritical, BusinessServiceName: "Checkout"},
			wantCrit:   CriticalityCritical,
			wantReason: "criticality raised to critical by business service 'Checkout'",
		},
		{
			name:     "lower BU never lowers the floor",
			own:      CriticalityHigh,
			bctx:     BusinessContext{BusinessUnitCriticality: CriticalityLow, BusinessUnitName: "Lab"},
			wantCrit: CriticalityHigh,
		},
		{
			name:     "equal-criticality BU adds no raise reason",
			own:      CriticalityHigh,
			bctx:     BusinessContext{BusinessUnitCriticality: CriticalityHigh, BusinessUnitName: "Ops"},
			wantCrit: CriticalityHigh,
		},
		{
			name: "highest of BU and service wins",
			own:  CriticalityLow,
			bctx: BusinessContext{
				BusinessUnitCriticality:    CriticalityMedium,
				BusinessUnitName:           "IT",
				BusinessServiceCriticality: CriticalityCritical,
				BusinessServiceName:        "Checkout",
			},
			wantCrit:   CriticalityCritical,
			wantReason: "business service 'Checkout'",
		},
		{
			name: "empty own criticality is raised by any business signal",
			own:  "",
			bctx: BusinessContext{BusinessUnitCriticality: CriticalityLow, BusinessUnitName: "Lab"},
			// "" ranks lowest (Score 0), so even a low BU raises it.
			wantCrit:   CriticalityLow,
			wantReason: "business unit 'Lab'",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := EffectiveCriticality(tc.own, tc.bctx)
			if got != tc.wantCrit {
				t.Fatalf("EffectiveCriticality = %q, want %q", got, tc.wantCrit)
			}
			if tc.wantReason == "" {
				if reason != "" {
					t.Fatalf("expected no raise reason, got %q", reason)
				}
			} else if !strings.Contains(reason, tc.wantReason) {
				t.Fatalf("reason %q does not contain %q", reason, tc.wantReason)
			}
		})
	}
}
