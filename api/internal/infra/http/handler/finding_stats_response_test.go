package handler

import (
	"encoding/json"
	"testing"
)

// The Findings page reads its headline numbers (in KEV, overdue SLA) from
// /findings/stats instead of issuing one list request per number. Lock the
// wire names it depends on.
func TestFindingStatsResponseRiskCountNames(t *testing.T) {
	b, err := json.Marshal(FindingStatsResponse{KevOpen: 3, EpssHighOpen: 2, SLABreached: 5})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]float64{"kev_open": 3, "epss_high_open": 2, "sla_breached": 5}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v (json: %s)", k, got[k], v, b)
		}
	}
}

// The overview strip and the state tabs read one response (research/81):
// lock the wire names of the open-scoped aggregates.
func TestFindingStatsResponseOverviewNames(t *testing.T) {
	b, err := json.Marshal(FindingStatsResponse{
		OpenBySeverity:       map[string]int64{"critical": 4},
		AwaitingVerification: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got["awaiting_verification"] != float64(2) {
		t.Errorf("awaiting_verification = %v (json: %s)", got["awaiting_verification"], b)
	}
	sev, ok := got["open_by_severity"].(map[string]any)
	if !ok || sev["critical"] != float64(4) {
		t.Errorf("open_by_severity = %v (json: %s)", got["open_by_severity"], b)
	}
}
