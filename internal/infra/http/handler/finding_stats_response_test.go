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
