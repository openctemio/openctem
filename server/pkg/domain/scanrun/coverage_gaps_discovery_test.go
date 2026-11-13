package scanrun

import (
	"encoding/json"
	"testing"
)

func TestParseCoverageGaps_PathDiscoveryReasons(t *testing.T) {
	list := json.RawMessage(`[
		{"host": "a.example.test", "reason": "catch_all"},
		{"host": "b.example.test", "reason": "scope_filtered:12"},
		{"host": "c.example.test", "reason": "scope_filtered:x"},
		{"host": "d.example.test", "reason": "made_up"},
		{"host": "e.example.test", "reason": "budget"}]`)
	got, total := ParseCoverageGaps(list, 0)
	if total != 3 || len(got) != 3 {
		t.Fatalf("kept %d (total %d), want catch_all, scope_filtered and budget: %+v", len(got), total, got)
	}
	if got[1].Reason != GapReasonScopeFiltered || got[1].Detail != "12" {
		t.Fatalf("scope_filtered:12 read as %+v", got[1])
	}
}
