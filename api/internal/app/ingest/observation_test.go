package ingest

import (
	"testing"
	"time"

	"github.com/openctemio/ctis/v2"
)

func TestFindingObservedAt(t *testing.T) {
	now := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	fallback := now.Add(-time.Minute)
	seen := now.Add(-48 * time.Hour)
	future := now.Add(time.Hour)
	ancient := time.Date(1990, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		f    *ctis.Finding
		want time.Time
	}{
		{"no finding", nil, fallback},
		{"no time", &ctis.Finding{}, fallback},
		{"the file's time", &ctis.Finding{LastSeenAt: &seen}, seen},
		{"a future time is not an observation", &ctis.Finding{LastSeenAt: &future}, fallback},
		{"a parse accident", &ctis.Finding{LastSeenAt: &ancient}, fallback},
	} {
		if got := findingObservedAt(tc.f, fallback, now); !got.Equal(tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsCompliancePass(t *testing.T) {
	for _, tc := range []struct {
		f    ctis.Finding
		want bool
	}{
		{ctis.Finding{Type: ctis.FindingTypeCompliance, Kind: "pass"}, true},
		{ctis.Finding{Type: ctis.FindingTypeCompliance, Kind: "fail"}, false},
		{ctis.Finding{Type: ctis.FindingTypeCompliance, Kind: "review"}, false},
		{ctis.Finding{Type: ctis.FindingTypeCompliance, Kind: "not_applicable"}, false},
		{ctis.Finding{Type: ctis.FindingTypeVulnerability, Kind: "pass"}, false},
	} {
		if got := isCompliancePass(&tc.f); got != tc.want {
			t.Errorf("%s/%s: %v", tc.f.Type, tc.f.Kind, got)
		}
	}
}

func TestGroupByObservedAt(t *testing.T) {
	t1, t2, fb := time.Unix(1, 0), time.Unix(2, 0), time.Unix(9, 0)
	order, groups := groupByObservedAt([]string{"a", "b", "c", "d"}, map[string]time.Time{"a": t2, "b": t1, "c": t2}, fb)
	if len(order) != 3 || !order[0].Equal(t2) || !order[1].Equal(t1) || !order[2].Equal(fb) {
		t.Fatalf("order = %v", order)
	}
	if len(groups[t2]) != 2 || groups[fb][0] != "d" {
		t.Fatalf("groups = %v", groups)
	}
}
