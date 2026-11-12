package vulnevent

import (
	"testing"
	"time"
)

func kinds(evs []Event) []Kind {
	out := make([]Kind, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Kind)
	}
	return out
}

func TestDiff(t *testing.T) {
	now := time.Date(2026, 10, 19, 8, 0, 0, 0, time.UTC)
	recent := now.Add(-24 * time.Hour)
	old := now.Add(-90 * 24 * time.Hour)
	f := func(v float64) *float64 { return &v }
	base := State{VulnID: "CVE-2026-1", Status: "Analyzed", Severity: "HIGH", CVSSScore: f(7.5),
		ProductIDs: []string{"a", "b"}, RangeCount: 2, Published: &old}

	cases := []struct {
		name string
		prev *State
		cur  State
		want []Kind
	}{
		{"new recent CVE with products", nil, State{VulnID: "CVE-2026-1", Published: &recent, ProductIDs: []string{"a"}, RangeCount: 1}, []Kind{KindPublished}},
		{"new old CVE with products", nil, State{VulnID: "CVE-2026-1", Published: &old, ProductIDs: []string{"a"}, RangeCount: 1}, []Kind{KindRangesAdded}},
		{"new CVE without products", nil, State{VulnID: "CVE-2026-1", Published: &recent}, nil},
		{"first products later", &State{VulnID: "CVE-2026-1", Published: &old}, State{VulnID: "CVE-2026-1", Published: &old, ProductIDs: []string{"a"}, RangeCount: 1}, []Kind{KindRangesAdded}},
		{"description edit", &base, base, nil},
		{"new product", &base, func() State { s := base; s.ProductIDs = []string{"a", "b", "c"}; s.RangeCount = 3; return s }(), []Kind{KindRangesWidened}},
		{"more ranges same products", &base, func() State { s := base; s.RangeCount = 4; return s }(), []Kind{KindRangesWidened}},
		{"narrowed", &base, func() State { s := base; s.ProductIDs = []string{"a"}; s.RangeCount = 1; return s }(), nil},
		{"severity up", &base, func() State { s := base; s.Severity = "CRITICAL"; s.CVSSScore = f(9.1); return s }(), []Kind{KindSeverityUp}},
		{"cvss inside band", &base, func() State { s := base; s.CVSSScore = f(8.2); return s }(), nil},
		{"cvss crosses 9 in same band", &State{VulnID: "CVE-2026-1", Severity: "CRITICAL", CVSSScore: f(8.9), ProductIDs: []string{"a"}, RangeCount: 1},
			State{VulnID: "CVE-2026-1", Severity: "CRITICAL", CVSSScore: f(9.3), ProductIDs: []string{"a"}, RangeCount: 1}, []Kind{KindSeverityUp}},
		{"severity down", &base, func() State { s := base; s.Severity = "MEDIUM"; return s }(), nil},
		{"rejected", &base, func() State { s := base; s.Status = "Rejected"; return s }(), []Kind{KindRejected}},
		{"withdrawn", &base, func() State { s := base; s.Status = "Withdrawn"; return s }(), []Kind{KindRejected}},
		{"rejected again", func() *State { s := base; s.Status = "Rejected"; return &s }(), func() State { s := base; s.Status = "Rejected"; return s }(), nil},
		{"never seen and rejected", nil, State{VulnID: "CVE-2026-1", Status: "Rejected"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := kinds(Diff(c.prev, c.cur, now))
			if len(got) != len(c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("got %v, want %v", got, c.want)
				}
			}
		})
	}
}

func TestDiffCarriesSourceAndSequence(t *testing.T) {
	now := time.Now().UTC()
	pub := now.Add(-time.Hour)
	evs := Diff(nil, State{VulnID: "CVE-2026-2", Published: &pub, ProductIDs: []string{"p"}, RangeCount: 1, FeedSequence: 42}, now)
	if len(evs) != 1 || evs[0].SourceAt == nil || !evs[0].SourceAt.Equal(pub) || evs[0].FeedSequence == nil || *evs[0].FeedSequence != 42 {
		t.Fatalf("event: %+v", evs)
	}
}

func TestEPSSBand(t *testing.T) {
	for score, want := range map[float64]int{0: 0, 0.099: 0, 0.1: 1, 0.49: 1, 0.5: 2, 0.97: 2} {
		if got := EPSSBand(score); got != want {
			t.Errorf("EPSSBand(%v) = %d, want %d", score, got, want)
		}
	}
}
