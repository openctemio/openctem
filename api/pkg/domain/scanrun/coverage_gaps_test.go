package scanrun

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseCoverageGaps(t *testing.T) {
	var list []map[string]any
	for i := range MaxTaskCoverageGaps + 5 {
		list = append(list, map[string]any{"host": "h" + strings.Repeat("x", i), "reason": GapReasonRateFloor})
	}
	list = append([]map[string]any{
		{"host": "evil\n\x1b[31mhost" + strings.Repeat("y", 400), "reason": GapReasonBlocked, "detail": "a\nb"},
		{"host": "", "reason": GapReasonBlocked},
		{"host": "x", "reason": "unknown"},
		{"host": "p.example.com", "reason": GapReasonProxyUnavailable},
		{"host": 7, "reason": GapReasonBlocked},
	}, list...)
	raw, _ := json.Marshal(list)
	gaps, total := ParseCoverageGaps(raw, 3)
	if len(gaps) != MaxTaskCoverageGaps || total != MaxTaskCoverageGaps+7 {
		t.Fatalf("%d gaps, total %d", len(gaps), total)
	}
	first := gaps[0]
	if strings.ContainsAny(first.Host, "\n\x1b") || len([]rune(first.Host)) > maxGapHostRunes || strings.Contains(first.Detail, "\n") {
		t.Fatalf("not cleaned: %q / %q", first.Host, first.Detail)
	}
	if g, n := ParseCoverageGaps(json.RawMessage(`"nope"`), 5); g != nil || n != 5 {
		t.Fatalf("malformed list: %v %d", g, n)
	}
	if _, n := ParseCoverageGaps(nil, MaxCoverageGapsTotal*10); n != MaxCoverageGapsTotal {
		t.Fatalf("total not capped: %d", n)
	}
}

func TestCoverageGapSummary(t *testing.T) {
	if s := CoverageGapSummary(nil, 0); s != "" {
		t.Fatalf("summary without gaps: %q", s)
	}
	list := []CoverageGap{{Host: "a.example.com", Reason: GapReasonBreakerOpen}, {Host: "b.example.com", Reason: GapReasonBlocked}}
	want := "Completed with 4 host(s) not fully covered: a.example.com (breaker_open), b.example.com (blocked), and 2 more"
	if s := CoverageGapSummary(list, 4); s != want {
		t.Fatalf("summary %q", s)
	}
}
