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

// The recheck's cause and certificate problem are kept when the platform
// knows them and dropped otherwise; the gap stays either way.
func TestParseCoverageGapsCauseAndCert(t *testing.T) {
	raw := json.RawMessage(`[
		{"host":"a.example.com:443","reason":"breaker_open","cause":"http_reset","cert":"expired"},
		{"host":"b.example.com:443","reason":"breaker_open","cause":"bogus","cert":"bogus"},
		{"host":"c.example.com:443","reason":"breaker_open","cause":7},
		{"host":"d.example.com:443","reason":"breaker_open","cert":"name_mismatch"}
	]`)
	gaps, total := ParseCoverageGaps(raw, 0)
	if total != 4 || len(gaps) != 4 {
		t.Fatalf("%d gaps, total %d: every gap is kept", len(gaps), total)
	}
	want := []struct{ cause, cert string }{{GapCauseHTTPReset, GapCertExpired}, {"", ""}, {"", ""}, {"", GapCertNameMismatch}}
	for i, w := range want {
		if gaps[i].Cause != w.cause || gaps[i].Cert != w.cert {
			t.Errorf("gap %d: %+v", i, gaps[i])
		}
	}
	s := CoverageGapSummary(gaps, total)
	if !strings.Contains(s, "a.example.com:443 (breaker_open: http_reset, certificate expired)") ||
		!strings.Contains(s, "b.example.com:443 (breaker_open)") ||
		!strings.Contains(s, "d.example.com:443 (breaker_open: certificate name mismatch)") {
		t.Fatalf("summary %q", s)
	}
}

func TestParseCoverageGaps_EdgeAndVendor(t *testing.T) {
	list := []map[string]any{
		{"host": "a.example.com", "reason": GapReasonBlocked, "edge": "challenged", "vendor": "DataDome"},
		{"host": "b.example.com", "reason": GapReasonBlocked, "edge": "blocked", "vendor": "cloud-flare_1.x"},
		{"host": "c.example.com", "reason": GapReasonBlocked, "edge": "tarpit", "vendor": "bad vendor"},
		{"host": "d.example.com", "reason": GapReasonBlocked, "edge": "blocked", "vendor": "evil\nvendor"},
		{"host": "e.example.com", "reason": GapReasonBlocked, "vendor": strings.Repeat("v", 33)},
		{"host": "f.example.com", "reason": GapReasonBlocked, "vendor": "-lead"},
		{"host": "g.example.com", "reason": GapReasonRateFloor, "edge": "blocked", "vendor": "datadome"},
		{"host": "h.example.com", "reason": GapReasonBlocked, "edge": 7, "vendor": 9},
		{"host": "i.example.com", "reason": GapReasonBlocked, "vendor": "\x1b[31m"},
	}
	raw, _ := json.Marshal(list)
	gaps, _ := ParseCoverageGaps(raw, 0)
	want := map[string][2]string{
		"a.example.com": {"challenged", "datadome"},
		"b.example.com": {"blocked", "cloud-flare_1.x"},
		"c.example.com": {"", ""},
		"d.example.com": {"blocked", ""},
		"e.example.com": {"", ""},
		"f.example.com": {"", ""},
		"g.example.com": {"", ""},
		"h.example.com": {"", ""},
		"i.example.com": {"", ""},
	}
	if len(gaps) != len(want) {
		t.Fatalf("%d gaps", len(gaps))
	}
	for _, g := range gaps {
		if w := want[g.Host]; g.Edge != w[0] || g.Vendor != w[1] {
			t.Errorf("%s: edge %q vendor %q, want %q %q", g.Host, g.Edge, g.Vendor, w[0], w[1])
		}
	}
}
