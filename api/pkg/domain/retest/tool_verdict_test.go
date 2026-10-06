package retest

import (
	"strings"
	"testing"
)

func TestDecideToolVerdict(t *testing.T) {
	const fid = "0193a1f0-0000-7000-8000-000000000001"
	cases := []struct {
		name string
		raw  string
		want Outcome
	}{
		{"nested still present", `{"status":"completed","metadata":{"retest":{"verdicts":[{"ref":"` + fid + `","verdict":"still_present","detail":"matched"}]}}}`, OutcomeStillPresent},
		{"nested fixed", `{"metadata":{"retest":{"verdicts":[{"ref":"` + fid + `","verdict":"fixed"}]}}}`, OutcomeFixed},
		{"top-level fixed", `{"retest":{"verdicts":[{"ref":"` + fid + `","verdict":"fixed"}]}}`, OutcomeFixed},
		{"unverifiable", `{"metadata":{"retest":{"verdicts":[{"ref":"` + fid + `","verdict":"unverifiable","detail":"timeout"}]}}}`, OutcomeUnknown},
		{"verdict for another finding only", `{"metadata":{"retest":{"verdicts":[{"ref":"0193a1f0-0000-7000-8000-000000000002","verdict":"fixed"}]}}}`, OutcomeUnknown},
		{"unknown verdict word", `{"metadata":{"retest":{"verdicts":[{"ref":"` + fid + `","verdict":"gone"}]}}}`, OutcomeUnknown},
		{"no verdicts", `{"metadata":{"retest":{"verdicts":[]}}}`, OutcomeUnknown},
		{"no retest member", `{"status":"completed","metadata":{"outcome":"not_detected"}}`, OutcomeUnknown},
		{"garbage", `not json`, OutcomeUnknown},
		{"empty", ``, OutcomeUnknown},
		{"wrong types", `{"metadata":{"retest":{"verdicts":"fixed"}}}`, OutcomeUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := DecideToolVerdict([]byte(tc.raw), fid)
			if got != tc.want {
				t.Fatalf("outcome = %s (%s), want %s", got, reason, tc.want)
			}
			if reason == "" {
				t.Fatal("empty reason")
			}
		})
	}
}

func TestDecideToolVerdictFirstMatchingRefWins(t *testing.T) {
	const fid = "f1"
	raw := `{"metadata":{"retest":{"verdicts":[{"ref":"other","verdict":"fixed"},{"ref":"f1","verdict":"still_present"},{"ref":"f1","verdict":"fixed"}]}}}`
	if got, _ := DecideToolVerdict([]byte(raw), fid); got != OutcomeStillPresent {
		t.Fatalf("got %s", got)
	}
}

func TestCleanDetail(t *testing.T) {
	in := "line1\nline2\x00\u202e evil\t" + strings.Repeat("é", 400)
	out := CleanDetail(in)
	if strings.ContainsAny(out, "\n\x00\u202e\t") {
		t.Fatalf("control characters kept: %q", out)
	}
	if len(out) > maxVerdictDetail {
		t.Fatalf("len %d > cap", len(out))
	}
	if !strings.HasPrefix(out, "line1 line2 evil") {
		t.Fatalf("got %q", out[:20])
	}
	for _, r := range out {
		if r == '�' {
			t.Fatal("cut inside a rune")
		}
	}
}
