package retest

import (
	"strings"
	"testing"
)

func TestDecideToolVerdict(t *testing.T) {
	const fid = "0193a1f0-0000-7000-8000-000000000001"
	const at = "https://h.example/admin"
	exchange := func(url string, status int) string {
		resp := ""
		if status > 0 {
			resp = `,"response":{"status":` + itoa(status) + `}`
		}
		return `[{"kind":"http_exchange","http":{"request":{"method":"GET","url":"` + url + `"}` + resp + `}}]`
	}
	v := func(verdict, extra string) string {
		return `{"metadata":{"retest":{"verdicts":[{"ref":"` + fid + `","verdict":"` + verdict + `"` + extra + `}]}}}`
	}
	cases := []struct {
		name string
		raw  string
		want Outcome
		code ReasonCode
	}{
		{"still present", v("still_present", `,"detail":"matched"`), OutcomeStillVulnerable, ReasonMatched},
		// A bare "fixed" (today's sensors) proves nothing about the endpoint.
		{"bare fixed → not reproduced", v("fixed", ""), OutcomeNotReproduced, ReasonNoEndpointProof},
		{"top-level bare fixed", `{"retest":{"verdicts":[{"ref":"` + fid + `","verdict":"fixed"}]}}`, OutcomeNotReproduced, ReasonNoEndpointProof},
		{"fixed with the endpoint's 404", v("fixed", `,"evidence":`+exchange(at, 404)), OutcomeConfirmedFixed, ReasonNotMatched},
		{"fixed at another path", v("fixed", `,"evidence":`+exchange(at+"/admin", 404)), OutcomeInconclusive, ReasonEndpointMismatch},
		{"fixed with a 403", v("fixed", `,"evidence":`+exchange(at, 403)), OutcomeInconclusive, ReasonBlocked},
		{"fixed without a response", v("fixed", `,"evidence":`+exchange(at, 0)), OutcomeInconclusive, ReasonUnreachable},
		{"unverifiable", v("unverifiable", `,"detail":"timeout"`), OutcomeInconclusive, ReasonUnreachable},
		{"verdict for another finding only", `{"metadata":{"retest":{"verdicts":[{"ref":"0193a1f0-0000-7000-8000-000000000002","verdict":"fixed"}]}}}`, OutcomeInconclusive, ReasonNoResult},
		{"unknown verdict word", v("gone", ""), OutcomeInconclusive, ReasonError},
		{"no verdicts", `{"metadata":{"retest":{"verdicts":[]}}}`, OutcomeInconclusive, ReasonNoResult},
		{"no retest member", `{"status":"completed","metadata":{"outcome":"not_detected"}}`, OutcomeInconclusive, ReasonNoResult},
		{"garbage", `not json`, OutcomeInconclusive, ReasonError},
		{"empty", ``, OutcomeInconclusive, ReasonNoResult},
		{"wrong types", `{"metadata":{"retest":{"verdicts":"fixed"}}}`, OutcomeInconclusive, ReasonError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DecideToolVerdict([]byte(tc.raw), fid, at)
			if got.Verdict.Outcome != tc.want || got.Verdict.Code != tc.code {
				t.Fatalf("= %s/%s (%s), want %s/%s", got.Verdict.Outcome, got.Verdict.Code, got.Verdict.Reason, tc.want, tc.code)
			}
			if got.Verdict.Reason == "" {
				t.Fatal("empty reason")
			}
		})
	}
}

func TestDecideToolVerdictKeepsEvidenceAndDigest(t *testing.T) {
	d := "sha256:" + strings.Repeat("c", 64)
	raw := `{"metadata":{"retest":{"verdicts":[{"ref":"f1","verdict":"fixed","template_digest":"` + d + `","evidence":[` +
		`{"kind":"http_exchange","http":{"request":{"url":"https://h/x","headers":[{"name":"Cookie","value":"sid=abcdef123"}]},"response":{"status":200}}}]}]}}}`
	got := DecideToolVerdict([]byte(raw), "f1", "https://h/x")
	if got.TemplateDigest != d || len(got.Evidence) != 1 || got.Verdict.Outcome != OutcomeConfirmedFixed {
		t.Fatalf("%+v", got)
	}
	bad := DecideToolVerdict([]byte(`{"metadata":{"retest":{"verdicts":[{"ref":"f1","verdict":"still_present","template_digest":"not-a-digest"}]}}}`), "f1", "")
	if bad.TemplateDigest != "" {
		t.Errorf("unsanitized digest kept: %q", bad.TemplateDigest)
	}
}

func TestDecideToolVerdictFirstMatchingRefWins(t *testing.T) {
	raw := `{"metadata":{"retest":{"verdicts":[{"ref":"other","verdict":"fixed"},{"ref":"f1","verdict":"still_present"},{"ref":"f1","verdict":"fixed"}]}}}`
	if got := DecideToolVerdict([]byte(raw), "f1", ""); got.Verdict.Outcome != OutcomeStillVulnerable {
		t.Fatalf("got %s", got.Verdict.Outcome)
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

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
