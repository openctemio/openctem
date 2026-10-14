package correlation

import (
	"testing"
	"time"
)

func TestPoint_StripsOnlyAnEchoedOutOfBandPayload(t *testing.T) {
	cases := []struct {
		url, loc, wantPath string
	}{
		{"https://h.example/oast.me", "//oast.me", "/"},
		{"https://h.example/interact.sh/en", "//interact.sh/en/", "/"},
		{"https://h.example/a/b.oast.fun", "https://b.oast.fun", "/a"},
		// The evidence does not show it: kept.
		{"https://h.example/oast.me", "", "/oast.me"},
		// Echoed but not an out-of-band domain: kept.
		{"https://h.example/evil.com", "//evil.com", "/evil.com"},
		// A payload that is not the path's tail: kept.
		{"https://h.example/oast.me/admin", "//oast.me", "/oast.me/admin"},
	}
	for _, c := range cases {
		var payloads []string
		if c.loc != "" {
			payloads = []string{c.loc}
		}
		p, ok := Point(PointInput{MatchedURL: c.url, Payloads: payloads})
		if !ok || p.Path != c.wantPath {
			t.Errorf("%s (%q): path %q, want %q", c.url, c.loc, p.Path, c.wantPath)
		}
	}
}

func TestPoint_KeepsSchemeHostPortMethodAndParams(t *testing.T) {
	a, _ := Point(PointInput{MatchedURL: "https://h.example/x?q=1"})
	for _, other := range []PointInput{
		{MatchedURL: "http://h.example/x?q=1"},
		{MatchedURL: "https://www.h.example/x?q=1"},
		{MatchedURL: "https://h.example:8443/x?q=1"},
		{MatchedURL: "https://h.example/x?term=1"},
		{MatchedURL: "https://h.example/x?q=1", Method: "POST"},
		{MatchedURL: "https://h.example/x?q=1", Params: []string{"form:q"}},
	} {
		if b, _ := Point(other); b.Key() == a.Key() {
			t.Errorf("%+v shares the key of %+v", other, a)
		}
	}
	if b, _ := Point(PointInput{MatchedURL: "https://H.example:443/x?q=2"}); b.Key() != a.Key() {
		t.Error("default port or host case split a point")
	}
}

func TestDecide_TiersAndGuardrails(t *testing.T) {
	now := time.Now()
	pt := InjectionPoint{Origin: "https://h", Path: "/", Method: "GET"}
	c := func(id, cve string, cwes []string, age int) Candidate {
		return Candidate{ID: id, AssetID: "a", CVE: cve, CWEs: cwes, Point: pt, Open: true, CreatedAt: now.Add(time.Duration(age) * time.Minute)}
	}
	opt := Options{Auto: true, Suggestions: true}
	p := Decide([]Candidate{c("g", "", []string{"CWE-601"}, 0), c("s", "CVE-1", []string{"CWE-601"}, 1)}, nil, opt)
	if len(p.Link) != 1 || p.Link[0].PrimaryID != "s" || p.Link[0].MemberID != "g" {
		t.Fatalf("generic+specific: %+v", p.Link)
	}
	// Two CVEs: never linked, never suggested together.
	p = Decide([]Candidate{c("a", "CVE-1", []string{"CWE-601"}, 0), c("b", "CVE-2", []string{"CWE-601"}, 1)}, nil, opt)
	if len(p.Link) != 0 || len(p.Suggest) != 0 {
		t.Fatalf("two CVEs: %+v %+v", p.Link, p.Suggest)
	}
	// Generic + generic: suggestion only.
	p = Decide([]Candidate{c("a", "", []string{"CWE-601"}, 0), c("b", "", []string{"CWE-601"}, 1)}, nil, opt)
	if len(p.Link) != 0 || len(p.Suggest) != 1 {
		t.Fatalf("two generics: %+v %+v", p.Link, p.Suggest)
	}
	// A rejected pair is never linked again.
	p = Decide([]Candidate{c("g", "", []string{"CWE-601"}, 0), c("s", "CVE-1", []string{"CWE-601"}, 1)},
		[]Link{{PrimaryID: "s", MemberID: "g", Tier: TierAuto, Rejected: true}}, opt)
	if len(p.Link) != 0 {
		t.Fatal("re-linked a rejected pair")
	}
	// Auto off: an active link is released.
	p = Decide([]Candidate{c("g", "", []string{"CWE-601"}, 0), c("s", "CVE-1", []string{"CWE-601"}, 1)},
		[]Link{{PrimaryID: "s", MemberID: "g", Tier: TierAuto}}, Options{})
	if len(p.Release) != 1 || p.Releases["g"] != "auto_correlation_off" {
		t.Fatalf("switch off: %+v %v", p.Release, p.Releases)
	}
}
