package querylang

import (
	"encoding/json"
	"testing"
	"time"
)

// shortFuzzSeeds start the short-form corpus, injection-shaped inputs
// included.
var shortFuzzSeeds = []string{
	`severity>=high kev=true -status:accepted last_seen<7d`,
	`(severity=critical OR kev=true) -(port:22,3389) domain=*.example.com`,
	`10.0.0.0/8 fe80::1 CVE-2024-3400 log4j "sql injection"`,
	`port:8000..8999 cvss:7.5.. epss:..0.1 age>30d first_detected_at>2026-01-01`,
	`asset.name=api-?? tool="nu*" file_path~"src/%_\\"`,
	`severity='; DROP TABLE findings; -- OR 1=1`,
	`tenant_id=00000000-0000-0000-0000-000000000000`,
	`text ~ "x" | count`, `findings where a = 1`, `where kev = true`,
	`NOT NOT -(-kev=true)`, `a:`, `:b`, `-`, `"`, `()`, `(((`, `OR`, `AND x`, `x is`, `x is not`,
	"assignee is empty -assignee is not empty",
}

// FuzzParseShort: the short parser never panics; problems have valid
// positions; a built filter prints to text that builds the same document,
// and printing is stable.
func FuzzParseShort(f *testing.F) {
	for _, s := range shortFuzzSeeds {
		f.Add(s)
	}
	opts := BuildOptions{Now: func() time.Time { return testNow }}
	f.Fuzz(func(t *testing.T, src string) {
		q, _, err := ParseFilter(Findings, src)
		if err != nil {
			qe, ok := AsError(err)
			if !ok {
				t.Fatalf("non-positional error %v", err)
			}
			for _, d := range qe.Details {
				if d.Start < 0 || d.End < d.Start || d.End > len(src) || d.Line < 1 || d.Column < 1 || d.Code == "" {
					t.Fatalf("bad problem %+v for %q", d, src)
				}
			}
			return
		}
		p, err := Build(q, src, memberAll(), opts)
		if err != nil {
			if _, ok := AsError(err); !ok {
				t.Fatalf("build: non-positional error %v", err)
			}
			return
		}
		doc := p.FilterDocument()
		q2, err := FromDocument(Findings, doc)
		if err != nil {
			t.Fatalf("FromDocument of %q: %v", src, err)
		}
		text := FormatShort(Findings, q2)
		p2, err := buildFuzz(text, opts)
		if err != nil {
			t.Fatalf("canonical %q of %q does not build: %v", text, src, err)
		}
		a, _ := json.Marshal(canonicalDoc(t, doc))
		b, _ := json.Marshal(canonicalDoc(t, p2.FilterDocument()))
		if string(a) != string(b) {
			t.Fatalf("round trip of %q via %q: %s != %s", src, text, a, b)
		}
		q3, _ := FromDocument(Findings, p2.FilterDocument())
		if again := FormatShort(Findings, q3); again != text {
			t.Fatalf("printing not stable for %q: %q then %q", src, text, again)
		}
	})
}

func buildFuzz(text string, opts BuildOptions) (*Plan, error) {
	q, _, err := ParseFilter(Findings, text)
	if err != nil {
		return nil, err
	}
	return Build(q, text, memberAll(), opts)
}

// canonicalDoc is the document's canonical short text built again, so
// documents that differ only in form (a not over an in, a scalar or a
// one-value list) compare equal.
func canonicalDoc(t *testing.T, doc map[string]any) map[string]any {
	q, err := FromDocument(Findings, doc)
	if err != nil {
		t.Fatal(err)
	}
	p, err := buildFuzz(FormatShort(Findings, q), BuildOptions{Now: func() time.Time { return testNow }})
	if err != nil {
		t.Fatal(err)
	}
	return p.FilterDocument()
}
