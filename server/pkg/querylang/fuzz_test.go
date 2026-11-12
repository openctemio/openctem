package querylang

import (
	"reflect"
	"testing"
)

// fuzzSeeds are the committed starting corpus (testdata/fuzz/FuzzParse
// holds the same inputs plus injection-shaped ones).
var fuzzSeeds = []string{
	"findings",
	"where severity = critical",
	`findings where state = open and severity in (critical, high) and asset.internet_facing = true and first_detected_at < -14d | count by asset.type, priority_class`,
	`findings where cve_id = "CVE-2026-1234" or text ~ "log4j" | count by asset.type`,
	`findings where not (a = 1 or b != "x") and c between 1 and 2 and d is not empty`,
	`assets where type in (domain, subdomain) and discovered_at > -7d | bucket discovered_at by day`,
	`findings | stats count(), avg(cvss_score) as a, p90(epss_score) by severity | top 5 by a`,
	`findings | count by severity | sort count desc, severity | limit 10`,
	`findings where title = "'; DROP TABLE findings; --"`,
	`findings where tenant_id = "00000000-0000-0000-0000-000000000000" or 1 = 1`,
	`findings where text ~ "\" OR 1=1 --"`,
	"findings where ((((a = 1))))",
	"findings where a = -1.5e3",
	"findings where a = \"\\x\"",
	"findings | bucket x by fortnight",
	"",
	"|",
	"findings where a = 1 | count by",
}

// FuzzParse: Parse never panics; an error has valid positions; a parsed
// query prints to text that parses to the same tree and prints the same.
func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		q, err := Parse(src)
		if err != nil {
			qe, ok := AsError(err)
			if !ok {
				t.Fatalf("non-positional error %v", err)
			}
			for _, d := range qe.Details {
				if d.Start < 0 || d.End < d.Start || d.End > len(src) || d.Line < 1 || d.Column < 1 {
					t.Fatalf("bad span %+v for %q", d, src)
				}
			}
			return
		}
		out := Format(q)
		q2, err := Parse(out)
		if err != nil {
			t.Fatalf("canonical text %q of %q does not parse: %v", out, src, err)
		}
		if !reflect.DeepEqual(stripSpans(q), stripSpans(q2)) {
			t.Fatalf("round trip changed %q (canonical %q)", src, out)
		}
		if out2 := Format(q2); out2 != out {
			t.Fatalf("printing is not stable: %q then %q", out, out2)
		}
		// Building as a member never panics either.
		_, _ = Build(q, src, memberAll(), BuildOptions{})
	})
}
