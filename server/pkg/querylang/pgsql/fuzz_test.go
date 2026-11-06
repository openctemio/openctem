package pgsql_test

import (
	"regexp"
	"testing"

	"github.com/openctemio/openctem/api/pkg/querylang"
	"github.com/openctemio/openctem/api/pkg/querylang/pgsql"
)

// FuzzCompile: parse, build and render never panic; every rendered
// statement starts its WHERE with the tenant predicate; no literal that
// is part of the SQL text: replacing every quoted literal with another
// string gives the same SQL (or a query that no longer builds).
func FuzzCompile(f *testing.F) {
	for _, s := range []string{
		`findings where state = open and asset.internet_facing = true | count by asset.type`,
		`findings where tool_name = "'; DROP TABLE findings; --" | count`,
		`findings where text ~ "%' OR 1=1 --" or cve_id in ("a", "b)") | stats avg(cvss_score) by severity`,
		`assets where name ~ "x\") OR (1=1" | bucket first_seen by week`,
		`findings where not (severity = critical) and related_to = me | top 5 by count`,
	} {
		f.Add(s)
	}
	pr := memberOf(tenantA)
	f.Fuzz(func(t *testing.T, src string) {
		q, err := querylang.Parse(src)
		if err != nil {
			return
		}
		p, err := querylang.Build(q, src, pr, querylang.BuildOptions{})
		if err != nil {
			return
		}
		st, err := pgsql.Render(p)
		if err != nil {
			t.Fatalf("Render(%q): %v", src, err)
		}
		if !regexp.MustCompile(`FROM (findings|assets) WHERE (findings|assets)\.tenant_id = \$\d+ AND `).MatchString(st.SQL) {
			t.Fatalf("no leading tenant predicate for %q", src)
		}
		q2, err := querylang.Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		replaceStrings(q2.Where)
		p2, err := querylang.Build(q2, src, pr, querylang.BuildOptions{})
		if err != nil {
			return
		}
		st2, err := pgsql.Render(p2)
		if err != nil {
			t.Fatal(err)
		}
		if st.SQL != st2.SQL {
			t.Fatalf("SQL text depends on a string literal of %q", src)
		}
	})
}

// replaceStrings sets every quoted literal to the same text.
func replaceStrings(e querylang.Expr) {
	fix := func(v *querylang.Value) {
		if v.Kind == querylang.ValString {
			v.Text = "zz"
		}
	}
	switch x := e.(type) {
	case *querylang.Logic:
		for _, t := range x.Terms {
			replaceStrings(t)
		}
	case *querylang.Not:
		replaceStrings(x.X)
	case *querylang.Compare:
		fix(&x.Value)
	case *querylang.In:
		for i := range x.Values {
			fix(&x.Values[i])
		}
	case *querylang.Between:
		fix(&x.Lo)
		fix(&x.Hi)
	case *querylang.Text:
		fix(&x.Value)
	}
}
