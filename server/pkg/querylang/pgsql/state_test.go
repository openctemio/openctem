package pgsql_test

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/server/pkg/querylang"
	"github.com/openctemio/openctem/server/pkg/querylang/pgsql"
)

// The state field compiles to the constant status predicate the findings
// list's state lens uses (one source of truth: the status sets), never a new
// query shape, and the tenant condition stays first and bound.
func TestStateField_CompilesToTheStatusSets(t *testing.T) {
	open := vulnerability.OpenStatusSQL("findings.status")
	closed := vulnerability.FindingLensSQL(vulnerability.FindingLensClosed)
	// Closed is the fixed and dispositioned sets together (order aside).
	for _, s := range append(vulnerability.FixedStatuses(), vulnerability.DispositionedStatuses()...) {
		if !strings.Contains(closed, "'"+string(s)+"'") {
			t.Fatalf("closed lens lacks %s: %s", s, closed)
		}
	}
	cases := []struct{ src, want string }{
		{"findings where state = open", "(" + open + ")"},
		{"findings where state = closed", "(" + closed + ")"},
		{"findings where not (state = closed)", "NOT COALESCE((" + closed + "), FALSE)"},
		{"findings where state = all", "(TRUE)"},
	}
	for _, c := range cases {
		_, st := render(t, c.src, memberOf(tenantA))
		sql := ph.ReplaceAllString(st.SQL, "$$n")
		if !strings.Contains(sql, c.want) {
			t.Errorf("%q: SQL lacks %q\n%s", c.src, c.want, sql)
		}
		if !strings.Contains(sql, " WHERE findings.tenant_id = $n AND ") || st.Args[0] != tenantA.String() {
			t.Errorf("%q: tenant condition changed: %v", c.src, st.Args)
		}
		if strings.Contains(sql, "'open'") || strings.Contains(sql, "'closed'") {
			t.Errorf("%q: lens name reached the SQL", c.src)
		}
	}
	// The short form builds the same statement as the long form.
	for _, pair := range [][2]string{{"state:open", "findings where state = open"}, {"-state:closed", "findings where not (state = closed)"}} {
		q, _, err := querylang.ParseFilter(querylang.Findings, pair[0])
		if err != nil {
			t.Fatal(err)
		}
		p, err := querylang.Build(q, pair[0], memberOf(tenantA), querylang.BuildOptions{})
		if err != nil {
			t.Fatal(err)
		}
		a, err := pgsql.Render(p)
		if err != nil {
			t.Fatal(err)
		}
		_, b := render(t, pair[1], memberOf(tenantA))
		if a.SQL != b.SQL || argText(a.Args) != argText(b.Args) {
			t.Errorf("%q and %q differ:\n%s\n%s", pair[0], pair[1], a.SQL, b.SQL)
		}
	}
}
