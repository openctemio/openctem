package pgsql_test

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/querylang"
	"github.com/openctemio/openctem/api/pkg/querylang/pgsql"
)

// A short-form search compiles to the same SQL text whatever its literals
// are: every value is a bound parameter, never part of the statement.
func TestShortForm_LiteralsNeverReachSQL(t *testing.T) {
	const tpl = `tool=VAL rule:VAL,"VAL2" file_path~"VAL-long" asset.domain=example.com cve=VAL asset.name=VAL* last_seen<7d severity>=high ip=10.1.2.3 TEXTVAL`
	literals := [][2]string{
		{"abc", "def"},
		{`x';DROP_TABLE_findings;--`, `y"z`},
		{`p%_q`, `\\`},
	}
	var first string
	built := 0
	for _, l := range literals {
		src := strings.NewReplacer("TEXTVAL", "word"+l[0], "VAL2", l[1], "VAL", l[0]).Replace(tpl)
		src = strings.ReplaceAll(src, `"`+l[1]+`"`, `"`+strings.ReplaceAll(l[1], `"`, `\"`)+`"`)
		q, _, err := querylang.ParseFilter(querylang.Findings, src)
		if err != nil {
			// Shapes the domain or glob checks refuse are fine: nothing runs.
			t.Logf("%q: %v", src, err)
			continue
		}
		p, err := querylang.Build(q, src, memberOf(tenantA), querylang.BuildOptions{})
		if err != nil {
			t.Logf("%q: %v", src, err)
			continue
		}
		st, err := pgsql.RenderMatch(p, pgsql.MatchOptions{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(st.IDsSQL, l[0]) || strings.Contains(st.IDsSQL, "DROP") {
			t.Fatalf("a literal reached the SQL: %s", st.IDsSQL)
		}
		built++
		if first == "" {
			first = st.IDsSQL
		} else if st.IDsSQL != first {
			t.Fatalf("SQL text depends on the literals:\n%s\n%s", first, st.IDsSQL)
		}
	}
	if built != len(literals) {
		t.Fatalf("%d of %d variants built", built, len(literals))
	}
}
