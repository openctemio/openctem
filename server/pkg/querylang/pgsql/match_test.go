package pgsql_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/querylang"
	"github.com/openctemio/openctem/api/pkg/querylang/pgsql"
)

func compile(t *testing.T, src string, pr querylang.Principal) *querylang.Plan {
	t.Helper()
	p, err := querylang.Compile(src, pr, querylang.BuildOptions{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("Compile(%q): %v", src, err)
	}
	return p
}

func TestRenderMatch_KeepsTheCallersRulesAndNarrows(t *testing.T) {
	p := compile(t, `findings where severity = critical`, memberOf(tenantA))
	st, err := pgsql.RenderMatch(p, pgsql.MatchOptions{Limit: 10, ExcludeStatuses: []string{"resolved"},
		ExcludeSources: []string{"pentest"}, ExcludeClaimed: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{st.CountSQL, st.IDsSQL} {
		for _, want := range []string{"findings.tenant_id", "findings.status <> ALL(", "findings.source <> ALL(",
			"remediation_task_members m", "m.left_at IS NULL AND m.role = 'primary'"} {
			if !strings.Contains(sql, want) {
				t.Errorf("statement lacks %q:\n%s", want, sql)
			}
		}
		// Every placeholder is bound.
		for i := 1; i <= len(st.Args); i++ {
			if !strings.Contains(sql, "$"+strconv.Itoa(i)) {
				t.Errorf("$%d unused in %s", i, sql)
			}
		}
		if strings.Contains(sql, "$"+strconv.Itoa(len(st.Args)+1)) {
			t.Errorf("unbound placeholder in %s", sql)
		}
	}
	if !strings.HasSuffix(st.IDsSQL, "LIMIT 11") {
		t.Errorf("ids fetch limit+1: %s", st.IDsSQL)
	}
	if st.Args[0] != tenantA.String() {
		t.Errorf("first arg is the caller's tenant, got %v", st.Args[0])
	}
	// The member's data scope stays in the statement.
	if !strings.Contains(st.CountSQL, "user_accessible_assets") {
		t.Errorf("restricted caller's scope missing: %s", st.CountSQL)
	}
}

func TestRenderMatch_RefusesAggregatesOtherEntitiesAndNoLimit(t *testing.T) {
	for _, src := range []string{`findings | count by severity`, `assets where internet_facing = true`} {
		p := compile(t, src, adminOf(tenantA))
		if _, err := pgsql.RenderMatch(p, pgsql.MatchOptions{Limit: 10}); !errors.Is(err, pgsql.ErrMatchNeedsFilter) {
			t.Errorf("%q: want ErrMatchNeedsFilter, got %v", src, err)
		}
	}
	p := compile(t, `findings where severity = high`, adminOf(tenantA))
	if _, err := pgsql.RenderMatch(p, pgsql.MatchOptions{}); err == nil {
		t.Error("a match without a limit must be refused")
	}
}
