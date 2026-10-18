package pgsql_test

import (
	"database/sql/driver"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/querylang"
	"github.com/openctemio/openctem/api/pkg/querylang/pgsql"
)

var update = flag.Bool("update", false, "rewrite the golden files")

var (
	tenantA = shared.MustIDFromString("11111111-1111-1111-1111-111111111111")
	tenantB = shared.MustIDFromString("33333333-3333-3333-3333-333333333333")
	userA   = shared.MustIDFromString("22222222-2222-2222-2222-222222222222")
	now     = time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
)

func all(string) bool { return true }

func memberOf(tenant shared.ID) querylang.Principal {
	return querylang.Principal{TenantID: tenant, UserID: userA, Scope: &shared.DataScope{TenantID: tenant, UserID: userA}, Has: all}
}

func adminOf(tenant shared.ID) querylang.Principal {
	return querylang.Principal{TenantID: tenant, UserID: userA, Admin: true,
		Scope: &shared.DataScope{TenantID: tenant, UserID: userA, Unrestricted: true}}
}

func render(t testing.TB, src string, pr querylang.Principal) (*querylang.Plan, *pgsql.Statement) {
	t.Helper()
	p, err := querylang.Compile(src, pr, querylang.BuildOptions{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("Compile(%q): %v", src, err)
	}
	st, err := pgsql.Render(p)
	if err != nil {
		t.Fatalf("Render(%q): %v", src, err)
	}
	return p, st
}

// argText prints bound values, arrays through their driver encoding.
func argText(args []any) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if v, ok := a.(driver.Valuer); ok {
			dv, _ := v.Value()
			a = dv
		}
		out = append(out, fmt.Sprintf("%v", a))
	}
	return "[" + strings.Join(out, " ") + "]"
}

var (
	ws = regexp.MustCompile(`\s+`)
	ph = regexp.MustCompile(`\$\d+`)
)

// TestGolden pins text -> canonical text -> SQL + args for representative
// queries (go test ./pkg/querylang/pgsql -run TestGolden -update).
func TestGolden(t *testing.T) {
	cases := []struct {
		name, src string
		pr        querylang.Principal
	}{
		{"count_member", "findings", memberOf(tenantA)},
		{"count_admin", "findings", adminOf(tenantA)},
		{"ciso_kpi", "findings where state = open and severity = critical and is_in_kev = true and asset.internet_facing = true and first_detected_at < -14d | count", memberOf(tenantA)},
		{"heatmap", "findings where state = open | count by asset.environment, priority_class", memberOf(tenantA)},
		{"hunting", `findings where cve_id = "CVE-2026-1234" or text ~ "log4j" | count by asset.type`, memberOf(tenantA)},
		{"stats_top", "findings where state = open | stats count(), avg(cvss_score), p90(epss_score), distinct(cve_id) by severity | top 3 by avg_cvss_score", memberOf(tenantA)},
		{"bucket", "assets where type in (domain, subdomain) and discovered_at > -7d | bucket discovered_at by day", memberOf(tenantA)},
		{"assets_between", "assets where risk_score between 50 and 90 and not tag in (pci, \"lab env\") | stats median(risk_score) by criticality | sort criticality | limit 10", adminOf(tenantA)},
	}
	for _, c := range cases {
		p, st := render(t, c.src, c.pr)
		got := fmt.Sprintf("-- %s\n%s\n\n%s\n\nargs: %v\n", querylang.Format(p.Query()), querylang.Describe(p),
			ws.ReplaceAllString(st.SQL, " "), argText(st.Args))
		path := filepath.Join("testdata", "golden", c.name+".sql")
		if *update {
			_ = os.MkdirAll(filepath.Dir(path), 0o755)
			if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v (run with -update)", c.name, err)
		}
		if string(want) != got {
			t.Errorf("%s: SQL changed\n got: %s\nwant: %s", c.name, got, want)
		}
	}
}

// Every statement carries the tenant predicate, the caller's scope, the
// member rule (non-administrators) and the mandatory exclusions.
func TestInjectedPredicates(t *testing.T) {
	queries := []string{
		"findings",
		"findings where severity = critical or status = draft",
		"findings where not (severity = critical) | count by severity",
		"findings where branch_only = true | stats avg(cvss_score) by asset.type",
	}
	for _, q := range queries {
		_, st := render(t, q, memberOf(tenantA))
		sql := ph.ReplaceAllString(st.SQL, "$$n")
		for _, want := range []string{
			" WHERE findings.tenant_id = $n AND ",
			"user_accessible_assets uaa WHERE uaa.user_id = $n AND uaa.tenant_id = $n",
			"findings.source <> 'pentest' OR findings.pentest_campaign_id IN (",
			"findings.status <> ALL(",
			"findings.branch_only = ",
			"a.program_only",
		} {
			if !strings.Contains(sql, want) {
				t.Errorf("%q: SQL lacks %q", q, want)
			}
		}
		for _, a := range st.Args {
			if s, ok := a.(string); ok && s == tenantB.String() {
				t.Errorf("%q: another tenant in args", q)
			}
		}
		if st.Args[0] != tenantA.String() {
			t.Errorf("%q: first arg %v is not the tenant", q, st.Args[0])
		}
	}
	_, st := render(t, "findings", adminOf(tenantA))
	st.SQL = ph.ReplaceAllString(st.SQL, "$$n")
	if strings.Contains(st.SQL, "pentest_campaign_members") || strings.Contains(st.SQL, "user_accessible_assets") {
		t.Error("admin got the member rule or scope rows")
	}
	if !strings.Contains(st.SQL, "findings.tenant_id = $n") || !strings.Contains(st.SQL, "a.program_only") || !strings.Contains(st.SQL, "ph.program_only") {
		t.Error("admin lost the tenant, mandatory or hidden-program predicate")
	}
	_, st = render(t, "assets | count by type", memberOf(tenantA))
	st.SQL = ph.ReplaceAllString(st.SQL, "$$n")
	for _, want := range []string{"assets.tenant_id = $n", "assets.id IN (SELECT uaa.asset_id", "assets.deleted_at IS NOT NULL", "assets.program_only"} {
		if !strings.Contains(st.SQL, want) {
			t.Errorf("assets SQL lacks %q", want)
		}
	}
}

// Injection attempts either fail to compile or reach the database only as
// bound parameters: their text never appears in the SQL.
func TestInjection(t *testing.T) {
	payloads := []string{
		`'; DROP TABLE findings; --`,
		`" OR 1=1 --`,
		`x') OR ('1'='1`,
		`{tenant}`,
		`{arg}`,
		`\'; SELECT pg_sleep(10); --`,
		"a b",
		`%_\`,
	}
	templates := []string{
		`findings where tool_name = %s`,
		`findings where tool_name in (%s, "x")`,
		`findings where text ~ %s`,
		`findings where file_path ~ %s`,
		`assets where name ~ %s | count by type`,
		`findings where asset.tag = %s | count by asset.type`,
		`findings where cve_id != %s`,
	}
	for _, tpl := range templates {
		for _, p := range payloads {
			src := fmt.Sprintf(tpl, querylang.Quote(p))
			pl, err := querylang.Compile(src, memberOf(tenantA), querylang.BuildOptions{})
			if err != nil {
				continue // rejected is fine
			}
			st, err := pgsql.Render(pl)
			if err != nil {
				t.Fatalf("%q: %v", src, err)
			}
			if strings.Contains(st.SQL, p) {
				t.Errorf("%q: payload in SQL text", src)
			}
		}
	}
	// Unquoted attempts never parse or never compile.
	for _, src := range []string{
		"findings where severity = critical; DROP TABLE findings",
		"findings where severity = critical -- comment",
		"findings where severity = critical /* x */",
		"findings where tenant_id = '11111111-1111-1111-1111-111111111111'",
		"findings where findings.tenant_id = x",
		"findings where severity = critical union select 1",
		"findings | count by tenant_id",
		"findings | stats sum(tenant_id)",
		"findings | count by severity | sort 1",
		"findings | count by severity | sort count; drop",
		"users | count",
		"credentials | count",
		"audit | count",
	} {
		if _, err := querylang.Compile(src, memberOf(tenantA), querylang.BuildOptions{}); err == nil {
			t.Errorf("%q compiled", src)
		}
	}
}

// Bindings cover every dimension, measure and time of every entity, with
// constant SQL only.
func TestBindingsComplete(t *testing.T) {
	for _, name := range querylang.EntityNames() {
		ent, _ := querylang.Lookup(name)
		check := func(path, field string) {
			e, err := pgsql.Expr(ent, path, field)
			if err != nil {
				t.Errorf("%s.%s: %v", name, path, err)
				return
			}
			if strings.Contains(e, "{arg}") || strings.Contains(e, "{user}") {
				t.Errorf("%s.%s: binding takes a value", name, path)
			}
			if strings.Contains(e, "SELECT") && !strings.Contains(e, "tenant_id = {tenant}") {
				t.Errorf("%s.%s: relation binding without a tenant predicate", name, path)
			}
		}
		for _, p := range ent.Dimensions() {
			check(p, ent.Dimension(p))
		}
		for _, p := range ent.Measures() {
			check(p, ent.Measure(p))
		}
		for _, p := range ent.Times() {
			check(p, ent.Time(p))
		}
	}
}

func TestLimitPlusOne(t *testing.T) {
	_, st := render(t, "findings | count by severity | top 7 by count", memberOf(tenantA))
	if st.Limit != 7 || !strings.HasSuffix(st.SQL, " LIMIT 8") {
		t.Errorf("limit %d sql %q", st.Limit, st.SQL[len(st.SQL)-20:])
	}
	_, st = render(t, "findings | count by severity", memberOf(tenantA))
	if !strings.HasSuffix(st.SQL, " LIMIT 1001") {
		t.Error("default cap is not 1000 + 1")
	}
	_, st = render(t, "findings | count", memberOf(tenantA))
	if strings.Contains(st.SQL, "LIMIT") || st.Grouped {
		t.Error("single-row aggregate grouped")
	}
}

const benchQuery = `findings where state = open and severity in (critical, high) and asset.internet_facing = true and first_detected_at < -14d and text ~ "log4j" | stats count(), avg(cvss_score) by asset.type, priority_class | top 10 by count`

func BenchmarkParse(b *testing.B) {
	for b.Loop() {
		if _, err := querylang.Parse(benchQuery); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompile(b *testing.B) {
	pr := memberOf(tenantA)
	for b.Loop() {
		if _, err := querylang.Compile(benchQuery, pr, querylang.BuildOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompileAndRender(b *testing.B) {
	pr := memberOf(tenantA)
	for b.Loop() {
		p, err := querylang.Compile(benchQuery, pr, querylang.BuildOptions{})
		if err != nil {
			b.Fatal(err)
		}
		if _, err := pgsql.Render(p); err != nil {
			b.Fatal(err)
		}
	}
}
