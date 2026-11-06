package query_test

// Custom queries over a migrated database: tenant isolation, the data
// scope, the pentest member rule, the mandatory exclusions (drafts,
// branch-only findings, program and deleted assets), user-less API keys,
// every aggregate's SQL, the estimate and the statement timeout.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/query"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/querylang"
)

type qEnv struct {
	t                             *testing.T
	db                            *sql.DB
	svc                           *query.Service
	tenantA, tenantB              shared.ID
	memberA, tester, noScope, own shared.ID
	ownerB                        shared.ID
}

func (e *qEnv) exec(q string, args ...any) {
	e.t.Helper()
	if _, err := e.db.ExecContext(context.Background(), q, args...); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
}

func newQEnv(t *testing.T) *qEnv {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		testdb.Skipf(t, "DATABASE_URL not set to a test database; skipping custom query DB test")
	}
	sqldb, err := sql.Open("postgres", url)
	if err != nil {
		testdb.Skipf(t, "open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		testdb.Skipf(t, "cannot reach DATABASE_URL: %v", err)
	}
	e := &qEnv{t: t, db: sqldb, tenantA: shared.NewID(), tenantB: shared.NewID(),
		memberA: shared.NewID(), tester: shared.NewID(), noScope: shared.NewID(), own: shared.NewID(), ownerB: shared.NewID()}
	e.seed()
	db := &postgres.DB{DB: sqldb}
	enf := datascope.New(postgres.NewDataScopeRepository(db), func(context.Context) datascope.Caller { return datascope.Caller{} }, logger.NewNop())
	e.svc = query.NewService(postgres.NewQueryExecutor(db, 0), enf, logger.NewNop())
	return e
}

func (e *qEnv) seed() {
	a, b := e.tenantA.String(), e.tenantB.String()
	users := []shared.ID{e.memberA, e.tester, e.noScope, e.own, e.ownerB}
	e.t.Cleanup(func() {
		ctx := context.Background()
		for _, t := range []string{a, b} {
			_, _ = e.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, t)
		}
		for _, u := range users {
			_, _ = e.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u.String())
		}
	})
	for _, t := range []string{a, b} {
		e.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, t, "q-"+t)
	}
	for _, u := range users {
		e.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'q')`, u.String(), u.String()+"@q.test")
	}
	for _, m := range []struct {
		u    shared.ID
		t    string
		role string
	}{{e.memberA, a, "member"}, {e.tester, a, "member"}, {e.noScope, a, "member"}, {e.own, a, "owner"}, {e.ownerB, b, "owner"}} {
		e.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, $3)`, m.u.String(), m.t, m.role)
	}
	// Tenant A: A1 (domain, internet facing), B1 (host), P1 (program only),
	// D1 (deleted). memberA's scope: A1, P1, D1. tester's scope: A1.
	asset := func(tenant, name, typ string, extra string) string {
		id := shared.NewID().String()
		e.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, is_internet_accessible, environment) VALUES ($1, $2, $3, $4, $5, 'production')`,
			id, tenant, name, typ, typ == "domain")
		if extra != "" {
			e.exec(`UPDATE assets SET `+extra+` WHERE id = $1`, id)
		}
		return id
	}
	a1 := asset(a, "a1.example.com", "domain", "")
	b1 := asset(a, "b1-host", "host", "")
	p1 := asset(a, "p1.example.com", "domain", "program_only = true")
	d1 := asset(a, "d1.example.com", "domain", "deleted_at = now()")
	x1 := asset(b, "x1.example.com", "domain", "")
	for _, s := range []struct {
		u     shared.ID
		asset string
	}{{e.memberA, a1}, {e.memberA, p1}, {e.memberA, d1}, {e.tester, a1}} {
		e.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
			s.u.String(), a, s.asset)
	}
	camp := shared.NewID().String()
	e.exec(`INSERT INTO pentest_campaigns (id, tenant_id, name) VALUES ($1, $2, 'q-camp')`, camp, a)
	e.exec(`INSERT INTO pentest_campaign_members (tenant_id, campaign_id, user_id, role) VALUES ($1, $2, $3, 'tester')`, a, camp, e.tester.String())
	finding := func(tenant, asset, source, sev, status string, cvss float64, camp any, branchOnly bool) {
		id := shared.NewID().String()
		e.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, cvss_score, epss_score, pentest_campaign_id, branch_only, title)
			VALUES ($1::uuid, $2, $3, $4, 'q-tool', 'q', $5, $1::text, $6, $7, 0.5, $8, $9, 'log4j in q')`,
			id, tenant, asset, source, sev, status, cvss, camp, branchOnly)
		if branchOnly {
			// The insert trigger derives the mark from the branch; set it.
			e.exec(`UPDATE findings SET branch_only = true WHERE id = $1`, id)
		}
	}
	finding(a, a1, "sast", "critical", "confirmed", 9.0, nil, false)   // visible to memberA
	finding(a, a1, "sast", "high", "confirmed", 7.0, nil, false)       // visible to memberA
	finding(a, b1, "sast", "critical", "confirmed", 8.0, nil, false)   // out of memberA's scope
	finding(a, a1, "pentest", "critical", "confirmed", 6, camp, false) // campaign members only
	finding(a, a1, "pentest", "critical", "draft", 6, camp, false)     // never
	finding(a, p1, "sast", "critical", "confirmed", 5, nil, false)     // program asset: never
	finding(a, d1, "sast", "low", "confirmed", 5, nil, false)          // on a deleted asset: counted (findings keep their asset id)
	finding(a, a1, "sast", "critical", "confirmed", 5, nil, true)      // branch only: never
	finding(b, x1, "sast", "critical", "confirmed", 9.9, nil, false)   // tenant B
}

func (e *qEnv) caller(user shared.ID, admin bool, perms ...string) query.Caller {
	tenant := e.tenantA
	if user == e.ownerB {
		tenant = e.tenantB
	}
	if len(perms) == 0 {
		perms = []string{"findings:read", "assets:read"}
	}
	return query.Caller{TenantID: tenant.String(), UserID: user.String(), IsAdmin: admin, Has: func(p string) bool {
		for _, x := range perms {
			if x == p {
				return true
			}
		}
		return false
	}}
}

func (e *qEnv) run(c query.Caller, q string) *query.RunResult {
	e.t.Helper()
	res, err := e.svc.Run(context.Background(), c, q)
	if err != nil {
		e.t.Fatalf("Run(%q): %v", q, err)
	}
	return res
}

func (e *qEnv) count(c query.Caller, q string) int64 {
	e.t.Helper()
	res := e.run(c, q)
	if len(res.Rows) != 1 {
		e.t.Fatalf("%q: %d rows", q, len(res.Rows))
	}
	n, _ := res.Rows[0][len(res.Rows[0])-1].(int64)
	return n
}

func TestQuery_ScopeAndIsolation_DB(t *testing.T) {
	e := newQEnv(t)
	cases := []struct {
		name string
		c    query.Caller
		q    string
		want int64
	}{
		{"member sees own scope, no pentest, no draft, no program, no branch-only", e.caller(e.memberA, false), "findings", 3},
		{"campaign member sees the published pentest finding, never the draft", e.caller(e.tester, false), "findings", 3},
		{"member without scope rows sees nothing", e.caller(e.noScope, false), "findings", 0},
		{"admin sees the tenant, still without drafts, program or branch-only", e.caller(e.own, true), "findings", 5},
		{"other tenant sees only its own", e.caller(e.ownerB, true), "findings", 1},
		{"asking for drafts does not reveal them", e.caller(e.own, true), "findings where status = draft", 0},
		{"asking for branch-only findings does not reveal them", e.caller(e.own, true), "findings where branch_only = true", 0},
		{"filters narrow", e.caller(e.memberA, false), "findings where severity = critical and asset.internet_facing = true", 1},
		{"text search", e.caller(e.memberA, false), `findings where text ~ "LOG4J" and cvss_score >= 7`, 2},
		{"assets: scope, no program, no deleted", e.caller(e.memberA, false), "assets", 1},
		{"assets admin", e.caller(e.own, true), "assets", 2},
		{"assets other tenant", e.caller(e.ownerB, true), "assets where type = domain", 1},
	}
	for _, c := range cases {
		if got := e.count(c.c, c.q); got != c.want {
			t.Errorf("%s: %q = %d, want %d", c.name, c.q, got, c.want)
		}
	}
	// A user-less API key (non-admin) reads nothing scoped.
	key := query.Caller{TenantID: e.tenantA.String(), APIKey: true, Has: func(string) bool { return true }}
	if got := e.count(key, "findings"); got != 0 {
		t.Errorf("user-less key counted %d", got)
	}
}

func TestQuery_AggregatesRun_DB(t *testing.T) {
	e := newQEnv(t)
	admin := e.caller(e.own, true)
	res := e.run(admin, "findings | count by asset.type, severity | sort count desc, asset.type, severity")
	got := make([]string, 0, len(res.Rows))
	for _, r := range res.Rows {
		got = append(got, fmt.Sprint(r...))
	}
	want := "domaincritical2 domainhigh1 domainlow1 hostcritical1"
	// Ties on count break on the groups: only the order of equal counts
	// is fixed by the sort keys.
	if strings.Join(got, " ") != want {
		t.Errorf("count by = %v, want %s", got, want)
	}
	if r := e.run(admin, "findings | stats sum(cvss_score), min(cvss_score), max(cvss_score), median(cvss_score), distinct(asset.type) by severity | sort severity"); len(r.Rows) != 3 {
		t.Errorf("stats rows = %v", r.Rows)
	}
	res = e.run(admin, "findings | stats count(), avg(cvss_score), p90(epss_score) by severity | top 1 by count")
	if len(res.Rows) != 1 || res.Rows[0][0] != "critical" || res.Rows[0][1] != int64(3) || !res.Truncated {
		t.Errorf("stats = %v truncated %v", res.Rows, res.Truncated)
	}
	if v, ok := res.Rows[0][2].(float64); !ok || v < 7.66 || v > 7.67 {
		t.Errorf("avg = %v", res.Rows[0][2])
	}
	res = e.run(admin, "assets | bucket first_seen by day | count by type")
	if len(res.Rows) != 2 {
		t.Errorf("bucket rows = %v", res.Rows)
	}
	if _, ok := res.Rows[0][0].(time.Time); !ok {
		t.Errorf("bucket column is %T", res.Rows[0][0])
	}
	ex, err := e.svc.Explain(context.Background(), e.caller(e.memberA, false), "findings where severity = critical | count by asset.type")
	if err != nil {
		t.Fatal(err)
	}
	if ex.Cost == "" || ex.Scope.Kind != "data_scope" || len(ex.Scope.Rules) < 4 || ex.Description == "" {
		t.Errorf("explain = %+v", ex)
	}
}

func TestQuery_PermissionsAndErrors_DB(t *testing.T) {
	e := newQEnv(t)
	ctx := context.Background()
	_, err := e.svc.Run(ctx, e.caller(e.memberA, false, "findings:read"), "assets | count")
	if _, ok := querylang.AsError(err); !ok {
		t.Errorf("assets without assets:read: %v", err)
	}
	_, err = e.svc.Run(ctx, e.caller(e.memberA, false, "findings:read"), "findings | count by asset.type")
	if qe, ok := querylang.AsError(err); !ok || !strings.Contains(qe.Error(), "cannot group by") {
		t.Errorf("relation without assets:read: %v", err)
	}
	if _, err := e.svc.Schema(ctx, e.caller(e.memberA, false, "findings:read"), "assets"); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("schema without permission: %v", err)
	}
}

// A statement that waits longer than the timeout (here: on a lock another
// transaction holds) ends with querylang.ErrTimeout.
func TestQuery_StatementTimeout_DB(t *testing.T) {
	e := newQEnv(t)
	db := &postgres.DB{DB: e.db}
	enf := datascope.New(postgres.NewDataScopeRepository(db), func(context.Context) datascope.Caller { return datascope.Caller{} }, logger.NewNop())
	svc := query.NewService(postgres.NewQueryExecutor(db, 300*time.Millisecond), enf, logger.NewNop())
	ctx := context.Background()
	tx, err := e.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `LOCK TABLE pentest_campaign_members IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	_, err = svc.Run(ctx, e.caller(e.memberA, false), "findings | count")
	if !errors.Is(err, querylang.ErrTimeout) {
		t.Errorf("want ErrTimeout, got %v", err)
	}
}
