package scanrun_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/lib/pq"

	scanrunapp "github.com/openctemio/openctem/server/internal/app/scanrun"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/scanrun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/filterspec"
	"github.com/openctemio/openctem/server/pkg/logger"
)

const wfOne = "00000000-0000-0000-0000-000000000001"

type runsFixture struct {
	db               *sql.DB
	svc              *scanrunapp.Service
	tenantA, tenantB shared.ID
	userScan         string
	managedScan      string
	a, b             map[string]string
}

func openRunDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.PingContext(context.Background()); err != nil {
		testdb.Skipf(t, "cannot reach test DB: %v", err)
	}
	return raw
}

func seedRunTenants(t *testing.T, db *sql.DB, n int) []shared.ID {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `INSERT INTO tenants (id, name, slug)
		SELECT u, 'run list test', 'run-list-' || u::text FROM (SELECT gen_random_uuid() AS u FROM generate_series(1, $1::int)) g
		RETURNING id::text`, n)
	if err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	defer rows.Close()
	var ids []shared.ID
	var strs []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
		strs = append(strs, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = ANY($1::uuid[])`, pq.Array(strs))
	})
	return ids
}

func seedRuns(t *testing.T, db *sql.DB, tenant shared.ID) (userScan, managedScan string, runs map[string]string) {
	t.Helper()
	if err := db.QueryRowContext(context.Background(), `INSERT INTO scans (tenant_id, name, scan_type, scanner_name, schedule_type, targets)
		VALUES ($1, 'user scan', 'single', 'nuclei', 'manual', ARRAY['example.com']) RETURNING id::text`, tenant.String()).Scan(&userScan); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(context.Background(), `INSERT INTO scans (tenant_id, name, scan_type, scanner_name, schedule_type, targets, ad_hoc, managed_by, managed_key)
		VALUES ($1, 'managed scan', 'single', 'nuclei', 'manual', ARRAY['example.com'], true, 'coverage', 'k') RETURNING id::text`, tenant.String()).Scan(&managedScan); err != nil {
		t.Fatal(err)
	}
	runs = map[string]string{}
	add := func(key, kind, status, trigger, scanID string, findings int, minutesAgo int, done bool) {
		t.Helper()
		wf := "NULL"
		if kind == "scan" || kind == "quick" {
			wf = "'" + wfOne + "'"
		}
		sc := "NULL"
		if scanID != "" {
			sc = "'" + scanID + "'"
		}
		completed := "NULL"
		if done {
			completed = fmt.Sprintf("now() - interval '%d minutes' + interval '90 seconds'", minutesAgo)
		}
		q := fmt.Sprintf(`INSERT INTO scan_runs (tenant_id, scan_workflow_id, scan_id, kind, status, trigger_type, total_findings, created_at, started_at, completed_at)
			VALUES ($1, %s, %s, $2, $3, $4, $5, now() - interval '%d minutes', now() - interval '%d minutes', %s) RETURNING id::text`, wf, sc, minutesAgo, minutesAgo, completed)
		var id string
		if err := db.QueryRowContext(context.Background(), q, tenant.String(), kind, status, trigger, findings).Scan(&id); err != nil {
			t.Fatalf("seed run %s: %v", key, err)
		}
		runs[key] = id
	}
	add("done", "scan", "completed", "manual", userScan, 12, 50, true)
	add("failed", "scan", "failed", "schedule", userScan, 0, 40, true)
	add("running", "scan", "running", "api", userScan, 3, 30, false)
	add("quick", "quick", "completed", "manual", "", 1, 20, true)
	add("managed", "scan", "completed", "system", managedScan, 4, 15, true)
	add("retest", "retest", "completed", "manual", "", 0, 10, true)
	add("validation", "validation", "completed", "manual", "", 0, 9, true)
	add("system", "system", "completed", "system", "", 0, 5, true)
	return userScan, managedScan, runs
}

func newRunsFixture(t *testing.T) *runsFixture {
	t.Helper()
	db := openRunDB(t)
	tenants := seedRunTenants(t, db, 2)
	f := &runsFixture{db: db, tenantA: tenants[0], tenantB: tenants[1]}
	f.userScan, f.managedScan, f.a = seedRuns(t, db, f.tenantA)
	_, _, f.b = seedRuns(t, db, f.tenantB)
	f.svc = scanrunapp.NewService(nil, nil, postgres.NewScanRunRepository(&postgres.DB{DB: db}), nil, nil, nil, nil, logger.NewNop())
	return f
}

var runListOpts = filterspec.Options{Unknown: filterspec.UnknownStrict, Extra: []string{"include_system"}}

func listRunsBySpec(t *testing.T, f *runsFixture, tenant shared.ID, q url.Values, hideFindingRuns bool) ([]string, int64) {
	t.Helper()
	spec, err := filterspec.ParseValues(q, scanrun.RunFields, runListOpts)
	if err != nil {
		t.Fatalf("parse %v: %v", q, err)
	}
	res, err := f.svc.ListRunsBySpec(context.Background(), tenant.String(), spec, q.Get("include_system") == "true", hideFindingRuns)
	if err != nil {
		t.Fatalf("list %v: %v", q, err)
	}
	ids := make([]string, len(res.Data))
	for i, r := range res.Data {
		ids[i] = r.ID.String()
	}
	return ids, res.Total
}

func oldRunInput(tenant shared.ID, q url.Values, exclude []string) scanrunapp.ListRunsInput {
	atoi := func(s string) int {
		var n int
		_, _ = fmt.Sscan(s, &n)
		return n
	}
	var kinds []string
	if v := q.Get("kind"); v != "" {
		kinds = strings.Split(v, ",")
	}
	return scanrunapp.ListRunsInput{
		TenantID: tenant.String(), ScanWorkflowID: q.Get("scan_workflow_id"), ScanID: q.Get("scan_id"), Kinds: kinds,
		IncludeSystem: q.Get("include_system") == "true", Origin: q.Get("origin"), AssetID: q.Get("asset_id"), Status: q.Get("status"),
		ExcludeKinds: exclude, Sort: q.Get("sort"), Page: atoi(q.Get("page")), PerPage: atoi(q.Get("per_page")),
	}
}

// The old params keep returning the same runs in the same order.
func TestListRunsBySpec_ParityWithTheOldList(t *testing.T) {
	f := newRunsFixture(t)
	ctx := context.Background()
	for _, c := range []struct {
		name    string
		q       url.Values
		exclude []string
	}{
		{"no params", url.Values{}, nil},
		{"status", url.Values{"status": {"completed"}}, nil},
		{"scan_id", url.Values{"scan_id": {f.userScan}}, nil},
		{"scan_workflow_id", url.Values{"scan_workflow_id": {wfOne}}, nil},
		{"kind list", url.Values{"kind": {"retest,validation"}}, nil},
		{"kind system names it", url.Values{"kind": {"system"}}, nil},
		{"include_system", url.Values{"include_system": {"true"}}, nil},
		{"origin system", url.Values{"origin": {"system"}}, nil},
		{"origin user", url.Values{"origin": {"user"}}, nil},
		{"finding runs hidden", url.Values{}, []string{"retest", "validation"}},
		{"finding runs hidden with include_system", url.Values{"include_system": {"true"}}, []string{"retest", "validation"}},
		{"sort total_findings", url.Values{"sort": {"-total_findings"}}, nil},
		{"sort started_at", url.Values{"sort": {"started_at"}}, nil},
		{"sort -completed_at", url.Values{"sort": {"-completed_at"}}, nil},
		{"paged", url.Values{"page": {"2"}, "per_page": {"2"}}, nil},
		{"status and origin", url.Values{"status": {"completed"}, "origin": {"system"}}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			want, err := f.svc.ListRuns(ctx, oldRunInput(f.tenantA, c.q, c.exclude))
			if err != nil {
				t.Fatal(err)
			}
			wantIDs := make([]string, len(want.Data))
			for i, r := range want.Data {
				wantIDs[i] = r.ID.String()
			}
			got, total := listRunsBySpec(t, f, f.tenantA, c.q, len(c.exclude) > 0)
			if strings.Contains(c.q.Get("sort"), "total_findings") {
				// runs that tie on the sort key come in id order, not reverse id order
				sort.Strings(got)
				sort.Strings(wantIDs)
			}
			if !reflect.DeepEqual(got, wantIDs) || total != want.Total {
				t.Errorf("new list = %v (total %d), old list = %v (total %d)", got, total, wantIDs, want.Total)
			}
		})
	}
}

func TestListRunsBySpec_NewFields(t *testing.T) {
	f := newRunsFixture(t)
	names := func(q url.Values) []string {
		ids, _ := listRunsBySpec(t, f, f.tenantA, q, false)
		inv := map[string]string{}
		for k, v := range f.a {
			inv[v] = k
		}
		out := make([]string, len(ids))
		for i, id := range ids {
			out[i] = inv[id]
		}
		return out
	}
	if got := names(url.Values{"trigger_type": {"schedule"}}); !reflect.DeepEqual(got, []string{"failed"}) {
		t.Errorf("trigger_type = %v", got)
	}
	if got := names(url.Values{"total_findings_gte": {"4"}, "sort": {"total_findings"}}); !reflect.DeepEqual(got, []string{"managed", "done"}) {
		t.Errorf("total_findings_gte = %v", got)
	}
	// 90 seconds for every finished run, none for the open one.
	if got := names(url.Values{"duration_gte": {"90"}, "kind": {"scan"}}); len(got) != 3 {
		t.Errorf("duration_gte = %v", got)
	}
	if got := names(url.Values{"duration": {"90"}, "status": {"running"}}); len(got) != 0 {
		t.Errorf("an open run has a duration: %v", got)
	}
	if got := names(url.Values{"started_at_lt": {"-PT35M"}}); !reflect.DeepEqual(got, []string{"failed", "done"}) {
		t.Errorf("started_at_lt = %v", got)
	}
}

func TestListRunsBySpec_TenantIsolation(t *testing.T) {
	f := newRunsFixture(t)
	inB := map[string]bool{}
	var bIDs []string
	for _, id := range f.b {
		inB[id] = true
		bIDs = append(bIDs, id)
	}
	for name, q := range map[string]url.Values{
		"no filter":    {"include_system": {"true"}},
		"B's ids":      {"id": {strings.Join(bIDs, ",")}, "include_system": {"true"}},
		"B's workflow": {"scan_workflow_id": {wfOne}, "include_system": {"true"}},
		"origin":       {"origin": {"system"}, "include_system": {"true"}},
		"status":       {"status": {"completed"}, "include_system": {"true"}},
	} {
		ids, _ := listRunsBySpec(t, f, f.tenantA, q, false)
		for _, id := range ids {
			if inB[id] {
				t.Errorf("%s: tenant B's run %s listed for tenant A", name, id)
			}
		}
	}
	if ids, total := listRunsBySpec(t, f, f.tenantA, url.Values{"id": {strings.Join(bIDs, ",")}, "include_system": {"true"}}, false); len(ids) != 0 || total != 0 {
		t.Errorf("tenant A reads tenant B's runs by id: %v", ids)
	}
	// Tenant B's managed scan does not make tenant A's run "system".
	if ids, _ := listRunsBySpec(t, f, f.tenantA, url.Values{"origin": {"system"}}, false); len(ids) != 1 || ids[0] != f.a["managed"] {
		t.Errorf("origin=system = %v, want tenant A's one managed run", ids)
	}
}

func TestListRunsBySpec_PlanUsesAnIndex(t *testing.T) {
	db := openRunDB(t)
	owner := testdb.OpenMigrator(t)
	tenants := seedRunTenants(t, db, 25)
	ids := make([]string, len(tenants))
	for i, id := range tenants {
		ids[i] = id.String()
	}
	if _, err := owner.ExecContext(context.Background(), `INSERT INTO scan_runs (tenant_id, scan_workflow_id, kind, status, trigger_type, total_findings, created_at, started_at, completed_at)
		SELECT t, $2::uuid, (ARRAY['scan','quick','system'])[1 + g % 3], (ARRAY['completed','failed','running'])[1 + g % 3], 'manual', g % 9,
		       now() - (g || ' minutes')::interval, now() - (g || ' minutes')::interval, now() - (g || ' minutes')::interval + interval '1 minute'
		FROM unnest($1::uuid[]) t, generate_series(1, 400) g`, pq.Array(ids), wfOne); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := owner.ExecContext(context.Background(), `ANALYZE scan_runs`); err != nil {
		t.Fatal(err)
	}
	actor, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: tenants[0]})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"", "status=failed", "kind=scan", "trigger_type=manual", "scan_id=" + shared.NewID().String(),
		"scan_workflow_id=" + wfOne, "asset_id=" + shared.NewID().String(), "created_at_gte=-PT2H", "started_at_lt=-PT2H",
		"completed_at_gte=-PT2H", "total_findings_gte=5", "duration_gte=30", "origin=user", "origin=system", "sort=-total_findings",
		"sort=-started_at", "id=" + shared.NewID().String(),
	} {
		vals, _ := url.ParseQuery(q)
		spec, err := filterspec.ParseValues(vals, scanrun.RunFields, runListOpts)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		w, err := filterspec.Compile(scanrun.RunListRules(spec, false, true), scanrun.RunFields, actor)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		var raw []byte
		if err := db.QueryRowContext(context.Background(), "EXPLAIN (FORMAT JSON) SELECT id FROM scan_runs WHERE "+w.SQL+" ORDER BY "+w.OrderBy+" LIMIT 20", w.Args...).Scan(&raw); err != nil {
			t.Fatalf("%q: explain: %v\n%s", q, err, w.SQL)
		}
		if node := seqScan(t, raw, "scan_runs"); node != "" {
			t.Errorf("%q: the plan reads the whole scan_runs table (%s)\n%s", q, node, w.SQL)
		}
	}
}

func seqScan(t *testing.T, raw []byte, table string) string {
	t.Helper()
	var plans []struct {
		Plan map[string]any `json:"Plan"`
	}
	if err := json.Unmarshal(raw, &plans); err != nil || len(plans) == 0 {
		t.Fatalf("explain output: %v %s", err, raw)
	}
	var walk func(n map[string]any) string
	walk = func(n map[string]any) string {
		if n["Node Type"] == "Seq Scan" && n["Relation Name"] == table {
			return "Seq Scan on " + table
		}
		kids, _ := n["Plans"].([]any)
		for _, k := range kids {
			if m, ok := k.(map[string]any); ok {
				if s := walk(m); s != "" {
					return s
				}
			}
		}
		return ""
	}
	return walk(plans[0].Plan)
}
