package scan_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/lib/pq"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/filterspec"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// System workflows the migrations seed; a scan of type workflow needs one.
const (
	wfOne = "00000000-0000-0000-0000-000000000001"
	wfTwo = "a0000002-0000-0000-0000-000000000004"
)

type scansFixture struct {
	db      *sql.DB
	svc     *scanapp.Service
	tenantA shared.ID
	tenantB shared.ID
	groupA  string
	groupA2 string
	// ids by name, per tenant
	a, b map[string]string
}

func seedScanTenants(t *testing.T, db *sql.DB, n int) []shared.ID {
	t.Helper()
	rows, err := db.QueryContext(context.Background(), `INSERT INTO tenants (id, name, slug)
		SELECT u, 'scan list test', 'scan-list-' || u::text FROM (SELECT gen_random_uuid() AS u FROM generate_series(1, $1::int)) g
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

func openScanDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	if err := raw.PingContext(context.Background()); err != nil {
		testdb.Skipf(t, "cannot reach test DB: %v", err)
	}
	return raw
}

// seedScans plants one tenant's scans: saved, paused, workflow, quick
// (ad hoc), archived and platform-managed ones, with the columns the list
// filters read.
func seedScans(t *testing.T, db *sql.DB, tenant shared.ID, group, group2 string) map[string]string {
	t.Helper()
	ids := map[string]string{}
	add := func(key, name, desc, typ, schedule, status string, tags []string, extra ...[2]string) {
		t.Helper()
		var id string
		scanner, wf := "nuclei", "NULL"
		if typ == "workflow" {
			scanner, wf = "", "'"+wfOne+"'"
		}
		q := fmt.Sprintf(`INSERT INTO scans (tenant_id, name, description, scan_type, scanner_name, scan_workflow_id, schedule_type, status, tags, targets %s)
			VALUES ($1, $2, $3, $4, NULLIF($5, ''), %s, $6, $7, $8, ARRAY['example.com'] %s) RETURNING id::text`, columnsOf(extra), wf, valuesOf(extra))
		if err := db.QueryRowContext(context.Background(), q, tenant.String(), name, desc, typ, scanner, schedule, status, pq.Array(tags)).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
		ids[key] = id
	}
	add("nightly", "Nightly external", "perimeter sweep", "single", "daily", "active", []string{"prod", "edge"}, [2]string{"total_runs", "5"}, [2]string{"failed_runs", "1"}, [2]string{"last_run_at", "now() - interval '1 day'"}, [2]string{"next_run_at", "now() + interval '1 day'"})
	add("weekly", "Weekly internal", "the nightly job's sibling", "single", "weekly", "paused", []string{"prod"}, [2]string{"total_runs", "2"}, [2]string{"last_run_at", "now() - interval '3 days'"})
	add("workflow", "Full recon", "", "workflow", "manual", "active", nil, [2]string{"total_runs", "9"}, [2]string{"sensor_preference", "'platform'"})
	add("never", "Never run", "", "single", "monthly", "disabled", []string{"lab"}, [2]string{"total_runs", "0"})
	add("quick", "Quick one-off", "", "single", "manual", "active", nil, [2]string{"ad_hoc", "true"}, [2]string{"total_runs", "1"})
	add("archived", "Old one-off", "", "single", "manual", "active", nil, [2]string{"archived_at", "now()"})
	add("managed", "Coverage scan", "", "single", "daily", "active", nil, [2]string{"ad_hoc", "true"}, [2]string{"managed_by", "'coverage'"}, [2]string{"managed_key", "'k1'"})
	add("grouped", "Grouped scan", "", "single", "daily", "active", []string{"edge"}, [2]string{"asset_group_id", "'" + group + "'"}, [2]string{"asset_group_ids", "ARRAY['" + group + "','" + group2 + "']::uuid[]"})
	return ids
}

// columnsOf and valuesOf turn {column, expression} pairs into SQL column and
// value lists (test data only; nothing here is request input).
func columnsOf(extra [][2]string) string {
	var cols []string
	for _, kv := range extra {
		cols = append(cols, kv[0])
	}
	if len(cols) == 0 {
		return ""
	}
	return ", " + strings.Join(cols, ", ")
}

func valuesOf(extra [][2]string) string {
	var vals []string
	for _, kv := range extra {
		vals = append(vals, kv[1])
	}
	if len(vals) == 0 {
		return ""
	}
	return ", " + strings.Join(vals, ", ")
}

func newScansFixture(t *testing.T) *scansFixture {
	t.Helper()
	db := openScanDB(t)
	tenants := seedScanTenants(t, db, 2)
	f := &scansFixture{db: db, tenantA: tenants[0], tenantB: tenants[1]}
	for _, g := range []*string{&f.groupA, &f.groupA2} {
		if err := db.QueryRowContext(context.Background(), `INSERT INTO asset_groups (tenant_id, name) VALUES ($1, $2) RETURNING id::text`,
			f.tenantA.String(), "group "+shared.NewID().String()).Scan(g); err != nil {
			t.Fatalf("seed group: %v", err)
		}
	}
	groupB := ""
	if err := db.QueryRowContext(context.Background(), `INSERT INTO asset_groups (tenant_id, name) VALUES ($1, 'b') RETURNING id::text`, f.tenantB.String()).Scan(&groupB); err != nil {
		t.Fatal(err)
	}
	f.a = seedScans(t, db, f.tenantA, f.groupA, f.groupA2)
	f.b = seedScans(t, db, f.tenantB, groupB, groupB)
	f.svc = scanapp.NewService(postgres.NewScanRepository(&postgres.DB{DB: db}), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, logger.NewNop())
	return f
}

// oldInput maps list params the way GET /scans did before the list query
// contract (the oracle of the parity test).
func oldInput(tenant shared.ID, q url.Values) scanapp.ListScansInput {
	atoi := func(s string) int {
		var n int
		_, _ = fmt.Sscan(s, &n)
		return n
	}
	var tags []string
	if v := q.Get("tags"); v != "" {
		tags = strings.Split(v, ",")
	}
	return scanapp.ListScansInput{
		TenantID: tenant.String(), AssetGroupID: q.Get("asset_group_id"), ScanWorkflowID: q.Get("scan_workflow_id"),
		ScanType: q.Get("scan_type"), ScheduleType: q.Get("schedule_type"), Status: q.Get("status"), Tags: tags,
		Search: q.Get("search"), IncludeAdHoc: q.Get("include_ad_hoc") == "true", Origin: q.Get("origin"),
		Sort: q.Get("sort"), Page: atoi(q.Get("page")), PerPage: atoi(q.Get("per_page")),
	}
}

var scanListOpts = filterspec.Options{Unknown: filterspec.UnknownStrict, Extra: []string{"include_ad_hoc"}}

func listBySpec(t *testing.T, f *scansFixture, tenant shared.ID, q url.Values) ([]string, int64) {
	t.Helper()
	spec, err := filterspec.ParseValues(q, scan.Fields, scanListOpts)
	if err != nil {
		t.Fatalf("parse %v: %v", q, err)
	}
	res, err := f.svc.ListScansBySpec(context.Background(), tenant.String(), spec, q.Get("include_ad_hoc") == "true")
	if err != nil {
		t.Fatalf("list %v: %v", q, err)
	}
	ids := make([]string, len(res.Data))
	for i, s := range res.Data {
		ids[i] = s.ID.String()
	}
	return ids, res.Total
}

// The old params keep returning the same scans, in the same order, as the
// request the list contract spells canonically.
func TestListScansBySpec_ParityWithTheOldList(t *testing.T) {
	f := newScansFixture(t)
	ctx := context.Background()
	for _, c := range []struct {
		name string
		q    url.Values
	}{
		{"no params", url.Values{}},
		{"status", url.Values{"status": {"active"}}},
		{"scan_type", url.Values{"scan_type": {"workflow"}}},
		{"schedule_type", url.Values{"schedule_type": {"daily"}}},
		{"search by name", url.Values{"search": {"nightly"}}},
		{"search by description", url.Values{"search": {"sibling"}}},
		{"search escapes LIKE", url.Values{"search": {"100%"}}},
		{"tags", url.Values{"tags": {"prod,lab"}}},
		{"origin system", url.Values{"origin": {"system"}}},
		{"origin user", url.Values{"origin": {"user"}}},
		{"include_ad_hoc", url.Values{"include_ad_hoc": {"true"}}},
		{"include_ad_hoc and origin user", url.Values{"include_ad_hoc": {"true"}, "origin": {"user"}}},
		{"workflow", url.Values{"scan_workflow_id": {wfOne}}},
		{"another workflow", url.Values{"scan_workflow_id": {wfTwo}}},
		{"sort -total_runs", url.Values{"sort": {"-total_runs"}}},
		{"sort last_run_at", url.Values{"sort": {"last_run_at"}}},
		{"sort -last_run_at", url.Values{"sort": {"-last_run_at"}}},
		{"sort -next_run_at", url.Values{"sort": {"-next_run_at"}}},
		{"sort -created_at paged", url.Values{"sort": {"-created_at"}, "page": {"2"}, "per_page": {"2"}}},
		{"everything", url.Values{"status": {"active"}, "scan_type": {"single"}, "schedule_type": {"daily"}, "tags": {"edge"}, "search": {"scan"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			want, err := f.svc.ListScans(ctx, oldInput(f.tenantA, c.q))
			if err != nil {
				t.Fatal(err)
			}
			wantIDs := make([]string, len(want.Data))
			for i, s := range want.Data {
				wantIDs[i] = s.ID.String()
			}
			// the same request, old names where the registry kept them as aliases
			got, total := listBySpec(t, f, f.tenantA, c.q)
			if !reflect.DeepEqual(got, wantIDs) || total != want.Total {
				t.Errorf("new list = %v (total %d), old list = %v (total %d)", got, total, wantIDs, want.Total)
			}
			// ... and with the canonical names
			canon := url.Values{}
			for k, v := range c.q {
				switch k {
				case "search":
					canon["q"] = v
				case "tags":
					canon["tag"] = v
				default:
					canon[k] = v
				}
			}
			got2, total2 := listBySpec(t, f, f.tenantA, canon)
			if !reflect.DeepEqual(got2, got) || total2 != total {
				t.Errorf("canonical request = %v (total %d), alias request = %v (total %d)", got2, total2, got, total)
			}
		})
	}
}

// The default list shows saved scans only; the rules hold whatever the
// filter says.
func TestListScansBySpec_VisibilityRules(t *testing.T) {
	f := newScansFixture(t)
	names := func(q url.Values) []string {
		ids, _ := listBySpec(t, f, f.tenantA, q)
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
	has := func(list []string, k string) bool {
		for _, x := range list {
			if x == k {
				return true
			}
		}
		return false
	}
	def := names(url.Values{})
	for _, hidden := range []string{"quick", "archived", "managed"} {
		if has(def, hidden) {
			t.Errorf("default list shows %s", hidden)
		}
	}
	if !has(def, "nightly") || !has(def, "workflow") {
		t.Errorf("default list lost saved scans: %v", def)
	}
	withAdHoc := names(url.Values{"include_ad_hoc": {"true"}})
	if !has(withAdHoc, "quick") || !has(withAdHoc, "managed") || has(withAdHoc, "archived") {
		t.Errorf("include_ad_hoc list = %v", withAdHoc)
	}
	system := names(url.Values{"origin": {"system"}})
	if len(system) != 1 || system[0] != "managed" {
		t.Errorf("origin=system = %v, want only the managed scan", system)
	}
	// An id filter does not reach an archived scan.
	if got := names(url.Values{"id": {f.a["archived"]}}); len(got) != 0 {
		t.Errorf("archived scan listed by id: %v", got)
	}
}

// The document endpoint applies the same registry and rules.
func TestListScansBySpec_DocumentMatchesParams(t *testing.T) {
	f := newScansFixture(t)
	ctx := context.Background()
	doc := `{"v":1,"filter":{"any":[{"field":"status","op":"in","value":["paused"]},{"field":"total_runs","op":"gte","value":9}]},"sort":["name"]}`
	spec, err := filterspec.ParseDocument([]byte(doc), scan.Fields, scanListOpts)
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.svc.ListScansBySpec(ctx, f.tenantA.String(), spec, false)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range res.Data {
		names = append(names, s.Name)
	}
	if !reflect.DeepEqual(names, []string{"Full recon", "Weekly internal"}) {
		t.Errorf("document list = %v", names)
	}
	// The document cannot lift the visibility rules.
	all := `{"v":1,"filter":{"any":[{"field":"origin","op":"eq","value":"system"},{"field":"status","op":"in","value":["active"]}]}}`
	spec, err = filterspec.ParseDocument([]byte(all), scan.Fields, scanListOpts)
	if err != nil {
		t.Fatal(err)
	}
	res, err = f.svc.ListScansBySpec(ctx, f.tenantA.String(), spec, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range res.Data {
		if s.AdHoc || s.Name == "Old one-off" {
			t.Errorf("document listed %q (ad hoc %v)", s.Name, s.AdHoc)
		}
	}
}

// Another tenant's scans never appear, whatever the filter names.
func TestListScansBySpec_TenantIsolation(t *testing.T) {
	f := newScansFixture(t)
	ctx := context.Background()
	inB := map[string]bool{}
	for _, id := range f.b {
		inB[id] = true
	}
	var bIDs []string
	for _, id := range f.b {
		bIDs = append(bIDs, id)
	}
	for name, q := range map[string]url.Values{
		"no filter":     {"include_ad_hoc": {"true"}},
		"by B's ids":    {"id": {strings.Join(bIDs, ",")}, "include_ad_hoc": {"true"}},
		"by B's name":   {"name_contains": {"Nightly"}},
		"B's workflow":  {"scan_workflow_id": {wfOne}},
		"B's origin":    {"origin": {"system"}},
		"tag":           {"tag": {"prod"}},
		"asset group":   {"asset_group_id": {f.groupA}},
		"search":        {"q": {"nightly"}},
		"permissive id": {"id_not": {f.a["nightly"]}, "include_ad_hoc": {"true"}},
	} {
		ids, _ := listBySpec(t, f, f.tenantA, q)
		for _, id := range ids {
			if inB[id] {
				t.Errorf("%s: tenant B's scan %s listed for tenant A", name, id)
			}
		}
	}
	if ids, total := listBySpec(t, f, f.tenantA, url.Values{"id": {strings.Join(bIDs, ",")}, "include_ad_hoc": {"true"}}); len(ids) != 0 || total != 0 {
		t.Errorf("tenant A reads tenant B's scans by id: %v", ids)
	}
	// the document path
	doc, _ := json.Marshal(map[string]any{"v": 1, "filter": map[string]any{"field": "id", "op": "in", "value": bIDs}})
	spec, err := filterspec.ParseDocument(doc, scan.Fields, scanListOpts)
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.svc.ListScansBySpec(ctx, f.tenantA.String(), spec, true)
	if err != nil || res.Total != 0 {
		t.Errorf("document by B's ids = %d rows, %v", res.Total, err)
	}
}

func TestListScansBySpec_AssetGroupMatchesTheLegacyAndTheListColumn(t *testing.T) {
	f := newScansFixture(t)
	for _, g := range []string{f.groupA, f.groupA2} {
		ids, _ := listBySpec(t, f, f.tenantA, url.Values{"asset_group_id": {g}})
		if len(ids) != 1 || ids[0] != f.a["grouped"] {
			t.Errorf("asset_group_id=%s = %v, want the grouped scan", g, ids)
		}
	}
}

// Every filter of the registry runs against the real schema, and a list
// never scans the whole table: the tenant index leads.
func TestListScansBySpec_PlanUsesAnIndex(t *testing.T) {
	db := openScanDB(t)
	owner := testdb.OpenMigrator(t)
	tenants := seedScanTenants(t, db, 25)
	_, err := owner.ExecContext(context.Background(), `INSERT INTO scans (tenant_id, name, scan_type, scanner_name, schedule_type, status, tags, targets, total_runs, created_at, last_run_at, next_run_at)
		SELECT t, 'scan ' || g, 'single', 'nuclei', (ARRAY['daily','weekly','manual'])[1 + g % 3], (ARRAY['active','paused'])[1 + g % 2],
		       ARRAY['t' || (g % 10)], ARRAY['example.com'], g % 7, now() - (g || ' minutes')::interval, now() - (g || ' hours')::interval, now() + (g || ' hours')::interval
		FROM unnest($1::uuid[]) t, generate_series(1, 400) g`, pq.Array(idStrings(tenants)))
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := owner.ExecContext(context.Background(), `ANALYZE scans`); err != nil {
		t.Fatalf("analyze: %v", err)
	}
	tenant := tenants[0]
	actor, err := filterspec.UserActor(filterspec.UserActorInput{TenantID: tenant})
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"", "status=active", "scan_type=single", "schedule_type=daily", "origin=user", "origin=system", "tag=t1", "tag_not=t1",
		"q=scan+1", "name_contains=can+4", "name=scan+1*", "created_at_gte=-P1D", "last_run_at_lt=-PT2H", "next_run_at_gt=PT1H",
		"total_runs_gte=3", "total_runs=2", "sort=-total_runs", "sort=-last_run_at", "sort=created_at", "scanner_name=nuclei",
		"asset_group_id=" + shared.NewID().String(), "scan_workflow_id=" + wfOne, "created_by=" + shared.NewID().String(),
		"profile_id=" + shared.NewID().String(), "scan_zone_id=" + shared.NewID().String(), "sensor_preference=auto", "failed_runs_gte=1",
		"last_run_status=failed", "id=" + shared.NewID().String(),
	} {
		vals, err := url.ParseQuery(q)
		if err != nil {
			t.Fatal(err)
		}
		spec, err := filterspec.ParseValues(vals, scan.Fields, scanListOpts)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		w, err := filterspec.Compile(scan.WithListVisibility(spec, false), scan.ListFields, actor)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		var raw []byte
		if err := db.QueryRowContext(context.Background(), "EXPLAIN (FORMAT JSON) SELECT id FROM scans WHERE "+w.SQL+" ORDER BY "+w.OrderBy+" LIMIT 20", w.Args...).Scan(&raw); err != nil {
			t.Fatalf("%q: explain: %v\n%s", q, err, w.SQL)
		}
		if node := seqScanOnScans(t, raw); node != "" {
			t.Errorf("%q: the plan reads the whole scans table (%s)\n%s", q, node, w.SQL)
		}
	}
}

func idStrings(ids []shared.ID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.String()
	}
	return out
}

// seqScanOnScans returns a description of a sequential scan of the scans
// table in an EXPLAIN (FORMAT JSON) plan, or "".
func seqScanOnScans(t *testing.T, raw []byte) string {
	t.Helper()
	var plans []struct {
		Plan map[string]any `json:"Plan"`
	}
	if err := json.Unmarshal(raw, &plans); err != nil || len(plans) == 0 {
		t.Fatalf("explain output: %v %s", err, raw)
	}
	var walk func(n map[string]any) string
	walk = func(n map[string]any) string {
		if n["Node Type"] == "Seq Scan" && n["Relation Name"] == "scans" {
			return fmt.Sprint(n["Node Type"], " on ", n["Relation Name"])
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
