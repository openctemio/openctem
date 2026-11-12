package handler

// GET /scans, POST /scans/search and GET /scan-runs on the list query
// contract, over a real database: the old param names keep answering with
// the same rows (and say they are deprecated), the document endpoint obeys
// the same rules, a tenant never sees another's rows, and an error never
// quotes what the caller sent.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/lib/pq"

	scansvc "github.com/openctemio/openctem/server/internal/app/scan"
	scanrunapp "github.com/openctemio/openctem/server/internal/app/scanrun"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
	"github.com/openctemio/openctem/server/pkg/validator"
)

type listFilterFixture struct {
	db               *sql.DB
	scans            *ScanHandler
	runs             *ScanWorkflowHandler
	tenantA, tenantB shared.ID
	scanA, scanB     map[string]string
	runA, runB       map[string]string
}

func newListFilterFixture(t *testing.T) *listFilterFixture {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		testdb.Skipf(t, "cannot reach test DB: %v", err)
	}
	rows, err := db.QueryContext(context.Background(), `INSERT INTO tenants (id, name, slug)
		SELECT u, 'list filter test', 'list-filter-' || u::text FROM (SELECT gen_random_uuid() AS u FROM generate_series(1, 2)) g
		RETURNING id::text`)
	if err != nil {
		t.Fatalf("seed tenants: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		ids = append(ids, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = ANY($1::uuid[])`, pq.Array(ids))
	})
	f := &listFilterFixture{db: db, tenantA: shared.MustIDFromString(ids[0]), tenantB: shared.MustIDFromString(ids[1])}
	f.scanA, f.runA = f.seed(t, f.tenantA)
	f.scanB, f.runB = f.seed(t, f.tenantB)
	pdb := &postgres.DB{DB: db}
	log := logger.NewNop()
	f.scans = NewScanHandler(scansvc.NewService(postgres.NewScanRepository(pdb), nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, log),
		nil, nil, validator.New(), log)
	f.runs = NewScanWorkflowHandler(scanrunapp.NewService(nil, nil, postgres.NewScanRunRepository(pdb), nil, nil, nil, nil, log), nil, log)
	return f
}

const secretProbe = "VALUE-ECHO-PROBE-7"

func (f *listFilterFixture) seed(t *testing.T, tenant shared.ID) (scans, runs map[string]string) {
	t.Helper()
	scans, runs = map[string]string{}, map[string]string{}
	add := func(key, name, desc, schedule, status string, tags []string, extra string) {
		var id string
		cols, vals := "", ""
		if extra != "" {
			kv := strings.SplitN(extra, "=", 2)
			cols, vals = ", "+kv[0], ", "+kv[1]
		}
		q := fmt.Sprintf(`INSERT INTO scans (tenant_id, name, description, scan_type, scanner_name, schedule_type, status, tags, targets %s)
			VALUES ($1, $2, $3, 'single', 'nuclei', $4, $5, $6, ARRAY['example.com'] %s) RETURNING id::text`, cols, vals)
		if err := f.db.QueryRowContext(context.Background(), q, tenant.String(), name, desc, schedule, status, pq.Array(tags)).Scan(&id); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
		scans[key] = id
	}
	add("nightly", "Nightly external", "perimeter", "daily", "active", []string{"prod", "edge"}, "")
	add("weekly", "Weekly internal", "the nightly sibling", "weekly", "paused", []string{"prod"}, "")
	add("quick", "Quick one-off", "", "manual", "active", nil, "ad_hoc=true")
	add("archived", "Old one-off", "", "manual", "active", nil, "archived_at=now()")
	var managed string
	if err := f.db.QueryRowContext(context.Background(), `INSERT INTO scans (tenant_id, name, scan_type, scanner_name, schedule_type, targets, ad_hoc, managed_by, managed_key)
		VALUES ($1, 'Coverage scan', 'single', 'nuclei', 'daily', ARRAY['example.com'], true, 'coverage', 'k') RETURNING id::text`,
		tenant.String()).Scan(&managed); err != nil {
		t.Fatal(err)
	}
	scans["managed"] = managed
	run := func(key, kind, status, scanID string) {
		var id string
		wf, sc := "NULL", "NULL"
		if kind == "scan" || kind == "quick" {
			wf = "'00000000-0000-0000-0000-000000000001'"
		}
		if scanID != "" {
			sc = "'" + scanID + "'"
		}
		q := fmt.Sprintf(`INSERT INTO scan_runs (tenant_id, scan_workflow_id, scan_id, kind, status, trigger_type)
			VALUES ($1, %s, %s, $2, $3, 'manual') RETURNING id::text`, wf, sc)
		if err := f.db.QueryRowContext(context.Background(), q, tenant.String(), kind, status).Scan(&id); err != nil {
			t.Fatalf("seed run %s: %v", key, err)
		}
		runs[key] = id
	}
	run("done", "scan", "completed", scans["nightly"])
	run("failed", "scan", "failed", scans["nightly"])
	run("retest", "retest", "completed", "")
	run("system", "system", "completed", "")
	return scans, runs
}

type listCaller struct {
	admin bool
	perms []string
}

var (
	listAdmin  = listCaller{admin: true}
	listReader = listCaller{perms: []string{permission.ScansRead.String(), permission.FindingsRead.String()}}
	// reads scans but not findings: finding runs are hidden from the run list
	listNoFindings = listCaller{perms: []string{permission.ScansRead.String()}}
)

func (f *listFilterFixture) do(h http.HandlerFunc, tenant shared.ID, c listCaller, method, target, body string) *httptest.ResponseRecorder {
	var r *http.Request
	if body == "" {
		r = httptest.NewRequestWithContext(context.Background(), method, target, nil)
	} else {
		r = httptest.NewRequestWithContext(context.Background(), method, target, strings.NewReader(body))
	}
	ctx := context.WithValue(r.Context(), middleware.TenantIDKey, tenant.String())
	ctx = context.WithValue(ctx, middleware.IsAdminKey, c.admin)
	if c.perms != nil {
		ctx = context.WithValue(ctx, middleware.FetchedPermissionsKey, c.perms)
	}
	rec := httptest.NewRecorder()
	h(rec, r.WithContext(ctx))
	return rec
}

func idsOf(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(out.Data))
	for i, d := range out.Data {
		ids[i] = d.ID
	}
	return ids
}

func (f *listFilterFixture) nameOf(id string) string {
	for _, m := range []map[string]string{f.scanA, f.runA} {
		for k, v := range m {
			if v == id {
				return k
			}
		}
	}
	return "?" + id
}

func (f *listFilterFixture) names(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	ids := idsOf(t, rec)
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = f.nameOf(id)
	}
	sort.Strings(out)
	return out
}

func TestScansList_OldParamsAnswerAndAnnounce(t *testing.T) {
	f := newListFilterFixture(t)
	old := f.do(f.scans.ListScans, f.tenantA, listReader, http.MethodGet, "/api/v1/scans?search=nightly&tags=prod", "")
	canon := f.do(f.scans.ListScans, f.tenantA, listReader, http.MethodGet, "/api/v1/scans?q=nightly&tag=prod", "")
	if !reflect.DeepEqual(f.names(t, old), f.names(t, canon)) || !reflect.DeepEqual(f.names(t, old), []string{"nightly", "weekly"}) {
		t.Errorf("old = %v, canonical = %v", f.names(t, old), f.names(t, canon))
	}
	h := old.Header()
	if h.Get("Deprecation") == "" || h.Get("Sunset") == "" {
		t.Errorf("an alias is not announced: %v", h)
	}
	warn := strings.Join(h.Values("Warning"), " | ")
	if !strings.Contains(warn, "search is deprecated; use q") || !strings.Contains(warn, "tags is deprecated; use tag") {
		t.Errorf("warnings = %q", warn)
	}
	if canon.Header().Get("Deprecation") != "" || canon.Header().Get("Sunset") != "" || len(canon.Header().Values("Warning")) != 0 {
		t.Errorf("canonical request carries deprecation headers: %v", canon.Header())
	}
	// the other old names are canonical names and need no alias
	rec := f.do(f.scans.ListScans, f.tenantA, listReader, http.MethodGet, "/api/v1/scans?status=paused&scan_type=single&schedule_type=weekly", "")
	if got := f.names(t, rec); !reflect.DeepEqual(got, []string{"weekly"}) || rec.Header().Get("Deprecation") != "" {
		t.Errorf("status filter = %v %v", got, rec.Header())
	}
}

func TestScansList_VisibilityThroughBothEndpoints(t *testing.T) {
	f := newListFilterFixture(t)
	get := func(q string) []string {
		return f.names(t, f.do(f.scans.ListScans, f.tenantA, listReader, http.MethodGet, "/api/v1/scans?"+q, ""))
	}
	post := func(q, doc string) []string {
		return f.names(t, f.do(f.scans.SearchScans, f.tenantA, listReader, http.MethodPost, "/api/v1/scans/search?"+q, doc))
	}
	if got := get(""); !reflect.DeepEqual(got, []string{"nightly", "weekly"}) {
		t.Errorf("default list = %v", got)
	}
	if got := post("", `{}`); !reflect.DeepEqual(got, []string{"nightly", "weekly"}) {
		t.Errorf("default document list = %v", got)
	}
	if got := get("include_ad_hoc=true"); !reflect.DeepEqual(got, []string{"managed", "nightly", "quick", "weekly"}) {
		t.Errorf("include_ad_hoc list = %v", got)
	}
	if got := post("include_ad_hoc=true", `{}`); len(got) != 4 {
		t.Errorf("include_ad_hoc document list = %v", got)
	}
	// an OR that names origin=system does not lift the rule, nor does an id filter reach the archived scan
	or := `{"filter":{"any":[{"field":"origin","op":"eq","value":"system"},{"field":"status","op":"in","value":["active"]}]}}`
	for _, n := range post("", or) {
		if n == "quick" || n == "archived" {
			t.Errorf("document OR listed %s", n)
		}
	}
	if got := post("", `{"filter":{"field":"id","op":"in","value":["`+f.scanA["archived"]+`"]}}`); len(got) != 0 {
		t.Errorf("archived scan listed by id: %v", got)
	}
}

func TestScansList_StrictParamsAndNoValueEcho(t *testing.T) {
	f := newListFilterFixture(t)
	for _, c := range []struct{ name, method, target, body string }{
		{"unknown param", http.MethodGet, "/api/v1/scans?nothing=" + secretProbe, ""},
		{"server-only field", http.MethodGet, "/api/v1/scans?archived=" + secretProbe, ""},
		{"bad enum", http.MethodGet, "/api/v1/scans?status=" + secretProbe, ""},
		{"bad id", http.MethodGet, "/api/v1/scans?id=" + secretProbe, ""},
		{"bad sort", http.MethodGet, "/api/v1/scans?sort=" + secretProbe, ""},
		{"bad int", http.MethodGet, "/api/v1/scans?total_runs_gte=" + secretProbe, ""},
		{"document unknown field", http.MethodPost, "/api/v1/scans/search", `{"filter":{"field":"nothing","op":"eq","value":"` + secretProbe + `"}}`},
		{"document server-only field", http.MethodPost, "/api/v1/scans/search", `{"filter":{"field":"ad_hoc","op":"eq","value":true},"q":"` + secretProbe + `","x":"` + secretProbe + `"}`},
		{"document bad value", http.MethodPost, "/api/v1/scans/search", `{"filter":{"field":"status","op":"in","value":["` + secretProbe + `"]}}`},
	} {
		h := f.scans.ListScans
		if c.method == http.MethodPost {
			h = f.scans.SearchScans
		}
		rec := f.do(h, f.tenantA, listReader, c.method, c.target, c.body)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "INVALID_FILTER") {
			t.Errorf("%s: %d %s, want 400 INVALID_FILTER", c.name, rec.Code, rec.Body)
		}
		if strings.Contains(rec.Body.String(), secretProbe) {
			t.Errorf("%s: the error quotes the input: %s", c.name, rec.Body)
		}
	}
	// a server-only field and a missing one are the same error
	a := f.do(f.scans.ListScans, f.tenantA, listReader, http.MethodGet, "/api/v1/scans?archived=true", "")
	b := f.do(f.scans.ListScans, f.tenantA, listReader, http.MethodGet, "/api/v1/scans?nothing=true", "")
	if strings.ReplaceAll(a.Body.String(), "archived", "X") != strings.ReplaceAll(b.Body.String(), "nothing", "X") {
		t.Errorf("field discovery:\n%s\n%s", a.Body, b.Body)
	}
}

func TestScansList_InjectionSeedsAreBound(t *testing.T) {
	f := newListFilterFixture(t)
	for _, s := range []string{`'; DROP TABLE scans; --`, `" OR 1=1 --`, `x') OR ('1'='1`, "a\x00b"} {
		q := url.Values{"q": {s}, "tag": {s}, "name_contains": {s}}.Encode()
		rec := f.do(f.scans.ListScans, f.tenantA, listReader, http.MethodGet, "/api/v1/scans?"+q, "")
		if rec.Code == http.StatusOK && len(idsOf(t, rec)) != 0 {
			t.Errorf("%q matched scans", s)
		}
		if rec.Code >= 500 {
			t.Errorf("%q: %d %s", s, rec.Code, rec.Body)
		}
	}
	var n int
	if err := f.db.QueryRowContext(context.Background(), `SELECT count(*) FROM scans WHERE tenant_id = $1`, f.tenantA.String()).Scan(&n); err != nil || n != 5 {
		t.Errorf("scans table changed: %d %v", n, err)
	}
}

func TestScansList_TenantIsolation(t *testing.T) {
	f := newListFilterFixture(t)
	b := map[string]bool{}
	var bIDs []string
	for _, id := range f.scanB {
		b[id] = true
		bIDs = append(bIDs, id)
	}
	reqs := []struct{ method, target, body string }{
		{http.MethodGet, "/api/v1/scans?include_ad_hoc=true", ""},
		{http.MethodGet, "/api/v1/scans?include_ad_hoc=true&id=" + strings.Join(bIDs, ","), ""},
		{http.MethodGet, "/api/v1/scans?q=nightly&tag=prod", ""},
		{http.MethodPost, "/api/v1/scans/search?include_ad_hoc=true", `{"filter":{"field":"id","op":"in","value":["` + strings.Join(bIDs, `","`) + `"]}}`},
		{http.MethodPost, "/api/v1/scans/search?include_ad_hoc=true", `{"filter":{"not":{"field":"id","op":"in","value":["` + f.scanA["nightly"] + `"]}}}`},
	}
	for _, r := range reqs {
		h := f.scans.ListScans
		if r.method == http.MethodPost {
			h = f.scans.SearchScans
		}
		for _, id := range idsOf(t, f.do(h, f.tenantA, listAdmin, r.method, r.target, r.body)) {
			if b[id] {
				t.Errorf("%s %s listed tenant B's scan", r.method, r.target)
			}
		}
	}
}

func TestScanRunsList_ParamsRulesAndIsolation(t *testing.T) {
	f := newListFilterFixture(t)
	get := func(c listCaller, q string) *httptest.ResponseRecorder {
		return f.do(f.runs.ListRuns, f.tenantA, c, http.MethodGet, "/api/v1/scan-runs?"+q, "")
	}
	if got := f.names(t, get(listAdmin, "")); !reflect.DeepEqual(got, []string{"done", "failed", "retest"}) {
		t.Errorf("default = %v (system runs are hidden)", got)
	}
	if got := f.names(t, get(listAdmin, "include_system=true")); len(got) != 4 {
		t.Errorf("include_system = %v", got)
	}
	if got := f.names(t, get(listAdmin, "kind=system")); !reflect.DeepEqual(got, []string{"system"}) {
		t.Errorf("kind=system = %v", got)
	}
	if got := f.names(t, get(listNoFindings, "include_system=true")); !reflect.DeepEqual(got, []string{"done", "failed", "system"}) {
		t.Errorf("a caller without findings:read sees %v", got)
	}
	if got := f.names(t, get(listAdmin, "status=failed&scan_id="+f.scanA["nightly"])); !reflect.DeepEqual(got, []string{"failed"}) {
		t.Errorf("status+scan_id = %v", got)
	}
	// the other tenant's rows never appear
	var bIDs []string
	for _, id := range f.runB {
		bIDs = append(bIDs, id)
	}
	if ids := idsOf(t, get(listAdmin, "include_system=true&id="+strings.Join(bIDs, ","))); len(ids) != 0 {
		t.Errorf("tenant A reads tenant B's runs: %v", ids)
	}
	if ids := idsOf(t, get(listAdmin, "include_system=true&scan_id="+f.scanB["nightly"])); len(ids) != 0 {
		t.Errorf("tenant A reads runs of tenant B's scan: %v", ids)
	}
	// strict params, no echo, the same error for a missing and a server-side field
	for _, q := range []string{"nothing=" + secretProbe, "status=" + secretProbe, "origin=" + secretProbe, "sort=" + secretProbe, "scan_id=" + secretProbe} {
		rec := get(listAdmin, q)
		if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), secretProbe) {
			t.Errorf("%s: %d %s", q, rec.Code, rec.Body)
		}
	}
}
