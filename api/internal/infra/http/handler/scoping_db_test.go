package handler

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/scoping"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func openScopingTestDB(t *testing.T) (*sql.DB, context.Context) {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed handler test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	ctx := context.Background()
	if err := raw.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return raw, ctx
}

func mustExec(ctx context.Context, t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	if _, err := db.ExecContext(ctx, q, args...); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func mustID(ctx context.Context, t *testing.T, db *sql.DB, q string, args ...any) string {
	t.Helper()
	var id string
	if err := db.QueryRowContext(ctx, q, args...).Scan(&id); err != nil {
		t.Fatalf("query %q: %v", q, err)
	}
	return id
}

func seedAssetRow(ctx context.Context, t *testing.T, db *sql.DB, tenantID, name, status string, crown bool) string {
	t.Helper()
	return mustID(ctx, t, db,
		`INSERT INTO assets (tenant_id, name, asset_type, status, is_crown_jewel)
		 VALUES ($1,$2,'host',$3,$4) RETURNING id`, tenantID, name, status, crown)
}

// TestScopingSummary_CountsSeededRows seeds every register the overview reads
// and checks each number, plus that another tenant's rows never leak in.
func TestScopingSummary_CountsSeededRows(t *testing.T) {
	db, ctx := openScopingTestDB(t)
	tenantID := seedHandlerTenant(ctx, t, db)
	otherTenant := seedHandlerTenant(ctx, t, db)

	userID := mustID(ctx, t, db, `INSERT INTO users (email) VALUES ($1) RETURNING id`, "scoping-"+shared.NewID().String()+"@example.test")
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id=$1`, userID) })
	mustExec(ctx, t, db, `INSERT INTO tenant_members (user_id, tenant_id) VALUES ($1,$2)`, userID, tenantID)
	groupID := mustID(ctx, t, db, `INSERT INTO groups (tenant_id, name, slug) VALUES ($1,'owners',$2) RETURNING id`, tenantID, "owners-"+tenantID)

	// Crown jewels: one owned by a user (a primary row matched from
	// owner_ref), one via a group RACI row, one unowned, one archived (not
	// counted).
	cjOwnerID := seedAssetRow(ctx, t, db, tenantID, "cj-owner-id", "active", true)
	mustExec(ctx, t, db, `INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1,$2,'primary','owner_ref')`, cjOwnerID, userID)
	cjGroup := seedAssetRow(ctx, t, db, tenantID, "cj-group", "active", true)
	mustExec(ctx, t, db, `INSERT INTO asset_owners (asset_id, group_id) VALUES ($1,$2)`, cjGroup, groupID)
	_ = seedAssetRow(ctx, t, db, tenantID, "cj-none", "stale", true)
	cjArchived := seedAssetRow(ctx, t, db, tenantID, "cj-archived", "archived", true)
	plain := seedAssetRow(ctx, t, db, tenantID, "plain", "active", false)
	// Other tenant: a crown jewel that must not be counted.
	foreignCJ := seedAssetRow(ctx, t, db, otherTenant, "foreign-cj", "active", true)

	// Business units: two, one asset mapped (plus an archived one, ignored).
	bu := mustID(ctx, t, db, `INSERT INTO business_units (id, tenant_id, name) VALUES (gen_random_uuid(),$1,'Retail') RETURNING id`, tenantID)
	mustExec(ctx, t, db, `INSERT INTO business_units (id, tenant_id, name) VALUES (gen_random_uuid(),$1,'Ops')`, tenantID)
	mustExec(ctx, t, db, `INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES (gen_random_uuid(),$1,$2,$3)`, tenantID, bu, plain)
	mustExec(ctx, t, db, `INSERT INTO business_unit_assets (id, tenant_id, business_unit_id, asset_id) VALUES (gen_random_uuid(),$1,$2,$3)`, tenantID, bu, cjArchived)

	// Business services: three, two linked to an asset.
	svcA := mustID(ctx, t, db, `INSERT INTO business_services (tenant_id, name) VALUES ($1,'Payments') RETURNING id`, tenantID)
	svcB := mustID(ctx, t, db, `INSERT INTO business_services (tenant_id, name) VALUES ($1,'Checkout') RETURNING id`, tenantID)
	mustExec(ctx, t, db, `INSERT INTO business_services (tenant_id, name) VALUES ($1,'Unlinked')`, tenantID)
	mustExec(ctx, t, db, `INSERT INTO business_service_assets (tenant_id, service_id, asset_id) VALUES ($1,$2,$3)`, tenantID, svcA, cjOwnerID)
	mustExec(ctx, t, db, `INSERT INTO business_service_assets (tenant_id, service_id, asset_id) VALUES ($1,$2,$3)`, tenantID, svcB, plain)

	// Boundary: 2 targets (one inactive still counts), 1 exclusion.
	mustExec(ctx, t, db, `INSERT INTO scope_targets (tenant_id, target_type, pattern) VALUES ($1,'domain','example.com')`, tenantID)
	mustExec(ctx, t, db, `INSERT INTO scope_targets (tenant_id, target_type, pattern, status) VALUES ($1,'domain','old.example.com','inactive')`, tenantID)
	mustExec(ctx, t, db, `INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason) VALUES ($1,'domain','hr.example.com','HR is out of scope')`, tenantID)

	// Attacker profiles: 2 for the tenant, 1 foreign.
	profA := mustID(ctx, t, db, `INSERT INTO attacker_profiles (tenant_id, name, profile_type, is_default) VALUES ($1,'Ext','external_unauth',true) RETURNING id`, tenantID)
	mustExec(ctx, t, db, `INSERT INTO attacker_profiles (tenant_id, name, profile_type) VALUES ($1,'Insider','malicious_insider')`, tenantID)
	foreignProf := mustID(ctx, t, db, `INSERT INTO attacker_profiles (tenant_id, name, profile_type) VALUES ($1,'Foreign','custom') RETURNING id`, otherTenant)

	// Threat models: one on a current crown jewel, one on the archived one,
	// one tenant-wide.
	mustExec(ctx, t, db, `INSERT INTO threat_models (tenant_id, scope_type, scope_ref_id, name) VALUES ($1,'crown_jewel',$2,'tm1')`, tenantID, cjGroup)
	mustExec(ctx, t, db, `INSERT INTO threat_models (tenant_id, scope_type, scope_ref_id, name) VALUES ($1,'crown_jewel',$2,'tm2')`, tenantID, cjArchived)
	mustExec(ctx, t, db, `INSERT INTO threat_models (tenant_id, scope_type, name) VALUES ($1,'tenant','tm3')`, tenantID)
	mustExec(ctx, t, db, `INSERT INTO threat_models (tenant_id, scope_type, scope_ref_id, name) VALUES ($1,'crown_jewel',$2,'foreign')`, otherTenant, foreignCJ)

	// Cycles: a closed one, a planning one, and the active one in focus.
	creator := shared.NewID().String()
	mustExec(ctx, t, db, `INSERT INTO ctem_cycles (tenant_id, name, status, created_by) VALUES ($1,'Q2','closed',$2)`, tenantID, creator)
	mustExec(ctx, t, db, `INSERT INTO ctem_cycles (tenant_id, name, status, created_by) VALUES ($1,'Q4 draft','planning',$2)`, tenantID, creator)
	active := mustID(ctx, t, db,
		`INSERT INTO ctem_cycles (tenant_id, name, status, created_by, start_date, end_date, charter)
		 VALUES ($1,'Q3 external','active',$2,'2026-10-01','2026-12-31',$3::jsonb) RETURNING id`,
		tenantID, creator, `{
			"objectives":["a","b","c"],
			"success_criteria":[{"name":"x","metric":"MTTR","target":"<= 7 days"},{"name":"y","metric":"KEV","target":"0"}],
			"in_scope_services":["`+svcA+`","`+svcB+`"],
			"exclusions":[{"item":"HR","reason":"out of scope"}],
			"threat_scenarios":"not an array"}`)
	mustExec(ctx, t, db, `INSERT INTO ctem_cycle_scope_snapshots (cycle_id, asset_id) VALUES ($1,$2),($1,$3)`, active, cjOwnerID, plain)
	mustExec(ctx, t, db, `INSERT INTO ctem_cycle_attacker_profiles (cycle_id, profile_id) VALUES ($1,$2)`, active, profA)
	// A foreign profile row slipped into the link table must not be counted.
	mustExec(ctx, t, db, `INSERT INTO ctem_cycle_attacker_profiles (cycle_id, profile_id) VALUES ($1,$2)`, active, foreignProf)

	h := NewScopingHandler(postgres.NewScopingSummaryRepository(&postgres.DB{DB: db}), logger.NewNop())
	get := func(tenant string) (scoping.Summary, string) {
		t.Helper()
		w := httptest.NewRecorder()
		h.GetSummary(w, cycleRequest(http.MethodGet, "/api/v1/scoping/summary", tenant, ""))
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
		}
		var s scoping.Summary
		if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return s, w.Body.String()
	}

	s, body := get(tenantID)
	t.Logf("summary: %s", body)

	if s.ActiveCycle == nil {
		t.Fatalf("active_cycle is null")
	}
	ac := *s.ActiveCycle
	if ac.ID != active || ac.Status != "active" || ac.Name != "Q3 external" {
		t.Errorf("active_cycle = %+v", ac)
	}
	if ac.StartDate == nil || ac.StartDate.Format("2006-01-02") != "2026-10-01" || ac.EndDate == nil {
		t.Errorf("dates = %v / %v", ac.StartDate, ac.EndDate)
	}
	checks := []struct {
		name      string
		got, want int
	}{
		{"objectives", ac.Objectives, 3},
		{"success_criteria", ac.SuccessCriteria, 2},
		{"in_scope_services", ac.InScopeServices, 2},
		{"exclusions", ac.Exclusions, 1},
		{"threat_scenarios (not an array)", ac.ThreatScenarios, 0},
		{"scope_assets", ac.ScopeAssets, 2},
		{"cycle attacker_profiles", ac.AttackerProfiles, 1},
		{"crown_jewels.total", s.CrownJewels.Total, 3},
		{"crown_jewels.with_owner", s.CrownJewels.WithOwner, 2},
		{"business_services.total", s.BusinessServices.Total, 3},
		{"business_services.with_assets", s.BusinessServices.WithAssets, 2},
		{"business_units.total", s.BusinessUnits.Total, 2},
		{"assets.total", s.Assets.Total, 4},
		{"assets.in_business_unit", s.Assets.InBusinessUnit, 1},
		{"boundary.targets", s.Boundary.Targets, 2},
		{"boundary.exclusions", s.Boundary.Exclusions, 1},
		{"attacker_profiles.total", s.AttackerProfiles.Total, 2},
		{"threat_models.total", s.ThreatModels.Total, 3},
		{"threat_models.crown_jewels_covered", s.ThreatModels.CrownJewelsCovered, 1},
		{"cycles.total", s.Cycles.Total, 3},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}

	// Once the active cycle moves to review it is still the focus; with only
	// the planning cycle left, planning is.
	mustExec(ctx, t, db, `UPDATE ctem_cycles SET status='review' WHERE id=$1`, active)
	if s, _ := get(tenantID); s.ActiveCycle == nil || s.ActiveCycle.Status != "review" {
		t.Errorf("after review: active_cycle = %+v", s.ActiveCycle)
	}
	mustExec(ctx, t, db, `UPDATE ctem_cycles SET status='closed' WHERE id=$1`, active)
	if s, _ := get(tenantID); s.ActiveCycle == nil || s.ActiveCycle.Status != "planning" || s.ActiveCycle.Name != "Q4 draft" {
		t.Errorf("after close: active_cycle = %+v", s.ActiveCycle)
	}

	// The other tenant sees only its own rows and no cycle.
	o, obody := get(otherTenant)
	if o.ActiveCycle != nil || o.CrownJewels.Total != 1 || o.AttackerProfiles.Total != 1 ||
		o.ThreatModels.CrownJewelsCovered != 1 || o.Cycles.Total != 0 || o.Assets.Total != 1 {
		t.Errorf("other tenant summary leaked or wrong: %s", obody)
	}
}

func profileRequest(method, tenantID, cycleID, profileID string) *http.Request {
	req := cycleRequest(method, "/api/v1/ctem-cycles/"+cycleID+"/profiles", tenantID, cycleID)
	if profileID != "" {
		chi.RouteContext(req.Context()).URLParams.Add("profileId", profileID)
	}
	return req
}

// TestCTEMCycleHandler_ListAndUnlinkProfiles covers the cycle profile list
// (same shape as GET /attacker-profiles/{id}), unlink, and the cross-tenant
// 404s.
func TestCTEMCycleHandler_ListAndUnlinkProfiles(t *testing.T) {
	db, ctx := openScopingTestDB(t)
	tenantID := seedHandlerTenant(ctx, t, db)
	otherTenant := seedHandlerTenant(ctx, t, db)
	creator := shared.NewID().String()

	cycle := mustID(ctx, t, db, `INSERT INTO ctem_cycles (tenant_id, name, created_by) VALUES ($1,'c',$2) RETURNING id`, tenantID, creator)
	builtIn := mustID(ctx, t, db,
		`INSERT INTO attacker_profiles (tenant_id, name, profile_type, description, capabilities, is_default)
		 VALUES ($1,'External Unauthenticated','external_unauth','no creds','{"network_access":"external"}',true) RETURNING id`, tenantID)
	custom := mustID(ctx, t, db, `INSERT INTO attacker_profiles (tenant_id, name, profile_type) VALUES ($1,'Insider','malicious_insider') RETURNING id`, tenantID)
	foreign := mustID(ctx, t, db, `INSERT INTO attacker_profiles (tenant_id, name, profile_type) VALUES ($1,'Foreign','custom') RETURNING id`, otherTenant)

	h := NewCTEMCycleHandler(db, nil, logger.NewNop())
	ap := NewAttackerProfileHandler(db, logger.NewNop())

	// Link through the existing endpoint: the foreign profile is ignored.
	{
		body := `{"profile_ids":["` + builtIn + `","` + custom + `","` + foreign + `"]}`
		req := cycleRequest(http.MethodPost, "/api/v1/ctem-cycles/"+cycle+"/profiles", tenantID, cycle)
		req.Body = io.NopCloser(strings.NewReader(body))
		w := httptest.NewRecorder()
		h.LinkProfile(w, req)
		if w.Code != http.StatusNoContent {
			t.Fatalf("link status = %d; body=%s", w.Code, w.Body.String())
		}
	}

	list := func(tenant, id string) (int, CTEMCycleProfilesResponse, string) {
		t.Helper()
		w := httptest.NewRecorder()
		h.ListProfiles(w, profileRequest(http.MethodGet, tenant, id, ""))
		var out CTEMCycleProfilesResponse
		if w.Code == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatalf("decode: %v", err)
			}
		}
		return w.Code, out, w.Body.String()
	}

	code, out, body := list(tenantID, cycle)
	t.Logf("profiles: %s", body)
	if code != http.StatusOK || len(out.Data) != 2 {
		t.Fatalf("list = %d %s, want 2 profiles", code, body)
	}
	if out.Data[0].ID != builtIn || !out.Data[0].IsDefault || out.Data[1].ID != custom {
		t.Errorf("order/content = %+v", out.Data)
	}

	// Same shape as GET /attacker-profiles/{id}.
	w := httptest.NewRecorder()
	ap.Get(w, cycleRequest(http.MethodGet, "/api/v1/attacker-profiles/"+builtIn, tenantID, builtIn))
	var single, fromList map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &single)
	var raw struct {
		Data []map[string]any `json:"data"`
	}
	_ = json.Unmarshal([]byte(body), &raw)
	fromList = raw.Data[0]
	for k := range single {
		if _, ok := fromList[k]; !ok {
			t.Errorf("list item lacks key %q present in GET /attacker-profiles/{id}", k)
		}
	}
	for k := range fromList {
		if _, ok := single[k]; !ok {
			t.Errorf("list item has extra key %q", k)
		}
	}

	// Cross-tenant: list and unlink are 404, and nothing is removed.
	if code, _, _ := list(otherTenant, cycle); code != http.StatusNotFound {
		t.Errorf("foreign list = %d, want 404", code)
	}
	w = httptest.NewRecorder()
	h.UnlinkProfile(w, profileRequest(http.MethodDelete, otherTenant, cycle, builtIn))
	if w.Code != http.StatusNotFound {
		t.Errorf("foreign unlink = %d, want 404", w.Code)
	}
	if code, _, _ := list(tenantID, "not-a-uuid"); code != http.StatusNotFound {
		t.Errorf("malformed id list = %d, want 404", code)
	}

	// Unlink, then unlink again (idempotent).
	for i := 0; i < 2; i++ {
		w = httptest.NewRecorder()
		h.UnlinkProfile(w, profileRequest(http.MethodDelete, tenantID, cycle, builtIn))
		if w.Code != http.StatusNoContent {
			t.Fatalf("unlink #%d = %d; body=%s", i+1, w.Code, w.Body.String())
		}
	}
	if _, out, body := list(tenantID, cycle); len(out.Data) != 1 || out.Data[0].ID != custom {
		t.Errorf("after unlink = %s", body)
	}
	// The profile itself is untouched.
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM attacker_profiles WHERE id=$1`, builtIn).Scan(&n); err != nil || n != 1 {
		t.Errorf("profile deleted by unlink: n=%d err=%v", n, err)
	}
}

// TestBusinessService_AssetCount: list and get carry asset_count, counted
// once per asset even when it is linked with two dependency types, and only
// for the tenant's own assets.
func TestBusinessService_AssetCount(t *testing.T) {
	db, ctx := openScopingTestDB(t)
	tenantID := seedHandlerTenant(ctx, t, db)

	a1 := seedAssetRow(ctx, t, db, tenantID, "a1", "active", false)
	a2 := seedAssetRow(ctx, t, db, tenantID, "a2", "active", false)
	linked := mustID(ctx, t, db, `INSERT INTO business_services (tenant_id, name) VALUES ($1,'Linked') RETURNING id`, tenantID)
	empty := mustID(ctx, t, db, `INSERT INTO business_services (tenant_id, name) VALUES ($1,'Empty') RETURNING id`, tenantID)
	mustExec(ctx, t, db, `INSERT INTO business_service_assets (tenant_id, service_id, asset_id, dependency_type) VALUES
		($1,$2,$3,'runs_on'),($1,$2,$3,'depends_on'),($1,$2,$4,'runs_on')`, tenantID, linked, a1, a2)

	h := NewBusinessServiceHandler(db, logger.NewNop())
	w := httptest.NewRecorder()
	h.List(w, cycleRequest(http.MethodGet, "/api/v1/business-services", tenantID, ""))
	if w.Code != http.StatusOK {
		t.Fatalf("list = %d %s", w.Code, w.Body.String())
	}
	var page struct {
		Data []BusinessServiceResponse `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := map[string]int{}
	for _, s := range page.Data {
		got[s.ID] = s.AssetCount
	}
	if got[linked] != 2 || got[empty] != 0 || len(got) != 2 {
		t.Errorf("asset_count = %v, want linked=2 empty=0", got)
	}

	w = httptest.NewRecorder()
	h.Get(w, cycleRequest(http.MethodGet, "/api/v1/business-services/"+linked, tenantID, linked))
	if !strings.Contains(w.Body.String(), `"asset_count":2`) {
		t.Errorf("get body = %s", w.Body.String())
	}
}

// TestCTEMCycleHandler_GetScopeCarriesAssetFields: each snapshot item names
// its asset, a row whose asset was deleted is kept with empty fields, another
// tenant gets 404, and malformed ids are 404 rather than 500.
func TestCTEMCycleHandler_GetScopeCarriesAssetFields(t *testing.T) {
	db, ctx := openScopingTestDB(t)
	tenantID := seedHandlerTenant(ctx, t, db)
	otherTenant := seedHandlerTenant(ctx, t, db)

	kept := mustID(ctx, t, db,
		`INSERT INTO assets (tenant_id, name, asset_type, criticality) VALUES ($1,'db-prod','host','critical') RETURNING id`, tenantID)
	gone := seedAssetRow(ctx, t, db, tenantID, "to-delete", "active", false)
	cycle := mustID(ctx, t, db, `INSERT INTO ctem_cycles (tenant_id, name, status, created_by) VALUES ($1,'c','active',$2) RETURNING id`,
		tenantID, shared.NewID().String())
	mustExec(ctx, t, db, `INSERT INTO ctem_cycle_scope_snapshots (cycle_id, asset_id, included_at) VALUES ($1,$2,NOW()-interval '1 minute'),($1,$3,NOW())`,
		cycle, kept, gone)
	mustExec(ctx, t, db, `DELETE FROM assets WHERE id=$1`, gone)

	h := NewCTEMCycleHandler(db, nil, logger.NewNop())
	get := func(tenant, id string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.GetScope(w, cycleRequest(http.MethodGet, "/api/v1/ctem-cycles/"+id+"/scope", tenant, id))
		return w
	}

	w := get(tenantID, cycle)
	t.Logf("scope: %s", w.Body.String())
	if w.Code != http.StatusOK {
		t.Fatalf("scope = %d %s", w.Code, w.Body.String())
	}
	var items []CTEMScopeSnapshotResponse
	if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
		t.Fatalf("decode (must stay a plain array): %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	if items[0].AssetID != kept || items[0].AssetName != "db-prod" || items[0].AssetType != "host" || items[0].AssetCriticality != "critical" {
		t.Errorf("kept item = %+v", items[0])
	}
	if items[1].AssetID != gone || items[1].AssetName != "" || items[1].AssetType != "" || items[1].AssetCriticality != "" {
		t.Errorf("deleted-asset item = %+v", items[1])
	}

	if w := get(otherTenant, cycle); w.Code != http.StatusNotFound {
		t.Errorf("foreign scope = %d, want 404", w.Code)
	}
	if w := get(tenantID, "not-a-uuid"); w.Code != http.StatusNotFound {
		t.Errorf("malformed scope = %d, want 404", w.Code)
	}
	w = httptest.NewRecorder()
	h.Get(w, cycleRequest(http.MethodGet, "/api/v1/ctem-cycles/x", tenantID, "x"))
	if w.Code != http.StatusNotFound {
		t.Errorf("malformed get = %d, want 404", w.Code)
	}
	w = httptest.NewRecorder()
	req := cycleRequest(http.MethodPost, "/api/v1/ctem-cycles/x/profiles", tenantID, "x")
	req.Body = io.NopCloser(strings.NewReader(`{"profile_ids":[]}`))
	h.LinkProfile(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("malformed link = %d, want 404", w.Code)
	}
	// A malformed profile id is skipped, not a 500.
	w = httptest.NewRecorder()
	req = cycleRequest(http.MethodPost, "/api/v1/ctem-cycles/"+cycle+"/profiles", tenantID, cycle)
	req.Body = io.NopCloser(strings.NewReader(`{"profile_ids":["nope"]}`))
	h.LinkProfile(w, req)
	if w.Code != http.StatusNoContent {
		t.Errorf("malformed profile id link = %d, want 204", w.Code)
	}
}
