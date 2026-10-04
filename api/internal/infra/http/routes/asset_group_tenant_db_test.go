package routes

// Asset-group membership over the real routes, services and a migrated
// database, across two tenants and a data-scoped member.
//
// An asset group's members live in asset_group_members, which has no
// tenant_id. Adding members must only ever admit assets of the group's own
// tenant (and of the caller's data scope), and every read of members, their
// findings and the counters derived from them must stay inside the group's
// tenant, even if a foreign row is already in the table.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

const (
	agtVictimAsset   = "agt-victim-asset.example.com"
	agtVictimFinding = "agt-VICTIM-SECRET finding message"
)

type agtHarness struct {
	t   *testing.T
	db  *sql.DB
	srv *httptest.Server

	tenantA, tenantB         shared.ID
	adminB, scopedB          shared.ID
	assetA, assetB1, assetB2 shared.ID
	findingA, groupB         shared.ID
}

func (h *agtHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func newAGTHarness(t *testing.T) *agtHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping asset-group tenant DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	h := &agtHarness{t: t, db: sqldb}
	h.seed()

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	enforcer := datascope.New(postgres.NewDataScopeRepository(db), nil,
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, log)
	groupSvc := app.NewAssetGroupService(postgres.NewAssetGroupRepository(db), log)
	groupSvc.SetDataScope(enforcer)

	router := infrahttp.NewChiRouter()
	auth := Middleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, middleware.UserIDKey, r.Header.Get("X-Test-User"))
			ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenantB.String())
			ctx = context.WithValue(ctx, middleware.IsAdminKey, r.Header.Get("X-Test-Admin") == "1")
			ctx = context.WithValue(ctx, middleware.PermissionsKey, []string{
				permission.AssetGroupsRead.String(), permission.AssetGroupsWrite.String(),
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	registerAssetGroupRoutes(router, handler.NewAssetGroupHandler(groupSvc, validator.New(), log), auth, nil)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *agtHarness) seed() {
	h.tenantA, h.tenantB = shared.NewID(), shared.NewID()
	h.adminB, h.scopedB = shared.NewID(), shared.NewID()
	h.assetA, h.assetB1, h.assetB2 = shared.NewID(), shared.NewID(), shared.NewID()
	h.findingA, h.groupB = shared.NewID(), shared.NewID()

	for _, tn := range []shared.ID{h.tenantA, h.tenantB} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tn.String(), "agt-"+tn.String())
	}
	h.t.Cleanup(func() {
		ctx := context.Background()
		for _, tn := range []shared.ID{h.tenantA, h.tenantB} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tn.String())
		}
		for _, u := range []shared.ID{h.adminB, h.scopedB} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u.String())
		}
	})
	for _, u := range []shared.ID{h.adminB, h.scopedB} {
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'agt')`, u.String(), u.String()+"@agt.test")
	}
	for id, a := range map[shared.ID][2]string{
		h.assetA:  {h.tenantA.String(), agtVictimAsset},
		h.assetB1: {h.tenantB.String(), "agt-b1.example.com"},
		h.assetB2: {h.tenantB.String(), "agt-b2-out-of-scope.example.com"},
	} {
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
			id.String(), a[0], a[1])
	}
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'sast', 'agt-tool', $4, 'critical', $1::text, 'confirmed')`,
		h.findingA.String(), h.tenantA.String(), h.assetA.String(), agtVictimFinding)
	h.exec(`INSERT INTO asset_groups (id, tenant_id, name) VALUES ($1, $2, 'agt-group')`, h.groupB.String(), h.tenantB.String())
	// scopedB may see B1 only.
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.scopedB.String(), h.tenantB.String(), h.assetB1.String())
}

func (h *agtHarness) do(user shared.ID, isAdmin bool, method, path string, body any) (int, string) {
	h.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, rdr)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-User", user.String())
	if isAdmin {
		req.Header.Set("X-Test-Admin", "1")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func (h *agtHarness) members() map[string]bool {
	h.t.Helper()
	rows, err := h.db.Query(`SELECT asset_id::text FROM asset_group_members WHERE asset_group_id = $1`, h.groupB.String())
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		out[id] = true
	}
	if err := rows.Err(); err != nil {
		h.t.Fatal(err)
	}
	return out
}

func (h *agtHarness) leaked(body string) bool {
	return strings.Contains(body, agtVictimAsset) || strings.Contains(body, agtVictimFinding) ||
		strings.Contains(body, h.assetA.String()) || strings.Contains(body, h.findingA.String())
}

func (h *agtHarness) readBack(who shared.ID, admin bool) {
	h.t.Helper()
	g := "/api/v1/asset-groups/" + h.groupB.String()
	for _, p := range []string{g, g + "/assets", g + "/findings", "/api/v1/asset-groups/", "/api/v1/asset-groups/stats"} {
		status, body := h.do(who, admin, http.MethodGet, p, nil)
		if status != http.StatusOK {
			h.t.Errorf("GET %s = %d (body %.200s)", p, status, body)
		}
		if h.leaked(body) {
			h.t.Errorf("GET %s leaked tenant A data: %.300s", p, body)
		}
	}
	var assetCount, ownMembers int
	if err := h.db.QueryRow(`SELECT asset_count FROM asset_groups WHERE id = $1`, h.groupB.String()).Scan(&assetCount); err != nil {
		h.t.Fatal(err)
	}
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM asset_group_members agm JOIN assets a ON a.id = agm.asset_id
		WHERE agm.asset_group_id = $1 AND a.tenant_id = $2`, h.groupB.String(), h.tenantB.String()).Scan(&ownMembers)
	if assetCount > ownMembers {
		h.t.Errorf("group asset_count = %d, but only %d members are tenant B assets", assetCount, ownMembers)
	}
	_, body := h.do(who, admin, http.MethodGet, g, nil)
	var got struct {
		FindingCount int `json:"finding_count"`
	}
	_ = json.Unmarshal([]byte(body), &got)
	if got.FindingCount != 0 {
		h.t.Errorf("group finding_count = %d, want 0 (tenant A finding counted)", got.FindingCount)
	}
}

// Tenant B's administrator adds tenant A's asset id to a tenant B group.
func TestAssetGroup_AddForeignTenantAsset_RejectedAndNotReadable(t *testing.T) {
	h := newAGTHarness(t)
	g := "/api/v1/asset-groups/" + h.groupB.String() + "/assets"

	status, body := h.do(h.adminB, true, http.MethodPost, g, map[string]any{"asset_ids": []string{h.assetA.String()}})
	if status == http.StatusOK {
		t.Errorf("adding a foreign-tenant asset = 200, want a rejection (body %.200s)", body)
	}
	if h.leaked(body) {
		t.Errorf("add response leaked tenant A data: %.300s", body)
	}
	// The response must be the one a non-existent id gets: no tenant oracle.
	nStatus, nBody := h.do(h.adminB, true, http.MethodPost, g, map[string]any{"asset_ids": []string{shared.NewID().String()}})
	if nStatus != status || nBody != body {
		t.Errorf("foreign id answered %d %q, unknown id %d %q: must be identical", status, body, nStatus, nBody)
	}
	// Mixed with a valid id: nothing is added (all or nothing).
	status, _ = h.do(h.adminB, true, http.MethodPost, g, map[string]any{"asset_ids": []string{h.assetB1.String(), h.assetA.String()}})
	if status == http.StatusOK {
		t.Errorf("mixed add with a foreign id = 200, want a rejection")
	}
	if m := h.members(); m[h.assetA.String()] || m[h.assetB1.String()] {
		t.Errorf("rejected add still wrote members: %v", m)
	}
	// A group created with the foreign id is refused too.
	status, body = h.do(h.adminB, true, http.MethodPost, "/api/v1/asset-groups/", map[string]any{
		"name": "agt-created", "environment": "production", "criticality": "high",
		"existing_asset_ids": []string{h.assetA.String()},
	})
	if status == http.StatusCreated || h.leaked(body) {
		t.Errorf("create with a foreign asset id = %d (body %.300s), want a rejection", status, body)
	}
	var n int
	_ = h.db.QueryRow(`SELECT COUNT(*) FROM asset_group_members WHERE asset_id = $1`, h.assetA.String()).Scan(&n)
	if n != 0 {
		t.Errorf("tenant A's asset is a member of %d tenant B group(s)", n)
	}
	h.readBack(h.adminB, true)

	// An own-tenant asset is still added.
	if status, body := h.do(h.adminB, true, http.MethodPost, g, map[string]any{"asset_ids": []string{h.assetB1.String()}}); status != http.StatusOK {
		t.Errorf("adding an own-tenant asset = %d, want 200 (body %.200s)", status, body)
	}
	if !h.members()[h.assetB1.String()] {
		t.Error("own-tenant asset was not added")
	}
}

// A cross-tenant member row that already exists (written before the fix)
// must not be readable through any group read.
func TestAssetGroup_ExistingForeignMemberRow_NotReadable(t *testing.T) {
	h := newAGTHarness(t)
	h.exec(`INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2)`, h.groupB.String(), h.assetA.String())
	// Recount through a legitimate membership change.
	if status, body := h.do(h.adminB, true, http.MethodPost, "/api/v1/asset-groups/"+h.groupB.String()+"/assets",
		map[string]any{"asset_ids": []string{h.assetB1.String()}}); status != http.StatusOK {
		t.Fatalf("add own asset = %d (body %.200s)", status, body)
	}
	var assetCount int
	_ = h.db.QueryRow(`SELECT asset_count FROM asset_groups WHERE id = $1`, h.groupB.String()).Scan(&assetCount)
	if assetCount != 1 {
		t.Errorf("asset_count = %d, want 1 (the foreign row must not count)", assetCount)
	}
	h.readBack(h.adminB, true)

	// Repository reads used by scan targeting stay in the group's tenant.
	repo := postgres.NewAssetGroupRepository(&postgres.DB{DB: h.db})
	ctx := context.Background()
	counts, err := repo.CountAssetsByType(ctx, h.groupB)
	if err != nil || counts[assetdom.TypeRef{Type: assetdom.AssetTypeDomain}] != 1 {
		t.Errorf("CountAssetsByType = %v (err %v), want domain:1", counts, err)
	}
	ids, err := repo.GetGroupIDsByAssetID(ctx, h.assetA)
	if err != nil || len(ids) != 0 {
		t.Errorf("GetGroupIDsByAssetID(tenant A asset) = %v (err %v), want none of tenant B's groups", ids, err)
	}
}

// A data-scoped member may only add assets inside their scope.
func TestAssetGroup_AddOutOfScopeAsset_Rejected(t *testing.T) {
	h := newAGTHarness(t)
	g := "/api/v1/asset-groups/" + h.groupB.String() + "/assets"

	status, body := h.do(h.scopedB, false, http.MethodPost, g, map[string]any{"asset_ids": []string{h.assetB2.String()}})
	if status == http.StatusOK {
		t.Errorf("scoped member adding an out-of-scope asset = 200, want a rejection (body %.200s)", body)
	}
	nStatus, nBody := h.do(h.scopedB, false, http.MethodPost, g, map[string]any{"asset_ids": []string{shared.NewID().String()}})
	if nStatus != status || nBody != body {
		t.Errorf("out-of-scope id answered %d %q, unknown id %d %q: must be identical", status, body, nStatus, nBody)
	}
	if h.members()[h.assetB2.String()] {
		t.Error("out-of-scope asset was added")
	}
	if status, body := h.do(h.scopedB, false, http.MethodPost, g, map[string]any{"asset_ids": []string{h.assetB1.String()}}); status != http.StatusOK {
		t.Errorf("scoped member adding an in-scope asset = %d, want 200 (body %.200s)", status, body)
	}
	// Removing an out-of-scope member is a no-op for the scoped member.
	h.exec(`INSERT INTO asset_group_members (asset_group_id, asset_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`, h.groupB.String(), h.assetB2.String())
	if status, body := h.do(h.scopedB, false, http.MethodDelete, g, map[string]any{"asset_ids": []string{h.assetB2.String()}}); status != http.StatusOK {
		t.Errorf("remove = %d (body %.200s)", status, body)
	}
	if !h.members()[h.assetB2.String()] {
		t.Error("scoped member removed an out-of-scope asset from the group")
	}
	// Too many ids in one request are refused before any database work.
	many := make([]string, 1001)
	for i := range many {
		many[i] = shared.NewID().String()
	}
	if status, _ := h.do(h.adminB, true, http.MethodPost, g, map[string]any{"asset_ids": many}); status != http.StatusBadRequest && status != http.StatusUnprocessableEntity {
		t.Errorf("1001 ids = %d, want 400/422", status)
	}
}
