package routes

// Access-group asset assignment (/api/v1/groups/{g}/assets) over the real
// routes, services and a migrated database, across two tenants.
//
// asset_owners has no tenant_id, so a group's asset row is tied to a tenant
// only through its group. Assigning must only ever admit live assets of the
// group's own tenant, answer a foreign id exactly like an unknown one, never
// materialize the foreign asset into the members' data scope, and every read
// of the group's assets must stay inside the group's tenant even when a
// foreign row is already in the table. Research doc 15, L-01.

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
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	userdom "github.com/openctemio/openctem/api/pkg/domain/user"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

const agaVictimAsset = "aga-victim-asset.example.com"

type agaHarness struct {
	t   *testing.T
	db  *sql.DB
	srv *httptest.Server

	tenantA, tenantB     shared.ID
	adminA, memberA      shared.ID
	groupA               shared.ID
	assetA1, assetA2     shared.ID
	assetDeleted, assetB shared.ID
}

func (h *agaHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("seed %q: %v", q, err)
	}
}

func newAGAHarness(t *testing.T) *agaHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping access-group tenant DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	h := &agaHarness{t: t, db: sqldb}
	h.seed()

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	groupSvc := app.NewGroupService(postgres.NewGroupRepository(db), log,
		app.WithAccessControlRepository(postgres.NewAccessControlRepository(db)))

	router := infrahttp.NewChiRouter()
	auth := Middleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, middleware.UserIDKey, h.adminA.String())
			ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenantA.String())
			ctx = context.WithValue(ctx, middleware.IsAdminKey, true)
			if u, err := userdom.NewLocalUserWithID(h.adminA, h.adminA.String()+"@aga.test", "aga"); err == nil {
				ctx = context.WithValue(ctx, middleware.LocalUserKey, u)
			}
			ctx = context.WithValue(ctx, middleware.PermissionsKey, []string{
				permission.GroupsRead.String(), permission.GroupsWrite.String(),
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	registerGroupRoutes(router, handler.NewGroupHandler(groupSvc, validator.New(), log), auth, nil)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *agaHarness) seed() {
	h.tenantA, h.tenantB = shared.NewID(), shared.NewID()
	h.adminA, h.memberA = shared.NewID(), shared.NewID()
	h.groupA = shared.NewID()
	h.assetA1, h.assetA2, h.assetDeleted, h.assetB = shared.NewID(), shared.NewID(), shared.NewID(), shared.NewID()

	for _, tn := range []shared.ID{h.tenantA, h.tenantB} {
		h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, tn.String(), "aga-"+tn.String())
	}
	h.t.Cleanup(func() {
		ctx := context.Background()
		// asset_owners and user_accessible_assets cascade from assets and
		// groups, which cascade from tenants.
		for _, tn := range []shared.ID{h.tenantA, h.tenantB} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, tn.String())
		}
		for _, u := range []shared.ID{h.adminA, h.memberA} {
			_, _ = h.db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, u.String())
		}
	})
	for _, u := range []shared.ID{h.adminA, h.memberA} {
		h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'aga')`, u.String(), u.String()+"@aga.test")
	}
	for id, a := range map[shared.ID][2]string{
		h.assetA1:      {h.tenantA.String(), "aga-a1.example.com"},
		h.assetA2:      {h.tenantA.String(), "aga-a2.example.com"},
		h.assetDeleted: {h.tenantA.String(), "aga-deleted.example.com"},
		h.assetB:       {h.tenantB.String(), agaVictimAsset},
	} {
		h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, exposure, criticality) VALUES ($1, $2, $3, 'domain', 'public', 'high')`,
			id.String(), a[0], a[1])
	}
	h.exec(`UPDATE assets SET deleted_at = now() WHERE id = $1`, h.assetDeleted.String())
	h.exec(`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, 'aga-group', $3)`,
		h.groupA.String(), h.tenantA.String(), "aga-"+h.groupA.String())
	// The group member is an active member of tenant A: only an active
	// principal gets scope rows (member lifecycle, migration 001013).
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, h.memberA.String(), h.tenantA.String())
	h.exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, h.groupA.String(), h.memberA.String())
}

func (h *agaHarness) do(method, path string, body any) (int, string) {
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
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func (h *agaHarness) count(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(q, args...).Scan(&n); err != nil {
		h.t.Fatalf("count %q: %v", q, err)
	}
	return n
}

func (h *agaHarness) ownerRows(asset shared.ID) int {
	return h.count(`SELECT COUNT(*) FROM asset_owners WHERE group_id = $1 AND asset_id = $2`, h.groupA.String(), asset.String())
}

func (h *agaHarness) memberSees(asset shared.ID) bool {
	return h.count(`SELECT COUNT(*) FROM user_accessible_assets WHERE user_id = $1 AND asset_id = $2`,
		h.memberA.String(), asset.String()) > 0
}

func (h *agaHarness) leaked(body string) bool {
	return strings.Contains(body, agaVictimAsset) || strings.Contains(body, h.assetB.String())
}

// Tenant A's administrator assigns tenant B's asset id to a tenant A group.
func TestAccessGroup_AssignForeignTenantAsset_Refused(t *testing.T) {
	h := newAGAHarness(t)
	p := "/api/v1/groups/" + h.groupA.String() + "/assets"

	status, body := h.do(http.MethodPost, p, map[string]any{"asset_id": h.assetB.String(), "ownership_type": "secondary"})
	if status != http.StatusNotFound {
		t.Errorf("assigning a foreign-tenant asset = %d, want 404 (body %.200s)", status, body)
	}
	if h.leaked(body) {
		t.Errorf("assign response leaked tenant B data: %.300s", body)
	}
	// Same answer as an id that does not exist: no existence oracle (it was a
	// foreign-key 500 before).
	nStatus, nBody := h.do(http.MethodPost, p, map[string]any{"asset_id": shared.NewID().String(), "ownership_type": "secondary"})
	if nStatus != status || nBody != body {
		t.Errorf("foreign id answered %d %q, unknown id %d %q: must be identical", status, body, nStatus, nBody)
	}
	if h.ownerRows(h.assetB) != 0 {
		t.Error("a cross-tenant asset_owners row was written")
	}
	if h.memberSees(h.assetB) {
		t.Error("the group's member got tenant B's asset in their data scope")
	}

	// A soft-deleted asset of the own tenant is refused the same way.
	if status, _ := h.do(http.MethodPost, p, map[string]any{"asset_id": h.assetDeleted.String(), "ownership_type": "secondary"}); status != http.StatusNotFound {
		t.Errorf("assigning a deleted asset = %d, want 404", status)
	}

	// The own tenant's live asset works, and its member sees it.
	if status, body := h.do(http.MethodPost, p, map[string]any{"asset_id": h.assetA1.String(), "ownership_type": "secondary"}); status/100 != 2 {
		t.Fatalf("assigning an own-tenant asset = %d, want 2xx (body %.200s)", status, body)
	}
	if h.ownerRows(h.assetA1) != 1 || !h.memberSees(h.assetA1) {
		t.Error("own-tenant assign did not write the row or the member's access")
	}
}

func TestAccessGroup_BulkAssignForeignTenantAsset_Skipped(t *testing.T) {
	h := newAGAHarness(t)
	p := "/api/v1/groups/" + h.groupA.String() + "/assets/bulk"

	status, body := h.do(http.MethodPost, p, map[string]any{
		"asset_ids":      []string{h.assetA2.String(), h.assetB.String(), h.assetDeleted.String()},
		"ownership_type": "secondary",
	})
	if status != http.StatusOK {
		t.Fatalf("bulk assign = %d, want 200 (body %.200s)", status, body)
	}
	if h.leaked(body) {
		t.Errorf("bulk response leaked tenant B data: %.300s", body)
	}
	var res struct {
		SuccessCount int `json:"success_count"`
		FailedCount  int `json:"failed_count"`
	}
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	if res.SuccessCount != 1 || res.FailedCount != 2 {
		t.Errorf("bulk result = %+v, want 1 success and 2 failed", res)
	}
	if h.ownerRows(h.assetB) != 0 || h.ownerRows(h.assetDeleted) != 0 {
		t.Error("bulk assign wrote a cross-tenant or deleted asset row")
	}
	// The refresh runs for every requested id; it must not materialize the
	// foreign asset even though the group exists.
	if h.memberSees(h.assetB) {
		t.Error("bulk assign put tenant B's asset in the member's data scope")
	}
	if h.ownerRows(h.assetA2) != 1 || !h.memberSees(h.assetA2) {
		t.Error("own-tenant asset in the bulk was not assigned")
	}
}

// Any writer, not only the API, is refused a cross-tenant group row.
func TestAccessGroup_CrossTenantRow_RefusedByDatabase(t *testing.T) {
	h := newAGAHarness(t)
	_, err := h.db.Exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'secondary')`,
		h.assetB.String(), h.groupA.String())
	if err == nil {
		t.Fatal("a direct cross-tenant asset_owners insert succeeded, want the trigger to refuse it")
	}
	h.exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'secondary')`, h.assetA1.String(), h.groupA.String())
	if _, err := h.db.Exec(`UPDATE asset_owners SET asset_id = $1 WHERE group_id = $2`, h.assetB.String(), h.groupA.String()); err == nil {
		t.Error("moving a group row onto a foreign-tenant asset succeeded, want the trigger to refuse it")
	}
	// The full refresh never materializes a foreign asset either.
	if _, err := h.db.Exec(`SELECT refresh_access_for_asset_assign($1, $2, 'secondary')`, h.groupA.String(), h.assetB.String()); err != nil {
		t.Fatal(err)
	}
	if h.memberSees(h.assetB) {
		t.Error("refresh_access_for_asset_assign materialized a foreign-tenant asset")
	}
}

// A foreign row already in the table (written before the fix) is never shown.
func TestAccessGroup_ExistingCrossTenantRow_NotReadable(t *testing.T) {
	h := newAGAHarness(t)
	ctx := context.Background()
	// Bypassing the trigger needs a superuser (session_replication_role); the
	// app role cannot, by design (D-6).
	conn, err := testdb.OpenAdmin(t).Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Bypass the trigger to plant the row a pre-fix release could write.
	if _, err := conn.ExecContext(ctx, `SET session_replication_role = replica`); err != nil {
		t.Skipf("cannot bypass triggers (needs superuser): %v", err)
	}
	_, err = conn.ExecContext(ctx, `INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'secondary')`,
		h.assetB.String(), h.groupA.String())
	_, _ = conn.ExecContext(ctx, `RESET session_replication_role`)
	if err != nil {
		t.Fatal(err)
	}
	h.exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'secondary')`, h.assetA1.String(), h.groupA.String())

	status, body := h.do(http.MethodGet, "/api/v1/groups/"+h.groupA.String()+"/assets", nil)
	if status != http.StatusOK {
		t.Fatalf("GET group assets = %d (body %.200s)", status, body)
	}
	if h.leaked(body) {
		t.Errorf("group asset list leaked tenant B's asset: %.400s", body)
	}
	if !strings.Contains(body, h.assetA1.String()) {
		t.Errorf("group asset list misses the own-tenant asset: %.400s", body)
	}
	var page struct {
		Total int64 `json:"total_count"`
	}
	_ = json.Unmarshal([]byte(body), &page)
	if page.Total != 1 {
		t.Errorf("group asset total = %d, want 1 (foreign row counted)", page.Total)
	}

	status, body = h.do(http.MethodGet, "/api/v1/groups/", nil)
	if status != http.StatusOK {
		t.Fatalf("GET groups = %d (body %.200s)", status, body)
	}
	var groups struct {
		Groups []struct {
			ID         string `json:"id"`
			AssetCount int    `json:"asset_count"`
		} `json:"groups"`
	}
	_ = json.Unmarshal([]byte(body), &groups)
	for _, g := range groups.Groups {
		if g.ID == h.groupA.String() && g.AssetCount != 1 {
			t.Errorf("group asset_count = %d, want 1 (foreign row counted)", g.AssetCount)
		}
	}

	// A full refresh does not turn the planted row into access.
	if _, err := h.db.Exec(`SELECT refresh_access_for_member_add($1, $2)`, h.groupA.String(), h.memberA.String()); err != nil {
		t.Fatal(err)
	}
	if h.memberSees(h.assetB) {
		t.Error("refresh_access_for_member_add materialized the foreign row")
	}
}
