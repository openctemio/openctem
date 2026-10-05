package routes

// The asset Owners routes over the real handler, repositories and a migrated
// database. asset_owners is the only owner store (one owner model).

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	_ "github.com/lib/pq"

	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type aoHarness struct {
	t      *testing.T
	db     *sql.DB
	srv    *httptest.Server
	tenant shared.ID
	actor  shared.ID // a member with assets:read/write/delete
	mu     sync.Mutex
	perms  []string // the actor's permissions (assets:* by default); setPerms
}

// setPerms replaces the actor's permissions for the next requests.
func (h *aoHarness) setPerms(perms ...permission.Permission) {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, p.String())
	}
	h.mu.Lock()
	h.perms = out
	h.mu.Unlock()
}

func (h *aoHarness) currentPerms() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.perms
}

func newAOHarness(t *testing.T) *aoHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set to a test database; skipping asset owner routes DB test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	h := &aoHarness{t: t, db: sqldb, tenant: shared.NewID(), actor: shared.NewID()}
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, h.tenant.String(), "ao-"+h.tenant.String())
	t.Cleanup(func() {
		_, _ = sqldb.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, h.tenant.String())
	})
	h.actor = h.member("actor")

	db := &postgres.DB{DB: sqldb}
	ownerHandler := handler.NewAssetOwnerHandler(postgres.NewAccessControlRepository(db), postgres.NewAssetRepository(db), logger.NewNop())
	h.setPerms(permission.AssetsRead, permission.AssetsWrite, permission.AssetsDelete)
	auth := Middleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, middleware.UserIDKey, h.actor.String())
			ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenant.String())
			ctx = context.WithValue(ctx, middleware.IsAdminKey, false)
			ctx = context.WithValue(ctx, middleware.PermissionsKey, h.currentPerms())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})
	router := infrahttp.NewChiRouter()
	registerAssetOwnerRoutes(router, ownerHandler, auth, nil)
	h.srv = httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *aoHarness) exec(q string, args ...any) {
	h.t.Helper()
	if _, err := h.db.ExecContext(context.Background(), q, args...); err != nil {
		h.t.Fatalf("%q: %v", q, err)
	}
}

// member creates a user who is a member of the harness tenant.
func (h *aoHarness) member(name string) shared.ID {
	h.t.Helper()
	id := shared.NewID()
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`, id.String(), id.String()+"@ao.test", name)
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id.String())
	})
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, id.String(), h.tenant.String())
	return id
}

func (h *aoHarness) asset(ownerRef string) shared.ID {
	h.t.Helper()
	id := shared.NewID()
	var ref any
	if ownerRef != "" {
		ref = ownerRef
	}
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, owner_ref) VALUES ($1, $2, $3, 'host', $4)`,
		id.String(), h.tenant.String(), "ao-"+id.String(), ref)
	return id
}

func (h *aoHarness) do(method, path string, body any) (int, string) {
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

type aoListed struct {
	Data []struct {
		ID               string  `json:"id"`
		UserID           *string `json:"user_id"`
		OwnershipType    string  `json:"ownership_type"`
		AssignmentSource string  `json:"assignment_source"`
	} `json:"data"`
}

func (h *aoHarness) list(assetID shared.ID) aoListed {
	h.t.Helper()
	status, body := h.do(http.MethodGet, "/api/v1/assets/"+assetID.String()+"/owners", nil)
	if status != http.StatusOK {
		h.t.Fatalf("list owners = %d %s", status, body)
	}
	var out aoListed
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		h.t.Fatalf("decode %s: %v", body, err)
	}
	return out
}

// An owner matched from owner_ref is listed with its source, and removing it
// clears the asset's owner_ref (so the owner-resolution controller does not
// add it back). Removing a manual owner leaves owner_ref alone.
func TestAssetOwners_OwnerRefOwnerRemovalClearsOwnerRef(t *testing.T) {
	h := newAOHarness(t)
	alice := h.member("alice")
	bob := h.member("bob")
	asset := h.asset(alice.String() + "@ao.test")
	h.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'primary', 'owner_ref')`,
		asset.String(), alice.String())
	h.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type, assignment_source) VALUES ($1, $2, 'secondary', 'manual')`,
		asset.String(), bob.String())

	listed := h.list(asset)
	sources := map[string]string{}
	ids := map[string]string{}
	for _, o := range listed.Data {
		if o.UserID != nil {
			sources[*o.UserID] = o.AssignmentSource
			ids[*o.UserID] = o.ID
		}
	}
	if sources[alice.String()] != "owner_ref" || sources[bob.String()] != "manual" {
		t.Fatalf("listed sources = %v, want alice owner_ref and bob manual", sources)
	}

	ownerRef := func() string {
		var ref sql.NullString
		if err := h.db.QueryRow(`SELECT owner_ref FROM assets WHERE id = $1`, asset.String()).Scan(&ref); err != nil {
			t.Fatal(err)
		}
		return ref.String
	}

	if status, body := h.do(http.MethodDelete, "/api/v1/assets/"+asset.String()+"/owners/"+ids[bob.String()], nil); status != http.StatusNoContent {
		t.Fatalf("remove manual owner = %d %s", status, body)
	}
	if ownerRef() == "" {
		t.Fatal("removing a manual owner cleared owner_ref")
	}

	if status, body := h.do(http.MethodDelete, "/api/v1/assets/"+asset.String()+"/owners/"+ids[alice.String()], nil); status != http.StatusNoContent {
		t.Fatalf("remove owner_ref owner = %d %s", status, body)
	}
	if got := ownerRef(); got != "" {
		t.Fatalf("owner_ref after removing its owner = %q, want empty", got)
	}
	if n := len(h.list(asset).Data); n != 0 {
		t.Fatalf("owners left = %d, want 0", n)
	}
}

func (h *aoHarness) canSee(user, asset shared.ID) bool {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM user_accessible_assets WHERE user_id = $1 AND asset_id = $2`,
		user.String(), asset.String()).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n > 0
}

func (h *aoHarness) scopeRows(user shared.ID) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRow(`SELECT COUNT(*) FROM user_accessible_assets WHERE user_id = $1`, user.String()).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// Owner decision O1: naming a user as an owner (any type) is an assignment
// only and never changes their data scope, and removing an owner never takes
// away access a grant gives.
func TestAssetOwners_AddingAUserOwnerDoesNotChangeDataScope(t *testing.T) {
	h := newAOHarness(t)
	dev := h.member("dev")
	asset := h.asset("")

	for _, typ := range []string{"primary", "secondary", "stakeholder", "informed"} {
		a := h.asset("")
		status, body := h.do(http.MethodPost, "/api/v1/assets/"+a.String()+"/owners",
			map[string]string{"user_id": dev.String(), "ownership_type": typ})
		if status != http.StatusCreated {
			t.Fatalf("add %s owner = %d %s", typ, status, body)
		}
	}
	if n := h.scopeRows(dev); n != 0 {
		t.Fatalf("adding user owners created %d data-scope rows, want 0 (fail-open user would drop to seeing only these)", n)
	}

	// A grant gives access; adding then removing an owner leaves it alone.
	h.setPerms(permission.AssetsRead, permission.AssetsWrite, permission.AssetsDelete, permission.GroupsRead, permission.GroupsWrite)
	if status, body := h.do(http.MethodPost, "/api/v1/assets/"+asset.String()+"/access-grants",
		map[string]string{"user_id": dev.String()}); status != http.StatusCreated {
		t.Fatalf("grant = %d %s", status, body)
	}
	status, body := h.do(http.MethodPost, "/api/v1/assets/"+asset.String()+"/owners",
		map[string]string{"user_id": dev.String(), "ownership_type": "primary"})
	if status != http.StatusCreated {
		t.Fatalf("add owner = %d %s", status, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &created)
	if status, body := h.do(http.MethodDelete, "/api/v1/assets/"+asset.String()+"/owners/"+created.ID, nil); status != http.StatusNoContent {
		t.Fatalf("remove owner = %d %s", status, body)
	}
	if !h.canSee(dev, asset) {
		t.Fatal("removing an owner took away access given by an explicit grant")
	}
}

// A group owner is the group's data-scope assignment: adding or removing one
// needs team:groups:write, and with it the group's members see the asset.
func TestAssetOwners_GroupOwnerNeedsGroupsWrite(t *testing.T) {
	h := newAOHarness(t)
	dev := h.member("dev")
	asset := h.asset("")
	group := shared.NewID()
	h.exec(`INSERT INTO groups (id, tenant_id, name, slug, is_active) VALUES ($1, $2, $3, $3, true)`,
		group.String(), h.tenant.String(), "g-"+group.String())
	h.exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`, group.String(), dev.String())

	add := map[string]string{"group_id": group.String(), "ownership_type": "secondary"}
	if status, body := h.do(http.MethodPost, "/api/v1/assets/"+asset.String()+"/owners", add); status != http.StatusForbidden {
		t.Fatalf("add group owner with assets:write only = %d %s, want 403", status, body)
	}
	if h.canSee(dev, asset) {
		t.Fatal("refused group owner still gave access")
	}

	h.setPerms(permission.AssetsRead, permission.AssetsWrite, permission.AssetsDelete, permission.GroupsWrite)
	status, body := h.do(http.MethodPost, "/api/v1/assets/"+asset.String()+"/owners", add)
	if status != http.StatusCreated {
		t.Fatalf("add group owner with groups:write = %d %s", status, body)
	}
	if !h.canSee(dev, asset) {
		t.Fatal("group owner (group assignment) did not give its member access")
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal([]byte(body), &created)

	h.setPerms(permission.AssetsRead, permission.AssetsWrite, permission.AssetsDelete)
	if status, body := h.do(http.MethodDelete, "/api/v1/assets/"+asset.String()+"/owners/"+created.ID, nil); status != http.StatusForbidden {
		t.Fatalf("remove group owner without groups:write = %d %s, want 403", status, body)
	}
	h.setPerms(permission.AssetsRead, permission.AssetsWrite, permission.AssetsDelete, permission.GroupsWrite)
	if status, body := h.do(http.MethodDelete, "/api/v1/assets/"+asset.String()+"/owners/"+created.ID, nil); status != http.StatusNoContent {
		t.Fatalf("remove group owner = %d %s", status, body)
	}
	if h.canSee(dev, asset) {
		t.Fatal("removing the group owner left the member's access")
	}
}

// Explicit access grants: tenant-isolated, idempotence refused with 409,
// revoke keeps access a group still gives.
func TestAssetAccessGrants_Lifecycle(t *testing.T) {
	h := newAOHarness(t)
	dev := h.member("dev")
	asset := h.asset("")
	path := "/api/v1/assets/" + asset.String() + "/access-grants"

	// Another tenant's member and another tenant's asset.
	other := shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "ao-"+other.String())
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM tenants WHERE id = $1`, other.String()) })
	stranger := shared.NewID()
	h.exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'stranger')`, stranger.String(), stranger.String()+"@ao.test")
	t.Cleanup(func() { _, _ = h.db.Exec(`DELETE FROM users WHERE id = $1`, stranger.String()) })
	h.exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, stranger.String(), other.String())
	foreignAsset := shared.NewID()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`,
		foreignAsset.String(), other.String(), "ao-"+foreignAsset.String())

	// assets:* alone cannot read or write grants (route gate).
	if status, _ := h.do(http.MethodGet, path, nil); status != http.StatusForbidden {
		t.Fatalf("list grants without groups:read = %d, want 403", status)
	}
	h.setPerms(permission.AssetsRead, permission.GroupsRead, permission.GroupsWrite)

	if status, body := h.do(http.MethodPost, path, map[string]string{"user_id": stranger.String()}); status != http.StatusNotFound {
		t.Fatalf("grant to another tenant's user = %d %s, want 404", status, body)
	}
	if status, body := h.do(http.MethodPost, "/api/v1/assets/"+foreignAsset.String()+"/access-grants",
		map[string]string{"user_id": dev.String()}); status != http.StatusNotFound {
		t.Fatalf("grant on another tenant's asset = %d %s, want 404", status, body)
	}
	status, body := h.do(http.MethodPost, path, map[string]string{"user_id": dev.String()})
	if status != http.StatusCreated {
		t.Fatalf("grant = %d %s", status, body)
	}
	var g struct {
		ID     string `json:"id"`
		Source string `json:"source"`
	}
	_ = json.Unmarshal([]byte(body), &g)
	if g.Source != "manual" || !h.canSee(dev, asset) {
		t.Fatalf("grant %+v did not give access", g)
	}
	if status, _ := h.do(http.MethodPost, path, map[string]string{"user_id": dev.String()}); status != http.StatusConflict {
		t.Fatalf("duplicate grant = %d, want 409", status)
	}
	status, body = h.do(http.MethodGet, path, nil)
	if status != http.StatusOK || !strings.Contains(body, dev.String()) {
		t.Fatalf("list grants = %d %s", status, body)
	}
	// Another tenant's grant id cannot be revoked through this asset.
	if status, _ := h.do(http.MethodDelete, "/api/v1/assets/"+foreignAsset.String()+"/access-grants/"+g.ID, nil); status != http.StatusNotFound {
		t.Fatalf("revoke via another tenant's asset = %d, want 404", status)
	}

	// A group still giving access keeps it after the revoke.
	group := shared.NewID()
	h.exec(`INSERT INTO groups (id, tenant_id, name, slug, is_active) VALUES ($1, $2, $3, $3, true)`,
		group.String(), h.tenant.String(), "g-"+group.String())
	h.exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`, group.String(), dev.String())
	h.exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'secondary')`, asset.String(), group.String())
	if status, _ := h.do(http.MethodDelete, path+"/"+g.ID, nil); status != http.StatusNoContent {
		t.Fatalf("revoke = %d", status)
	}
	if !h.canSee(dev, asset) {
		t.Fatal("revoke removed access the group still gives")
	}
	h.exec(`DELETE FROM asset_owners WHERE asset_id = $1 AND group_id = $2`, asset.String(), group.String())
	h.exec(`SELECT refresh_access_for_asset_unassign($1, $2)`, group.String(), asset.String())
	if h.canSee(dev, asset) {
		t.Fatal("access remained with neither grant nor group")
	}
}

// A user cannot grant themself access to an asset (23b I-M5): a member about
// to leave a group could otherwise turn the group-derived access into a
// permanent personal grant.
func TestAssetAccessGrants_SelfGrantRefused(t *testing.T) {
	h := newAOHarness(t)
	asset := h.asset("")
	h.setPerms(permission.AssetsRead, permission.GroupsRead, permission.GroupsWrite)
	status, body := h.do(http.MethodPost, "/api/v1/assets/"+asset.String()+"/access-grants",
		map[string]string{"user_id": h.actor.String()})
	if status != http.StatusForbidden {
		t.Fatalf("self-grant = %d %s, want 403", status, body)
	}
	if h.canSee(h.actor, asset) {
		t.Fatalf("refused self-grant still gave access")
	}
}
