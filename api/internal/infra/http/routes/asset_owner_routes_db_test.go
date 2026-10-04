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
	perms := []string{permission.AssetsRead.String(), permission.AssetsWrite.String(), permission.AssetsDelete.String()}
	auth := Middleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, middleware.UserIDKey, h.actor.String())
			ctx = context.WithValue(ctx, middleware.TenantIDKey, h.tenant.String())
			ctx = context.WithValue(ctx, middleware.IsAdminKey, false)
			ctx = context.WithValue(ctx, middleware.PermissionsKey, perms)
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
