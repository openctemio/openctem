package handler

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Naming a user or group of another tenant as an asset owner must answer
// exactly what naming an unknown id answers (404), so the response never
// confirms that an id exists in another organization.
func TestAddAssetOwner_NoCrossTenantExistenceOracle_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("seed: %v (%s)", err, q)
		}
	}
	tenantA, tenantB := shared.NewID(), shared.NewID()
	for _, tn := range []shared.ID{tenantA, tenantB} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'oracle', $2)`, tn.String(), "o-"+tn.String())
		tn := tn
		t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, tn.String()) })
	}
	mkUser := func(tenant shared.ID) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'u')`, id.String(), id.String()+"@oracle.example.com")
		exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, id.String(), tenant.String())
		t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id.String()) })
		return id
	}
	mkGroup := func(tenant shared.ID) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, 'g', $3)`, id.String(), tenant.String(), "g-"+id.String())
		return id
	}
	assetID := shared.NewID()
	exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'host')`, assetID.String(), tenantA.String(), "a-"+assetID.String())
	ownUser, foreignUser := mkUser(tenantA), mkUser(tenantB)
	ownGroup, foreignGroup := mkGroup(tenantA), mkGroup(tenantB)

	pdb := &postgres.DB{DB: db}
	h := NewAssetOwnerHandler(postgres.NewAccessControlRepository(pdb), postgres.NewAssetRepository(pdb), logger.NewNop())

	post := func(body string) (int, string) {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/assets/"+assetID.String()+"/owners", bytes.NewBufferString(body))
		r.SetPathValue("id", assetID.String())
		c := context.WithValue(r.Context(), middleware.TenantIDKey, tenantA.String())
		c = context.WithValue(c, middleware.UserIDKey, ownUser.String())
		c = context.WithValue(c, middleware.IsAdminKey, true)
		w := httptest.NewRecorder()
		h.AddOwner(w, r.WithContext(c))
		return w.Code, w.Body.String()
	}

	for _, field := range []string{"user_id", "group_id"} {
		foreign, unknown := foreignUser, shared.NewID()
		if field == "group_id" {
			foreign = foreignGroup
		}
		fc, fb := post(`{"` + field + `":"` + foreign.String() + `","ownership_type":"informed"}`)
		uc, ub := post(`{"` + field + `":"` + unknown.String() + `","ownership_type":"informed"}`)
		if fc != http.StatusNotFound {
			t.Errorf("%s of another tenant: status %d, want 404 (%s)", field, fc, fb)
		}
		if fc != uc || len(fb) == 0 || fb != ub {
			t.Errorf("%s: foreign id answered %d %s, unknown id answered %d %s; they must be identical", field, fc, fb, uc, ub)
		}
	}

	// Positive control: members of the caller's own tenant are accepted.
	for _, body := range []string{
		`{"user_id":"` + ownUser.String() + `","ownership_type":"informed"}`,
		`{"group_id":"` + ownGroup.String() + `","ownership_type":"informed"}`,
	} {
		if code, b := post(body); code != http.StatusCreated && code != http.StatusOK {
			t.Errorf("own-tenant owner refused: %d %s", code, b)
		}
	}
}
