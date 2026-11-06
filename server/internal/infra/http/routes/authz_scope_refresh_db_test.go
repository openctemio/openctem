package routes

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A rebuild after one tenant's scope rule changed touches only that tenant's
// scope rows; the global rebuild truncated every tenant's.
func TestScopeRefreshForTenantLeavesOtherTenantsAlone(t *testing.T) {
	h := newDSHarness(t)
	otherTenant, otherUser, otherAsset := shared.NewID(), shared.NewID(), shared.NewID()
	// Plant a row for a tenant that exists nowhere, with triggers and
	// foreign keys off on one superuser connection.
	conn, err := testdb.OpenAdmin(t).Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(t.Context(), `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(t.Context(), `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'primary')`,
		otherUser.String(), otherTenant.String(), otherAsset.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(t.Context(), `SET session_replication_role = DEFAULT`); err != nil {
		t.Fatal(err)
	}
	repo := postgres.NewAccessControlRepository(&postgres.DB{DB: h.db})
	if err := repo.RefreshUserAccessibleAssetsForTenant(t.Context(), h.tenant); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM user_accessible_assets WHERE tenant_id = $1`, otherTenant.String()).Scan(&n)
	if n != 1 {
		t.Errorf("another tenant's scope rows = %d after a tenant rebuild, want 1 (untouched)", n)
	}
	if _, err := conn.ExecContext(t.Context(), `DELETE FROM user_accessible_assets WHERE tenant_id = $1`, otherTenant.String()); err != nil {
		t.Fatal(err)
	}
}
