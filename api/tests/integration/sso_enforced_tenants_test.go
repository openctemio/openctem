package integration

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ListSSOEnforcedTenantIDs lists exactly the organizations whose security
// settings require SSO (the post-downgrade sweep reads it).
func TestTenantRepository_ListSSOEnforcedTenantIDs(t *testing.T) {
	sqlDB := setupTestDB(t)
	ctx := context.Background()
	enforced := createTestTenant(t, sqlDB, "sso-enforced")
	plain := createTestTenant(t, sqlDB, "sso-plain")
	t.Cleanup(func() { cleanupTestData(sqlDB, enforced); cleanupTestData(sqlDB, plain) })
	if _, err := sqlDB.ExecContext(ctx,
		`UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{security}', '{"sso_enforced": true}'::jsonb) WHERE id = $1`,
		enforced.String()); err != nil {
		t.Fatalf("seed enforcement: %v", err)
	}
	repo := postgres.NewTenantRepository(&postgres.DB{DB: sqlDB})
	ids, err := repo.ListSSOEnforcedTenantIDs(ctx, 100000)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	has := func(id shared.ID) bool {
		for _, x := range ids {
			if x == id {
				return true
			}
		}
		return false
	}
	if !has(enforced) || has(plain) {
		t.Fatalf("enforced listed=%v, plain listed=%v", has(enforced), has(plain))
	}
}
