package postgres

import (
	"context"
	"testing"
)

// TestListActiveTenantIDs_ExcludesSystemTenant: the platform system tenant
// (00000000-…-000000000000, seeded by migration 000058 to own system scan
// profiles and templates) is not a customer tenant. Every background sweep
// that iterates ListActiveTenantIDs used to get it; shared.ID treats the zero
// UUID as "empty", so per-tenant services rejected it ("tenant ID is
// required") and cert-monitor logged a warning for it on every tick.
func TestListActiveTenantIDs_ExcludesSystemTenant(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewTenantRepository(&DB{DB: db})

	real := seedTestTenant(ctx, t, db)

	ids, err := repo.ListActiveTenantIDs(ctx)
	if err != nil {
		t.Fatalf("ListActiveTenantIDs: %v", err)
	}
	var sawReal bool
	for _, id := range ids {
		if id.String() == "00000000-0000-0000-0000-000000000000" || id.IsZero() {
			t.Errorf("system tenant returned by ListActiveTenantIDs")
		}
		if id == real {
			sawReal = true
		}
	}
	if !sawReal {
		t.Errorf("a real tenant (%s) is missing from ListActiveTenantIDs", real)
	}
}
