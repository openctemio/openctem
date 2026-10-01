package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/infra/postgres"
	"github.com/openctemio/api/pkg/domain/shared"
)

// These repositories deleted with "WHERE tenant_id = $1 AND id = $2" and never
// looked at the affected-row count, so DELETE of an id that does not exist —
// or that belongs to another tenant — answered 204 as if it had worked. The
// v0.9.0 API crawl saw tenant B "delete" six of tenant A's records with 204
// (the rows survived; nothing leaked, but the API claimed success).
func TestDeleteOfAnIDOutsideTheTenantIsNotFound(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	owner := createTestTenant(t, db, "delete-owner")
	other := createTestTenant(t, db, "delete-other")
	unitID := shared.NewID()
	if _, err := db.Exec(`INSERT INTO business_units (id, tenant_id, name) VALUES ($1, $2, 'bu')`,
		unitID.String(), owner.String()); err != nil {
		t.Fatalf("insert business unit: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM business_units WHERE tenant_id = $1`, owner.String())
		for _, id := range []shared.ID{owner, other} {
			_, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id.String())
		}
	})

	pg := &postgres.DB{DB: db}
	deletes := map[string]func(tenant, id shared.ID) error{
		"business unit": func(tn, id shared.ID) error { return postgres.NewBusinessUnitRepository(pg).Delete(ctx, tn, id) },
		"control test":  func(tn, id shared.ID) error { return postgres.NewControlTestRepository(pg).Delete(ctx, tn, id) },
		"remediation campaign": func(tn, id shared.ID) error {
			return postgres.NewRemediationCampaignRepository(pg).Delete(ctx, tn, id)
		},
		"report schedule": func(tn, id shared.ID) error { return postgres.NewReportScheduleRepository(pg).Delete(ctx, tn, id) },
		"simulation":      func(tn, id shared.ID) error { return postgres.NewSimulationRepository(pg).Delete(ctx, tn, id) },
		"threat actor":    func(tn, id shared.ID) error { return postgres.NewThreatActorRepository(pg).Delete(ctx, tn, id) },
	}
	for name, del := range deletes {
		if err := del(owner, shared.NewID()); !errors.Is(err, shared.ErrNotFound) {
			t.Errorf("%s: delete of an unknown id returned %v, want shared.ErrNotFound", name, err)
		}
	}

	// Another tenant's delete is a not-found and leaves the row alone ...
	if err := deletes["business unit"](other, unitID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete returned %v, want shared.ErrNotFound", err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM business_units WHERE id = $1`, unitID.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("row after cross-tenant delete: count=%d err=%v", n, err)
	}
	// ... and the owner's delete still works.
	if err := deletes["business unit"](owner, unitID); err != nil {
		t.Fatalf("owner delete: %v", err)
	}
}
