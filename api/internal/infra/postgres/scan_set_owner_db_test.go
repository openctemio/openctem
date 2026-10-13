package postgres

// SetOwner: an administrator taking ownership of a scan whose owner is
// missing (docs/architecture/scan-ownership.md). Tenant-scoped and a
// compare-and-swap on the previous owner.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestScanRepository_SetOwner_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	repo := NewScanRepository(&DB{DB: db})
	tenantA := seedScanTriggerTenant(ctx, t, db)
	tenantB := seedScanTriggerTenant(ctx, t, db)
	admin := seedSWUser(ctx, t, db)
	other := seedSWUser(ctx, t, db)

	sc, err := scan.NewScan(tenantA, "ownerless", shared.ID{}, scan.ScanTypeSingle)
	if err != nil {
		t.Fatal(err)
	}
	sc.SetTargets([]string{"example.com"})
	if err := sc.SetSingleScanner("nuclei", nil, 1); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM scans WHERE id = $1`, sc.ID.String()) })

	owner := func() *shared.ID {
		got, err := repo.GetByTenantAndID(ctx, tenantA, sc.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.CreatedBy
	}

	if ok, err := repo.SetOwner(ctx, tenantB, sc.ID, nil, admin); err != nil || ok {
		t.Fatalf("another tenant set the owner: ok=%v err=%v", ok, err)
	}
	if owner() != nil {
		t.Fatal("cross-tenant SetOwner changed the scan")
	}
	if ok, err := repo.SetOwner(ctx, tenantA, sc.ID, &other, admin); err != nil || ok {
		t.Fatalf("stale previous owner won: ok=%v err=%v", ok, err)
	}
	if ok, err := repo.SetOwner(ctx, tenantA, sc.ID, nil, admin); err != nil || !ok {
		t.Fatalf("set owner: ok=%v err=%v", ok, err)
	}
	if got := owner(); got == nil || *got != admin {
		t.Fatalf("owner = %v, want %s", got, admin)
	}
	// A second take-over that still expects no owner loses the race.
	if ok, err := repo.SetOwner(ctx, tenantA, sc.ID, nil, other); err != nil || ok {
		t.Fatalf("second take-over won: ok=%v err=%v", ok, err)
	}
}
