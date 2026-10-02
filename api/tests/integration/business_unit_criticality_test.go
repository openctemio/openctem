package integration

import (
	"context"
	"errors"
	"testing"

	assetapp "github.com/openctemio/api/internal/app/asset"
	"github.com/openctemio/api/internal/infra/postgres"
	businessunit "github.com/openctemio/api/pkg/domain/businessunit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// TestBusinessUnitCriticalityRoundTrip proves that criticality, risk_tolerance
// and parent_id actually persist through the repository (the audit found these
// were UI-only phantoms fed by a hardcoded 'medium') and that parent linkage is
// same-tenant, non-self and cycle-free.
func TestBusinessUnitCriticalityRoundTrip(t *testing.T) {
	db := setupTestDB(t)
	// Register Close first so it runs LAST (t.Cleanup is LIFO) — after the
	// delete cleanup below. A plain `defer db.Close()` would shut the pool
	// before Cleanup runs, silently orphaning the test rows.
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()

	tenant := createTestTenant(t, db, "bu-crit")
	otherTenant := createTestTenant(t, db, "bu-crit-other")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM business_units WHERE tenant_id IN ($1,$2)`, tenant.String(), otherTenant.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id IN ($1,$2)`, tenant.String(), otherTenant.String())
	})

	repo := postgres.NewBusinessUnitRepository(&postgres.DB{DB: db})
	svc := assetapp.NewBusinessUnitService(repo, nil, logger.NewNop())

	strptr := func(s string) *string { return &s }

	// Create parent BU with explicit criticality/risk_tolerance.
	parent, err := svc.Create(ctx, assetapp.CreateBusinessUnitInput{
		TenantID: tenant.String(), Name: "__test-parent",
		Criticality: strptr("high"), RiskTolerance: strptr("low"),
	})
	if err != nil {
		t.Fatalf("create parent: %v", err)
	}

	// Round-trip parent through the DB.
	pid, _ := shared.IDFromString(parent.ID().String())
	got, err := repo.GetByID(ctx, tenant, pid)
	if err != nil {
		t.Fatalf("get parent: %v", err)
	}
	if got.Criticality() != businessunit.CriticalityHigh {
		t.Errorf("parent criticality = %q, want high", got.Criticality())
	}
	if got.RiskTolerance() != businessunit.RiskToleranceLow {
		t.Errorf("parent risk_tolerance = %q, want low", got.RiskTolerance())
	}
	if got.ParentID() != nil {
		t.Errorf("parent should have no parent, got %v", got.ParentID())
	}

	// Create child linked to parent.
	child, err := svc.Create(ctx, assetapp.CreateBusinessUnitInput{
		TenantID: tenant.String(), Name: "__test-child",
		Criticality: strptr("critical"), ParentID: strptr(parent.ID().String()),
	})
	if err != nil {
		t.Fatalf("create child: %v", err)
	}
	cid, _ := shared.IDFromString(child.ID().String())
	gotChild, err := repo.GetByID(ctx, tenant, cid)
	if err != nil {
		t.Fatalf("get child: %v", err)
	}
	if gotChild.ParentID() == nil || *gotChild.ParentID() != parent.ID() {
		t.Errorf("child parent_id = %v, want %s", gotChild.ParentID(), parent.ID())
	}
	if gotChild.Criticality() != businessunit.CriticalityCritical {
		t.Errorf("child criticality = %q, want critical", gotChild.Criticality())
	}
	// Default risk_tolerance applied when omitted.
	if gotChild.RiskTolerance() != businessunit.RiskToleranceMedium {
		t.Errorf("child default risk_tolerance = %q, want medium", gotChild.RiskTolerance())
	}

	// Update round-trips changes.
	if _, err := svc.Update(ctx, assetapp.UpdateBusinessUnitInput{
		TenantID: tenant.String(), ID: child.ID().String(),
		Name: "__test-child", Criticality: strptr("low"), RiskTolerance: strptr("high"),
	}); err != nil {
		t.Fatalf("update child: %v", err)
	}
	gotChild, _ = repo.GetByID(ctx, tenant, cid)
	if gotChild.Criticality() != businessunit.CriticalityLow || gotChild.RiskTolerance() != businessunit.RiskToleranceHigh {
		t.Errorf("after update crit=%q risk=%q, want low/high", gotChild.Criticality(), gotChild.RiskTolerance())
	}

	// --- Rejections ---

	// Invalid enum.
	if _, err := svc.Create(ctx, assetapp.CreateBusinessUnitInput{
		TenantID: tenant.String(), Name: "__test-badcrit", Criticality: strptr("bogus"),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("invalid criticality: want ErrValidation, got %v", err)
	}

	// Self-parent.
	if _, err := svc.Update(ctx, assetapp.UpdateBusinessUnitInput{
		TenantID: tenant.String(), ID: parent.ID().String(),
		Name: "__test-parent", ParentID: strptr(parent.ID().String()),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("self-parent: want ErrValidation, got %v", err)
	}

	// Cross-tenant parent (parent exists but in another tenant).
	otherBU, err := svc.Create(ctx, assetapp.CreateBusinessUnitInput{
		TenantID: otherTenant.String(), Name: "__test-foreign",
	})
	if err != nil {
		t.Fatalf("create foreign bu: %v", err)
	}
	if _, err := svc.Update(ctx, assetapp.UpdateBusinessUnitInput{
		TenantID: tenant.String(), ID: child.ID().String(),
		Name: "__test-child", ParentID: strptr(otherBU.ID().String()),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("cross-tenant parent: want ErrValidation, got %v", err)
	}

	// Cycle: make parent's parent = child (child already points to parent).
	if _, err := svc.Update(ctx, assetapp.UpdateBusinessUnitInput{
		TenantID: tenant.String(), ID: parent.ID().String(),
		Name: "__test-parent", ParentID: strptr(child.ID().String()),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("cycle: want ErrValidation, got %v", err)
	}

	// Bogus/nonexistent parent id.
	if _, err := svc.Update(ctx, assetapp.UpdateBusinessUnitInput{
		TenantID: tenant.String(), ID: child.ID().String(),
		Name: "__test-child", ParentID: strptr(shared.NewID().String()),
	}); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("bogus parent: want ErrValidation, got %v", err)
	}
}
