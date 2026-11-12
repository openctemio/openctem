package integration

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// TestAttackPathFindings checks the per-step finding summary of the attack
// paths to one asset: the open count equals the findings list's Open lens for
// the asset (the "View N findings" link opens exactly that list), the lead is
// the open finding with the largest step weight, informational findings and
// low-confidence version matches are never a lead, and another tenant's
// findings are never read.
func TestAttackPathFindings(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()

	tenant := createTestTenant(t, db, "path-findings")
	other := createTestTenant(t, db, "path-findings-other")
	assetA := createTestAsset(t, db, tenant, "path-a")
	assetB := createTestAsset(t, db, tenant, "path-b")
	assetC := createTestAsset(t, db, tenant, "path-c")
	foreign := createTestAsset(t, db, other, "path-foreign")
	t.Cleanup(func() {
		for _, tid := range []shared.ID{tenant, other} {
			_, _ = db.Exec(`DELETE FROM findings WHERE tenant_id=$1`, tid.String())
			_, _ = db.Exec(`DELETE FROM assets WHERE tenant_id=$1`, tid.String())
			_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tid.String())
		}
	})

	insert := func(tid, assetID shared.ID, title, severity, status string, kev bool, epss any, tool string, conf int) string {
		t.Helper()
		id := shared.NewID().String()
		_, err := db.Exec(`
			INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, title,
				severity, status, is_in_kev, epss_score, confidence, fingerprint, created_at, updated_at)
			VALUES ($1::uuid,$2,$3,'manual',$4,$5,$11,$6,$7,$8,$9,$10,$1::text, NOW(), NOW())`,
			id, tid.String(), assetID.String(), tool, title, severity, status, kev, epss, conf, title)
		if err != nil {
			t.Fatalf("insert finding: %v", err)
		}
		return id
	}

	// Asset A: the KEV finding (weight 0.9) beats a critical with EPSS 0.6.
	kevID := insert(tenant, assetA, "kev one", "high", "new", true, 0.2, "test", 100)
	insert(tenant, assetA, "critical epss", "critical", "confirmed", false, 0.6, "test", 100)
	insert(tenant, assetA, "fixed", "critical", "resolved", true, 0.99, "test", 100) // closed: not counted
	insert(tenant, assetA, "info", "info", "new", false, nil, "test", 100)           // counted, never a lead
	// Asset B: only a low-confidence version match and an info finding: counted,
	// no lead (the step is "assumed").
	insert(tenant, assetB, "potential", "critical", "new", false, 0.9, "version-match", 50)
	insert(tenant, assetB, "info b", "info", "new", false, nil, "test", 100)
	// Another tenant's finding on its own asset.
	insert(other, foreign, "foreign", "critical", "new", true, 0.99, "test", 100)

	repo := postgres.NewFindingRepository(&postgres.DB{DB: db})
	got, err := repo.AttackPathFindings(ctx, tenant, []string{assetA.String(), assetB.String(), assetC.String(), foreign.String()})
	if err != nil {
		t.Fatalf("AttackPathFindings: %v", err)
	}

	a := got[assetA.String()]
	if a.OpenCount != 3 || a.KEVCount != 1 {
		t.Errorf("asset A open %d kev %d, want 3 and 1", a.OpenCount, a.KEVCount)
	}
	if a.Lead == nil || a.Lead.ID != kevID || !a.Lead.KEV || a.Lead.Title != "kev one" {
		t.Errorf("asset A lead = %+v, want the KEV finding", a.Lead)
	}
	b := got[assetB.String()]
	if b.OpenCount != 2 || b.Lead != nil {
		t.Errorf("asset B open %d lead %+v, want 2 and no lead", b.OpenCount, b.Lead)
	}
	if _, ok := got[assetC.String()]; ok {
		t.Error("asset C has no open finding and must not appear")
	}
	if _, ok := got[foreign.String()]; ok {
		t.Error("another tenant's asset was read")
	}

	// Parity with the findings list: Open lens, filtered to the asset.
	for _, id := range []shared.ID{assetA, assetB} {
		n, err := repo.Count(ctx, vulnerability.NewFindingFilter().WithTenantID(tenant).WithAssetID(id).
			WithStatuses(vulnerability.OpenStatuses()...))
		if err != nil {
			t.Fatal(err)
		}
		if int(n) != got[id.String()].OpenCount {
			t.Errorf("asset %s: list count %d, path open count %d", id, n, got[id.String()].OpenCount)
		}
	}
}
