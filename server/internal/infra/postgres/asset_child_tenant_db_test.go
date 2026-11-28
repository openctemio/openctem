package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/internal/testdb"
	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/attribution"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// The asset reads of child tables keyed by asset id are pinned to the
// asset's tenant too (defense in depth): a row of another tenant that names
// this asset's id (planted with constraints off, as a bug or a restore
// could leave it) changes nothing the asset's own tenant reads, neither the
// "rescore pending" mark nor the open findings the statistics count.
func TestAssetChildReads_PinnedToTenant_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	admin := testdb.OpenAdmin(t)
	repo := NewAssetRepository(&DB{DB: db})
	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)

	a, err := asset.NewAssetWithTenant(tenantA, "child-tenant__test.example.com", asset.AssetTypeDomain, asset.CriticalityHigh)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	seedDashFinding(ctx, t, db, tenantA, a.ID(), "high", "new", nil)

	conn, err := admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SET session_replication_role = replica`); err != nil {
		t.Skipf("cannot plant rows with constraints off: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `DELETE FROM asset_risk_queue WHERE asset_id = $1`, a.ID().String()); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO asset_risk_queue (asset_id, tenant_id, enqueued_at) VALUES ($1, $2, now() - interval '1 minute')`,
		a.ID().String(), tenantB.String()); err != nil {
		t.Fatalf("plant risk queue row: %v", err)
	}
	fid := shared.NewID().String()
	if _, err := conn.ExecContext(ctx, `
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, $3, 'sca', 'test', 'msg', 'critical', $1, 'new')`, fid, tenantB.String(), a.ID().String()); err != nil {
		t.Fatalf("plant finding: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `RESET session_replication_role`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.ExecContext(context.Background(), `DELETE FROM findings WHERE id = $1`, fid)
		_, _ = admin.ExecContext(context.Background(), `DELETE FROM asset_risk_queue WHERE asset_id = $1`, a.ID().String())
	})

	got, err := repo.GetByID(ctx, tenantA, a.ID())
	if err != nil {
		t.Fatal(err)
	}
	if got.RiskScorePending() {
		t.Error("risk_score_pending is true from another tenant's queue row")
	}

	stats, err := repo.GetAggregateStats(ctx, tenantA, asset.AccessScope{}, nil, nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if stats.FindingsTotal != 1 || stats.WithFindings != 1 {
		t.Errorf("stats findings_total=%d with_findings=%d, want 1 and 1 (another tenant's finding on the asset id counted)",
			stats.FindingsTotal, stats.WithFindings)
	}
}

// The "no attribution record" filter looks for the record in the asset's
// own tenant, like every other attribution condition.
func TestAttributionCond_UnrecordedPinnedToTenant(t *testing.T) {
	cond, _ := attributionCond(&attribution.StateFilter{Unrecorded: true}, 1)
	if !strings.Contains(cond, "aat.tenant_id = a.tenant_id") {
		t.Errorf("unrecorded condition is not pinned to the tenant: %s", cond)
	}
}
