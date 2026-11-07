package postgres

import (
	"context"
	"math"
	"testing"
)

// Compliance findings (benchmark check results) never count in the
// vulnerability figures: the executive SLA percentage and open counts, and
// the dashboard facts. A practice change marks the asset for a refresh.
func TestDashboard_ComplianceLeftOut_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardRepository(db)
	tenant := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)

	seedExecFinding(ctx, t, db, tenant, asset, "new", "P2", "on_track")
	seedExecFinding(ctx, t, db, tenant, asset, "confirmed", "P2", "overdue")
	// A failed benchmark check, overdue under the vulnerability windows.
	seedExecFinding(ctx, t, db, tenant, asset, "confirmed", "P2", "overdue")
	if _, err := db.ExecContext(ctx, `UPDATE findings SET finding_type = 'compliance', practice = 'compliance', practice_reason = 'benchmark_check'
		WHERE id = (SELECT id FROM findings WHERE tenant_id = $1 AND status = 'confirmed' ORDER BY id LIMIT 1)`, tenant.String()); err != nil {
		t.Fatal(err)
	}

	s, err := repo.GetExecutiveSummary(ctx, tenant, nil, nil, 30)
	if err != nil {
		t.Fatal(err)
	}
	if s.SLACompliancePct == nil || math.Abs(*s.SLACompliancePct-50) > 0.001 {
		t.Fatalf("SLA %% = %v, want 50 (the compliance finding left out)", s.SLACompliancePct)
	}

	if _, err := db.ExecContext(ctx, `SELECT dash_recompute_asset($1, $2)`, tenant.String(), asset.String()); err != nil {
		t.Fatal(err)
	}
	if n := factCount(ctx, t, db, `SELECT COALESCE(sum(finding_count), 0) FROM dash_asset_state WHERE tenant_id = $1`, tenant.String()); n != 2 {
		t.Fatalf("facts count %d findings, want 2 (no compliance)", n)
	}

	// Moving a finding into compliance marks its asset for a refresh.
	if _, err := db.ExecContext(ctx, `DELETE FROM dash_dirty_assets WHERE tenant_id = $1`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE findings SET practice = 'compliance' WHERE tenant_id = $1 AND status = 'new'`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	if n := factCount(ctx, t, db, `SELECT count(*) FROM dash_dirty_assets WHERE tenant_id = $1`, tenant.String()); n == 0 {
		t.Fatal("a practice change did not mark the asset for a fact refresh")
	}
}
