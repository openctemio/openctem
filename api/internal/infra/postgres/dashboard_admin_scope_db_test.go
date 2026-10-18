package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// An administrator reaches every asset except the private-program ones hidden
// from them, so their scope is non-nil but not restricted. Only a restricted
// caller loses the tenant-wide figures (deduplication rate, risk-score change);
// an unrestricted one keeps them.
func TestDashboard_UnrestrictedScopeKeepsTenantWideFigures(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardRepository(db)

	tenant := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	if _, err := db.ExecContext(ctx, `UPDATE assets SET risk_score = 80 WHERE id = $1`, asset.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO asset_merge_log (tenant_id, kept_asset_id, kept_asset_name, correlation_type, action)
		VALUES ($1, $2, 'kept', 'name', 'merge')`, tenant.String(), asset.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO risk_snapshots (tenant_id, snapshot_date, risk_score_avg, findings_open)
		VALUES ($1, CURRENT_DATE - 1, 50, 0)`, tenant.String()); err != nil {
		t.Fatal(err)
	}

	admin := &shared.DataScope{TenantID: tenant, UserID: shared.NewID(), Unrestricted: true}
	member := &shared.DataScope{TenantID: tenant, UserID: shared.NewID()}

	for name, tc := range map[string]struct {
		scope     *shared.DataScope
		wantDedup bool
	}{"admin hidden from a program": {admin, true}, "no scope": {nil, true}, "restricted member": {member, false}} {
		q, err := repo.GetDataQualityScorecard(ctx, tenant, tc.scope)
		if err != nil {
			t.Fatalf("%s scorecard: %v", name, err)
		}
		if got := q.DeduplicationRate > 0; got != tc.wantDedup {
			t.Errorf("%s: dedup rate %v, reported=%v want %v", name, q.DeduplicationRate, got, tc.wantDedup)
		}
		s, err := repo.GetExecutiveSummary(ctx, tenant, tc.scope, tc.scope, 30)
		if err != nil {
			t.Fatalf("%s summary: %v", name, err)
		}
		if tc.wantDedup && s.RiskScoreChange != 30 {
			t.Errorf("%s: risk score change %v, want 30", name, s.RiskScoreChange)
		}
		if !tc.wantDedup && s.RiskScoreChange != 0 {
			t.Errorf("%s: risk score change %v, want 0", name, s.RiskScoreChange)
		}
	}
}
