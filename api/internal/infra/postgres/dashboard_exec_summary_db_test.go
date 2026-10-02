package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

func seedExecFinding(ctx context.Context, t *testing.T, db *sql.DB, tenantID, assetID shared.ID, status, priority, sla string) {
	t.Helper()
	id := shared.NewID()
	var prio any
	if priority != "" {
		prio = priority
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, priority_class, sla_status)
		VALUES ($1, $2, $3, 'sca', 'test', 'msg', 'high', $4, $5, $6, $7)`,
		id.String(), tenantID.String(), assetID.String(), id.String(), status, prio, sla); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
}

// The executive summary's open-finding figures come from one aggregate pass
// (open_agg) instead of 8 sub-selects over a materialized CTE. Pin the
// numbers: open total, P0/P1 open, SLA breached and SLA compliance, all
// tenant-scoped and excluding closed statuses.
func TestExecutiveSummary_OpenAggregates(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardRepository(db)

	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)
	assetA := seedOwnedAsset(ctx, t, db, tenantA, nil)
	assetB := seedOwnedAsset(ctx, t, db, tenantB, nil)

	seedExecFinding(ctx, t, db, tenantA, assetA, "new", "P0", "overdue")
	seedExecFinding(ctx, t, db, tenantA, assetA, "confirmed", "P0", "on_track")
	seedExecFinding(ctx, t, db, tenantA, assetA, "in_progress", "P1", "exceeded")
	seedExecFinding(ctx, t, db, tenantA, assetA, "new", "", "on_track")
	seedExecFinding(ctx, t, db, tenantA, assetA, "resolved", "P0", "overdue")       // closed
	seedExecFinding(ctx, t, db, tenantA, assetA, "false_positive", "P1", "overdue") // closed
	seedExecFinding(ctx, t, db, tenantB, assetB, "new", "P0", "overdue")            // other tenant

	s, err := repo.GetExecutiveSummary(ctx, tenantA, 30)
	if err != nil {
		t.Fatalf("GetExecutiveSummary: %v", err)
	}
	if s.FindingsTotal != 4 || s.P0Open != 2 || s.P1Open != 1 || s.SLABreached != 2 {
		t.Fatalf("open aggregates wrong: total=%d p0=%d p1=%d breached=%d",
			s.FindingsTotal, s.P0Open, s.P1Open, s.SLABreached)
	}
	if s.SLACompliancePct != 50 {
		t.Fatalf("SLA compliance: want 50, got %v", s.SLACompliancePct)
	}

	empty := seedTestTenant(ctx, t, db)
	e, err := repo.GetExecutiveSummary(ctx, empty, 30)
	if err != nil {
		t.Fatalf("empty tenant: %v", err)
	}
	if e.FindingsTotal != 0 || e.SLACompliancePct != 100 {
		t.Fatalf("empty tenant: want total 0 / compliance 100, got %d / %v", e.FindingsTotal, e.SLACompliancePct)
	}
}
