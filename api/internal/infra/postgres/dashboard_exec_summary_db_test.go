package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
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

	s, err := repo.GetExecutiveSummary(ctx, tenantA, nil, nil, 30)
	if err != nil {
		t.Fatalf("GetExecutiveSummary: %v", err)
	}
	if s.FindingsTotal != 4 || s.P0Open != 2 || s.P1Open != 1 || s.SLABreached != 2 {
		t.Fatalf("open aggregates wrong: total=%d p0=%d p1=%d breached=%d",
			s.FindingsTotal, s.P0Open, s.P1Open, s.SLABreached)
	}
	if s.SLACompliancePct == nil || *s.SLACompliancePct != 50 {
		t.Fatalf("SLA compliance: want 50, got %v", s.SLACompliancePct)
	}

	empty := seedTestTenant(ctx, t, db)
	e, err := repo.GetExecutiveSummary(ctx, empty, nil, nil, 30)
	if err != nil {
		t.Fatalf("empty tenant: %v", err)
	}
	if e.FindingsTotal != 0 || e.SLACompliancePct != nil {
		t.Fatalf("empty tenant: want total 0 / compliance not measured (nil), got %d / %v", e.FindingsTotal, e.SLACompliancePct)
	}
}

// The dashboard's "current" priority bars read P0..P3 open from the summary
// (live, in the viewer's scope) instead of the last stored snapshot, which
// is organization-wide and a day old: a scoped viewer saw zeros next to their
// own open P1 findings. Scoped tells the web there is no trend to show.
func TestExecutiveSummary_LivePriorityCountsFollowScope(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardRepository(db)

	tenant := seedTestTenant(ctx, t, db)
	mine := seedOwnedAsset(ctx, t, db, tenant, nil)
	other := seedOwnedAsset(ctx, t, db, tenant, nil)
	seedExecFinding(ctx, t, db, tenant, mine, "new", "P1", "on_track")
	seedExecFinding(ctx, t, db, tenant, mine, "new", "P2", "on_track")
	seedExecFinding(ctx, t, db, tenant, mine, "fix_applied", "P3", "on_track")
	seedExecFinding(ctx, t, db, tenant, other, "new", "P0", "on_track")
	seedExecFinding(ctx, t, db, tenant, other, "new", "P2", "on_track")
	seedExecFinding(ctx, t, db, tenant, other, "resolved", "P3", "on_track") // closed

	org, err := repo.GetExecutiveSummary(ctx, tenant, nil, nil, 30)
	if err != nil {
		t.Fatalf("org summary: %v", err)
	}
	if org.P0Open != 1 || org.P1Open != 1 || org.P2Open != 2 || org.P3Open != 1 || org.Scoped {
		t.Fatalf("org: p0..p3 = %d/%d/%d/%d scoped=%v, want 1/1/2/1 false",
			org.P0Open, org.P1Open, org.P2Open, org.P3Open, org.Scoped)
	}
	if sum := org.P0Open + org.P1Open + org.P2Open + org.P3Open; sum != org.FindingsTotal {
		t.Errorf("p0..p3 sum %d != findings_total %d", sum, org.FindingsTotal)
	}

	user := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, 'scoped')`,
		user.String(), "scoped-"+user.String()[:8]+"@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
		user.String(), tenant.String(), mine.String()); err != nil {
		t.Fatalf("seed scope: %v", err)
	}
	scope := &shared.DataScope{TenantID: tenant, UserID: user}
	s, err := repo.GetExecutiveSummary(ctx, tenant, scope, scope, 30)
	if err != nil {
		t.Fatalf("scoped summary: %v", err)
	}
	if s.P0Open != 0 || s.P1Open != 1 || s.P2Open != 1 || s.P3Open != 1 || !s.Scoped {
		t.Fatalf("scoped: p0..p3 = %d/%d/%d/%d scoped=%v, want 0/1/1/1 true",
			s.P0Open, s.P1Open, s.P2Open, s.P3Open, s.Scoped)
	}
}
