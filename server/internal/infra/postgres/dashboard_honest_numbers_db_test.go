package postgres

import (
	"context"
	"database/sql"
	"math"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Honest dashboard numbers: the overdue count is the executive summary's SLA
// breaches, the finding total is the open lens, an SLA percentage and a fix
// time are "not measured" (nil) when there is nothing to measure, and the fix
// time reports the median and the 90th percentile beside the mean.

func TestStats_OverdueEqualsExecutiveSLABreached_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardRepository(db)
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	otherAsset := seedOwnedAsset(ctx, t, db, other, nil)

	seedExecFinding(ctx, t, db, tenant, asset, "new", "P0", "overdue")
	seedExecFinding(ctx, t, db, tenant, asset, "confirmed", "P1", "exceeded")
	seedExecFinding(ctx, t, db, tenant, asset, "in_progress", "P1", "on_track")
	seedExecFinding(ctx, t, db, tenant, asset, "new", "P2", "warning")
	seedExecFinding(ctx, t, db, tenant, asset, "resolved", "P0", "overdue")       // closed work
	seedExecFinding(ctx, t, db, tenant, asset, "false_positive", "P0", "overdue") // closed work
	seedExecFinding(ctx, t, db, other, otherAsset, "new", "P0", "overdue")        // other tenant

	all, err := repo.GetAllStats(ctx, tenant, nil)
	if err != nil {
		t.Fatal(err)
	}
	exec, err := repo.GetExecutiveSummary(ctx, tenant, nil, nil, 30)
	if err != nil {
		t.Fatal(err)
	}
	if all.Findings.Overdue != 2 || all.Findings.Overdue != exec.SLABreached {
		t.Errorf("stats overdue = %d, executive sla_breached = %d, want both 2", all.Findings.Overdue, exec.SLABreached)
	}
	// The total is the open lens (4), and the executive summary agrees.
	if all.Findings.Total != 4 || all.Findings.Total != exec.FindingsTotal {
		t.Errorf("stats total = %d, executive total = %d, want both 4 (open only)", all.Findings.Total, exec.FindingsTotal)
	}
	sum := 0
	for _, n := range all.Findings.BySeverity {
		sum += n
	}
	if sum != all.Findings.Total {
		t.Errorf("by-severity sums to %d, total is %d: they must be the same population", sum, all.Findings.Total)
	}
	// A viewer scoped to no asset counts nothing, whatever the tenant holds.
	scoped, err := repo.GetAllStats(ctx, tenant, &shared.DataScope{TenantID: tenant, UserID: shared.NewID()})
	if err != nil {
		t.Fatal(err)
	}
	if scoped.Findings.Overdue != 0 || scoped.Findings.Total != 0 {
		t.Errorf("scope-less viewer sees overdue %d / total %d, want 0 / 0", scoped.Findings.Overdue, scoped.Findings.Total)
	}
}

func TestExecutiveSLA_DenominatorIsFindingsWithAnSLA_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardRepository(db)
	tenant := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)

	sla := func() *float64 {
		t.Helper()
		s, err := repo.GetExecutiveSummary(ctx, tenant, nil, nil, 30)
		if err != nil {
			t.Fatal(err)
		}
		return s.SLACompliancePct
	}
	if got := sla(); got != nil {
		t.Fatalf("no findings: SLA %% = %v, want nil (not measured), never 100", *got)
	}
	// Open findings without an SLA do not make the percentage measurable.
	seedExecFinding(ctx, t, db, tenant, asset, "new", "P3", "not_applicable")
	if _, err := db.ExecContext(ctx, `UPDATE findings SET sla_status = NULL WHERE tenant_id = $1`, tenant.String()); err != nil {
		t.Fatal(err)
	}
	seedExecFinding(ctx, t, db, tenant, asset, "new", "P3", "not_applicable")
	if got := sla(); got != nil {
		t.Fatalf("only findings without an SLA: SLA %% = %v, want nil", *got)
	}
	// 1 of 2 tracked findings is past its SLA: 50 %, however many untracked
	// findings sit beside them.
	seedExecFinding(ctx, t, db, tenant, asset, "new", "P0", "on_track")
	seedExecFinding(ctx, t, db, tenant, asset, "confirmed", "P0", "overdue")
	if got := sla(); got == nil || math.Abs(*got-50) > 0.001 {
		t.Fatalf("SLA %% = %v, want 50", got)
	}
}

func TestMTTR_NullWhenEmptyAndMedianP90_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardRepository(db)
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	otherAsset := seedOwnedAsset(ctx, t, db, other, nil)

	s, err := repo.GetExecutiveSummary(ctx, tenant, nil, nil, 30)
	if err != nil {
		t.Fatal(err)
	}
	if s.MTTRCriticalHrs != nil || s.MTTRCriticalMedianHrs != nil || s.MTTRCriticalP90Hrs != nil || s.MTTRHighHrs != nil || s.MTTRCriticalSample != 0 {
		t.Fatalf("nothing fixed: executive MTTR must be nil (not 0 h), got %+v", s)
	}
	a, err := repo.GetMTTRAnalytics(ctx, tenant, nil, 90)
	if err != nil {
		t.Fatal(err)
	}
	if a.Overall != nil || a.OverallMedian != nil || a.OverallP90 != nil || len(a.BySeverity) != 0 || len(a.ByPriorityClass) != 0 || a.SampleSize != 0 {
		t.Fatalf("nothing fixed: analytics must be empty/nil, got %+v", a)
	}

	seed := func(tid, aid shared.ID, hours int) {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `
			INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status,
				first_detected_at, resolved_at, closure_reason, verification, priority_class)
			VALUES ($1::uuid, $2, $3, 'sca', 'test', 'msg', 'critical', $1::text, 'resolved',
				NOW() - make_interval(hours => $4::int + 1), NOW() - interval '1 hour', 'fixed', 'retest', 'P0')`,
			id.String(), tid.String(), aid.String(), hours); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// 10 h, 20 h and 90 h: mean 40, median 20, p90 = 20 + 0.8 * 70 = 76.
	for _, h := range []int{10, 20, 90} {
		seed(tenant, asset, h)
	}
	seed(other, otherAsset, 1000) // another tenant never enters
	s, err = repo.GetExecutiveSummary(ctx, tenant, nil, nil, 30)
	if err != nil {
		t.Fatal(err)
	}
	near := func(p *float64, want float64) bool { return p != nil && math.Abs(*p-want) < 0.05 }
	if !near(s.MTTRCriticalHrs, 40) || !near(s.MTTRCriticalMedianHrs, 20) || !near(s.MTTRCriticalP90Hrs, 76) || s.MTTRCriticalSample != 3 {
		t.Errorf("executive critical MTTR mean/median/p90/n = %v/%v/%v/%d, want 40/20/76/3",
			s.MTTRCriticalHrs, s.MTTRCriticalMedianHrs, s.MTTRCriticalP90Hrs, s.MTTRCriticalSample)
	}
	if s.MTTRHighHrs != nil {
		t.Errorf("no high finding was fixed: MTTR high = %v, want nil", *s.MTTRHighHrs)
	}
	a, err = repo.GetMTTRAnalytics(ctx, tenant, nil, 90)
	if err != nil {
		t.Fatal(err)
	}
	if !near(a.Overall, 40) || !near(a.OverallMedian, 20) || !near(a.OverallP90, 76) || a.SampleSize != 3 {
		t.Errorf("analytics overall = %+v", a)
	}
	if _, ok := a.BySeverity["high"]; ok || a.BySeverity["critical"] < 39 {
		t.Errorf("by severity = %v, want critical only", a.BySeverity)
	}
	if _, ok := a.ByPriorityClass["P1"]; ok || len(a.ByPriorityClass) != 1 {
		t.Errorf("by priority = %v, want P0 only", a.ByPriorityClass)
	}
}

// velocityOld is the per-week join GetRiskVelocity used before the range-scan
// rewrite, kept as the oracle of the equality test.
func velocityOld(ctx context.Context, db *sql.DB, tenantID shared.ID, weeks int) ([]module.RiskVelocityPoint, error) {
	rows, err := db.QueryContext(ctx, `WITH weeks AS (
		SELECT generate_series(
			date_trunc('week', NOW() - ($2::int || ' weeks')::interval),
			date_trunc('week', NOW()),
			'1 week'::interval
		) AS week_start
	)
	SELECT
		w.week_start,
		COALESCE(SUM(CASE WHEN f.created_at >= w.week_start AND f.created_at < w.week_start + '1 week'::interval THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN f.resolved_at >= w.week_start AND f.resolved_at < w.week_start + '1 week'::interval
			AND `+vulnerability.RemediatedSQL("f")+` THEN 1 ELSE 0 END), 0)
	FROM weeks w
	LEFT JOIN findings f ON f.tenant_id = $1 AND NOT f.branch_only AND f.status NOT IN ('draft', 'in_review')
	GROUP BY w.week_start
	ORDER BY w.week_start`, tenantID.String(), weeks)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []module.RiskVelocityPoint
	for rows.Next() {
		var p module.RiskVelocityPoint
		if err := rows.Scan(&p.Week, &p.NewCount, &p.ResolvedCount); err != nil {
			return nil, err
		}
		p.Velocity = p.NewCount - p.ResolvedCount
		out = append(out, p)
	}
	return out, rows.Err()
}

func TestRiskVelocity_RangeScanEqualsPerWeekJoin_DB(t *testing.T) {
	ctx := context.Background()
	db := openGroupsDB(t)
	repo := NewDashboardRepository(db)
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)
	asset := seedOwnedAsset(ctx, t, db, tenant, nil)
	otherAsset := seedOwnedAsset(ctx, t, db, other, nil)

	// Findings spread over 20 weeks (some outside a 12-week window), created
	// and resolved in the same or in different weeks, plus rows that must not
	// count: drafts, in review, obsolete closures, branch-only, other tenant.
	seed := func(tid, aid shared.ID, createdAgo, resolvedAgo time.Duration, status, reason string, branchOnly bool) {
		t.Helper()
		id := shared.NewID()
		var resolved any
		if resolvedAgo >= 0 {
			resolved = time.Now().Add(-resolvedAgo)
		}
		if _, err := db.ExecContext(ctx, `
			INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status,
				created_at, first_detected_at, resolved_at, closure_reason, branch_only)
			VALUES ($1::uuid, $2, $3, 'sca', 'test', 'msg', 'high', $1::text, $4, $5, $5, $6, NULLIF($7, ''), $8)`,
			id.String(), tid.String(), aid.String(), status, time.Now().Add(-createdAgo), resolved, reason, branchOnly); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	const day = 24 * time.Hour
	for i := 0; i < 20; i++ {
		ago := time.Duration(i)*7*day + time.Duration(i%5)*day
		seed(tenant, asset, ago, -1, "new", "", false)                  // open
		seed(tenant, asset, ago+3*day, ago, "resolved", "fixed", false) // fixed
		if i%3 == 0 {
			seed(tenant, asset, ago+10*day, ago+day, "resolved", "obsolete_asset", false) // not a fix
			seed(tenant, asset, ago, -1, "draft", "", false)
			seed(tenant, asset, ago, -1, "in_review", "", false)
			seed(tenant, asset, ago, -1, "new", "", true)
		}
	}
	seed(other, otherAsset, 2*day, day, "resolved", "fixed", false)

	for _, weeks := range []int{4, 12, 26} {
		want, err := velocityOld(ctx, db, tenant, weeks)
		if err != nil {
			t.Fatal(err)
		}
		got, err := repo.GetRiskVelocity(ctx, tenant, nil, weeks)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(want) || len(got) != weeks+1 {
			t.Fatalf("weeks=%d: %d points, want %d", weeks, len(got), len(want))
		}
		total := 0
		for i := range want {
			if !got[i].Week.Equal(want[i].Week) || got[i].NewCount != want[i].NewCount || got[i].ResolvedCount != want[i].ResolvedCount || got[i].Velocity != want[i].Velocity {
				t.Errorf("weeks=%d point %d: got %+v, old query %+v", weeks, i, got[i], want[i])
			}
			total += got[i].NewCount + got[i].ResolvedCount
		}
		if total == 0 {
			t.Errorf("weeks=%d: the seed produced no counts, the equality is vacuous", weeks)
		}
	}
}
