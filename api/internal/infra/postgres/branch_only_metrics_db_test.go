package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Branch-only findings are not exposure (docs/architecture/branch-only-findings.md):
// dashboards, executive and MTTR metrics, risk inputs, asset and group counts
// and the threat model leave them out. Each assertion compares a tenant with
// one counting and one branch-only finding against the same tenant before
// the branch-only one exists.
func TestBranchOnly_MetricsLeaveThemOut(t *testing.T) {
	ctx := context.Background()
	f := newBranchOnlyFixture(ctx, t)
	dash := NewDashboardRepository(f.db)
	findings := NewFindingRepository(&DB{DB: f.db})

	counting, _ := f.finding(ctx, t, f.tenant, f.repo, &f.main)
	branchOnly, _ := f.finding(ctx, t, f.tenant, f.repo, &f.feature)
	if !f.branchOnly(ctx, t, branchOnly) || f.branchOnly(ctx, t, counting) {
		t.Fatal("fixture: want one counting and one branch-only finding")
	}

	stats, err := dash.GetFindingStats(ctx, f.tenant)
	if err != nil || stats.Total != 1 {
		t.Fatalf("GetFindingStats total = %d (%v), want 1", stats.Total, err)
	}
	all, err := dash.GetAllStats(ctx, f.tenant, nil)
	if err != nil || all.Findings.Total != 1 {
		t.Fatalf("GetAllStats findings = %+v (%v), want 1", all, err)
	}
	filtered, err := dash.GetFilteredFindingStats(ctx, []string{f.tenant.String()})
	if err != nil || filtered.Total != 1 {
		t.Fatalf("GetFilteredFindingStats total = %d (%v), want 1", filtered.Total, err)
	}
	exec, err := dash.GetExecutiveSummary(ctx, f.tenant, 30)
	if err != nil || exec.FindingsTotal != 1 || exec.FindingsNew != 1 {
		t.Fatalf("executive summary open %d new %d (%v), want 1 and 1", exec.FindingsTotal, exec.FindingsNew, err)
	}
	for _, tr := range exec.TopRisks {
		if tr.FindingID == branchOnly.String() {
			t.Fatal("a branch-only finding is a top risk")
		}
	}
	activity, err := dash.GetRecentActivity(ctx, f.tenant, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range activity {
		if a.RefID == branchOnly.String() {
			t.Fatal("a branch-only finding is in recent activity")
		}
	}

	facts, err := findings.ListThreatFindings(ctx, f.tenant, []shared.ID{f.repo})
	if err != nil || len(facts) != 1 {
		t.Fatalf("threat findings = %d (%v), want 1", len(facts), err)
	}

	a, err := NewAssetRepository(&DB{DB: f.db}).GetByID(ctx, f.tenant, f.repo)
	if err != nil || a.FindingCount() != 1 {
		t.Fatalf("asset finding count = %v (%v), want 1", a, err)
	}

	// Promoted: it counts everywhere.
	f.exec(ctx, t, `UPDATE repository_branches SET is_protected = TRUE WHERE id = $1`, f.feature.String())
	if stats, err := dash.GetFindingStats(ctx, f.tenant); err != nil || stats.Total != 2 {
		t.Fatalf("after promotion total = %d (%v), want 2", stats.Total, err)
	}
}
