package postgres

import (
	"context"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The findings page reads its overview cards and its state tab counts from
// ONE stats response (research/81): by_state for the tabs, open_by_severity,
// kev_open, sla_breached and awaiting_verification for the cards. Each card
// that says "open" must count exactly the Open tab's rows, so these numbers
// use the Open lens predicate. Skipped unless DATABASE_URL is set.

func TestGetStats_OverviewAgreesWithTheOpenTab(t *testing.T) {
	db := openStatsTestDB(t)
	ctx := context.Background()

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

	for _, p := range []statsProbe{
		{source: "sca", severity: "critical", status: "new", kev: true, sla: "overdue"},
		{source: "sca", severity: "critical", status: "confirmed"},
		{source: "sca", severity: "high", status: "fix_applied"},
		{source: "sca", severity: "high", status: "not_observed", sla: "exceeded"},
		{source: "sca", severity: "none", status: "new"},
		// Closed: never open.
		{source: "sca", severity: "critical", status: "resolved", kev: true, sla: "overdue"},
		{source: "sca", severity: "high", status: "false_positive"},
		// Pentest drafts are not published findings: not in the Open tab,
		// so not in any open card either.
		{source: "pentest", severity: "critical", status: "draft", kev: true, sla: "overdue"},
		{source: "pentest", severity: "high", status: "in_review"},
	} {
		seedStatsFinding(ctx, t, db, tenantID, assetID, p)
	}
	// Another tenant: never counted.
	other := seedTestTenant(ctx, t, db)
	seedStatsFinding(ctx, t, db, other, seedTestAsset(ctx, t, db, other),
		statsProbe{source: "sca", severity: "critical", status: "fix_applied", kev: true, sla: "overdue"})

	repo := NewFindingRepository(&DB{DB: db})
	stats, err := repo.GetStats(ctx, tenantID, nil, vulnerability.FindingStatsFilter{})
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}

	open := stats.ByState[vulnerability.FindingLensOpen]
	var openSum int64
	for _, n := range stats.OpenBySeverity {
		openSum += n
	}
	checks := []struct {
		name      string
		got, want int64
	}{
		{"by_state.open", open, 5},
		{"by_state.all", stats.ByState[vulnerability.FindingLensAll], 9},
		{"sum(open_by_severity) == by_state.open", openSum, open},
		{"open_by_severity.critical", stats.OpenBySeverity[vulnerability.SeverityCritical], 2},
		{"open_by_severity.high", stats.OpenBySeverity[vulnerability.SeverityHigh], 2},
		{"open_by_severity.info (with none)", stats.OpenBySeverity[vulnerability.SeverityInfo], 1},
		{"kev_open (draft excluded)", stats.KevOpen, 1},
		{"sla_breached (draft excluded)", stats.SLABreached, 2},
		{"awaiting_verification", stats.AwaitingVerification, 1},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// A member restricted by data scope sees overview numbers over their assets
// only, the same rows as their Open tab.
func TestGetStats_OverviewRespectsDataScope(t *testing.T) {
	db := openStatsTestDB(t)
	ctx := context.Background()

	tenantID := seedTestTenant(ctx, t, db)
	visible := seedTestAsset(ctx, t, db, tenantID)
	hidden := seedTestAsset(ctx, t, db, tenantID)
	seedStatsFinding(ctx, t, db, tenantID, visible, statsProbe{source: "sca", severity: "high", status: "new"})
	seedStatsFinding(ctx, t, db, tenantID, hidden, statsProbe{source: "sca", severity: "critical", status: "new", kev: true, sla: "overdue"})
	seedStatsFinding(ctx, t, db, tenantID, hidden, statsProbe{source: "sca", severity: "critical", status: "fix_applied"})

	userID := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`,
		userID.String(), userID.String()+"@stats-overview.test", "stats-overview"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, userID.String())
	})
	if _, err := db.ExecContext(ctx,
		`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id) VALUES ($1, $2, $3)`,
		userID.String(), tenantID.String(), visible.String()); err != nil {
		t.Fatalf("seed user_accessible_assets: %v", err)
	}

	repo := NewFindingRepository(&DB{DB: db})
	scoped, err := repo.GetStats(ctx, tenantID, &userID, vulnerability.FindingStatsFilter{})
	if err != nil {
		t.Fatalf("GetStats (scoped): %v", err)
	}
	if scoped.OpenBySeverity[vulnerability.SeverityCritical] != 0 || scoped.KevOpen != 0 ||
		scoped.SLABreached != 0 || scoped.AwaitingVerification != 0 {
		t.Errorf("hidden asset leaked into the overview: critical=%d kev=%d sla=%d awaiting=%d",
			scoped.OpenBySeverity[vulnerability.SeverityCritical], scoped.KevOpen,
			scoped.SLABreached, scoped.AwaitingVerification)
	}
	if scoped.OpenBySeverity[vulnerability.SeverityHigh] != 1 || scoped.ByState[vulnerability.FindingLensOpen] != 1 {
		t.Errorf("scoped open: high=%d open=%d, want 1/1",
			scoped.OpenBySeverity[vulnerability.SeverityHigh], scoped.ByState[vulnerability.FindingLensOpen])
	}
}
