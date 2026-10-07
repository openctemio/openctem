package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The Exposures type pages (vulnerabilities, secrets, code, misconfigurations)
// read their counts from /findings/stats?sources=… instead of walking the whole
// list. These tests prove the sources filter narrows EVERY number the query
// returns, and that it composes with tenant isolation, data scope and asset_id
// rather than replacing them. Skipped unless DATABASE_URL is set (CI provisions
// Postgres).

type statsProbe struct {
	source, severity, status, sla string
	kev                           bool
	epss                          float64
}

func openStatsTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB execution check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db
}

func seedStatsFinding(ctx context.Context, t *testing.T, db *sql.DB, tenantID, assetID shared.ID, p statsProbe) {
	t.Helper()
	id := shared.NewID()
	var epss any
	if p.epss > 0 {
		epss = p.epss
	}
	sla := p.sla
	if sla == "" {
		sla = "on_track"
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO findings
		   (id, tenant_id, asset_id, source, tool_name, message, severity, status,
		    fingerprint, sla_status, is_in_kev, epss_score)
		 VALUES ($1, $2, $3, $4, 'stats-test', 'stats sources probe', $5, $6, $7, $8, $9, $10)`,
		id.String(), tenantID.String(), assetID.String(), p.source, p.severity, p.status,
		"stats-fp-"+id.String(), sla, p.kev, epss)
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
}

func TestGetStats_SourcesFilterScopesEveryNumber(t *testing.T) {
	db := openStatsTestDB(t)
	ctx := context.Background()

	tenantID := seedTestTenant(ctx, t, db)
	assetID := seedTestAsset(ctx, t, db, tenantID)

	// In scope for sources=sca,sast.
	in := []statsProbe{
		{source: "sca", severity: "critical", status: "new", kev: true, epss: 0.5, sla: "overdue"},
		{source: "sca", severity: "high", status: "confirmed", epss: 0.2},
		{source: "sast", severity: "medium", status: "in_progress", sla: "exceeded"},
		{source: "sast", severity: "low", status: "resolved", kev: true, epss: 0.9, sla: "overdue"}, // closed: excluded from *_open / sla_breached
		{source: "sca", severity: "info", status: "false_positive"},
	}
	// Out of scope: every one of these would move a number if the filter leaked.
	out := []statsProbe{
		{source: "secret", severity: "critical", status: "new", kev: true, epss: 0.8, sla: "exceeded"},
		{source: "iac", severity: "high", status: "resolved"},
		{source: "dast", severity: "medium", status: "confirmed", kev: true, epss: 0.3, sla: "overdue"},
	}
	for _, p := range append(append([]statsProbe{}, in...), out...) {
		seedStatsFinding(ctx, t, db, tenantID, assetID, p)
	}

	// Another tenant with matching-source findings must never be counted.
	otherTenant := seedTestTenant(ctx, t, db)
	otherAsset := seedTestAsset(ctx, t, db, otherTenant)
	seedStatsFinding(ctx, t, db, otherTenant, otherAsset, statsProbe{source: "sca", severity: "critical", status: "new", kev: true, epss: 0.9, sla: "overdue"})

	repo := NewFindingRepository(&DB{DB: db})

	stats, err := repo.GetStats(ctx, tenantID, nil, vulnerability.FindingStatsFilter{
		Sources: []vulnerability.FindingSource{vulnerability.FindingSourceSCA, vulnerability.FindingSourceSAST},
	})
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}

	checks := []struct {
		name      string
		got, want int64
	}{
		{"total", stats.Total, 5},
		{"by_severity.critical", stats.BySeverity[vulnerability.SeverityCritical], 1},
		{"by_severity.high", stats.BySeverity[vulnerability.SeverityHigh], 1},
		{"by_severity.medium", stats.BySeverity[vulnerability.SeverityMedium], 1},
		{"by_severity.low", stats.BySeverity[vulnerability.SeverityLow], 1},
		{"by_severity.info", stats.BySeverity[vulnerability.SeverityInfo], 1},
		{"by_severity.none (folded into info)", stats.BySeverity[vulnerability.SeverityNone], 0},
		{"by_status.new", stats.ByStatus[vulnerability.FindingStatusNew], 1},
		{"by_status.confirmed", stats.ByStatus[vulnerability.FindingStatusConfirmed], 1},
		{"by_status.in_progress", stats.ByStatus[vulnerability.FindingStatusInProgress], 1},
		{"by_status.resolved", stats.ByStatus[vulnerability.FindingStatusResolved], 1},
		{"by_status.false_positive", stats.ByStatus[vulnerability.FindingStatusFalsePositive], 1},
		{"by_source.sca", stats.BySource[vulnerability.FindingSourceSCA], 3},
		{"by_source.sast", stats.BySource[vulnerability.FindingSourceSAST], 2},
		{"by_source.secret", stats.BySource[vulnerability.FindingSourceSecret], 0},
		{"by_source.iac", stats.BySource[vulnerability.FindingSourceIaC], 0},
		{"by_source.dast", stats.BySource[vulnerability.FindingSourceDAST], 0},
		{"open_count", stats.OpenCount, 3},
		{"resolved_count", stats.ResolvedCount, 1},
		{"kev_open", stats.KevOpen, 1},
		{"epss_high_open", stats.EpssHighOpen, 2},
		{"sla_breached", stats.SLABreached, 2},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}

	// No sources ⇒ whole tenant (unchanged behavior), still not the other tenant.
	all, err := repo.GetStats(ctx, tenantID, nil, vulnerability.FindingStatsFilter{})
	if err != nil {
		t.Fatalf("GetStats (unfiltered): %v", err)
	}
	if all.Total != int64(len(in)+len(out)) {
		t.Errorf("unfiltered total = %d, want %d", all.Total, len(in)+len(out))
	}
	if all.KevOpen != 3 {
		t.Errorf("unfiltered kev_open = %d, want 3", all.KevOpen)
	}
}

// sources composes with asset_id and with the data-scope narrowing: a scoped
// user only sees their assets' findings, and sources narrows that further.
func TestGetStats_SourcesComposesWithAssetAndDataScope(t *testing.T) {
	db := openStatsTestDB(t)
	ctx := context.Background()

	tenantID := seedTestTenant(ctx, t, db)
	visible := seedTestAsset(ctx, t, db, tenantID)
	hidden := seedTestAsset(ctx, t, db, tenantID)

	seedStatsFinding(ctx, t, db, tenantID, visible, statsProbe{source: "secret", severity: "high", status: "new"})
	seedStatsFinding(ctx, t, db, tenantID, visible, statsProbe{source: "sca", severity: "high", status: "new"})
	seedStatsFinding(ctx, t, db, tenantID, hidden, statsProbe{source: "secret", severity: "critical", status: "new"})

	userID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO users (id, email, name) VALUES ($1, $2, $3)`,
		userID.String(), userID.String()+"@stats-scope.test", "stats-scope"); err != nil {
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
	secretOnly := []vulnerability.FindingSource{vulnerability.FindingSourceSecret}

	scoped, err := repo.GetStats(ctx, tenantID, &userID, vulnerability.FindingStatsFilter{Sources: secretOnly})
	if err != nil {
		t.Fatalf("GetStats (scoped): %v", err)
	}
	if scoped.Total != 1 || scoped.BySeverity[vulnerability.SeverityCritical] != 0 {
		t.Errorf("data scope + sources: total=%d critical=%d, want total=1 critical=0 (hidden asset leaked?)",
			scoped.Total, scoped.BySeverity[vulnerability.SeverityCritical])
	}

	byAsset, err := repo.GetStats(ctx, tenantID, nil, vulnerability.FindingStatsFilter{AssetID: &hidden, Sources: secretOnly})
	if err != nil {
		t.Fatalf("GetStats (asset): %v", err)
	}
	if byAsset.Total != 1 || byAsset.BySeverity[vulnerability.SeverityCritical] != 1 {
		t.Errorf("asset_id + sources: total=%d critical=%d, want 1/1",
			byAsset.Total, byAsset.BySeverity[vulnerability.SeverityCritical])
	}
}
