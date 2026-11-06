package postgres

// The EPSS sync's daily history (docs/architecture/vulnerability-page.md,
// "EPSS trend"): one point per feed day, only for CVEs some finding carries,
// rewritten when the sync runs twice, and trimmed to the retention.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/threatintel"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestEPSSHistory_SyncRecordsFindingCVEsOnly_DB(t *testing.T) {
	db := catalogTestDB(t)
	ctx := context.Background()
	withFinding, without := uniqueCVE(), uniqueCVE()+"1"
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = db.ExecContext(bg, `DELETE FROM epss_score_history WHERE cve_id = ANY($1)`, "{"+withFinding+","+without+"}")
		_, _ = db.ExecContext(bg, `DELETE FROM epss_scores WHERE cve_id = ANY($1)`, "{"+withFinding+","+without+"}")
	})

	tenant := seedTestTenant(ctx, t, db)
	asset := seedTestAsset(ctx, t, db, tenant)
	if _, err := db.ExecContext(ctx, `
		INSERT INTO findings (tenant_id, asset_id, cve_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1, $2, $3, 'sca', 'trivy', 'm', 'high', $4, 'new')`,
		tenant.String(), asset.String(), withFinding, "fp-"+shared.NewID().String()); err != nil {
		t.Fatal(err)
	}

	day := time.Date(2099, 3, 10, 0, 0, 0, 0, time.UTC)
	old := day.AddDate(0, 0, -EPSSHistoryRetentionDays)
	kept := day.AddDate(0, 0, -(EPSSHistoryRetentionDays - 1))
	for _, d := range []time.Time{old, kept} {
		if _, err := db.ExecContext(ctx, `INSERT INTO epss_score_history (cve_id, score_date, epss_score) VALUES ($1, $2, 0.01)`, withFinding, d); err != nil {
			t.Fatal(err)
		}
	}

	repo := NewThreatIntelRepository(&DB{DB: db}).EPSS()
	sync := func(score float64) {
		t.Helper()
		if err := repo.UpsertBatch(ctx, []*threatintel.EPSSScore{
			threatintel.NewEPSSScore(withFinding, score, 80, "v2025", day),
			threatintel.NewEPSSScore(without, 0.9, 99, "v2025", day),
		}); err != nil {
			t.Fatal(err)
		}
	}
	sync(0.2)
	sync(0.25) // the same feed day again: the point is rewritten, not doubled

	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM epss_score_history WHERE cve_id = $1`, without).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("a CVE no finding carries has %d history points, want 0", n)
	}

	fr := NewFindingRepository(&DB{DB: db})
	pts, err := fr.EPSSTrend(ctx, withFinding)
	if err != nil {
		t.Fatal(err)
	}
	want := []vulnerability.EPSSPoint{{Date: kept.Format(time.DateOnly), Score: 0.01}, {Date: day.Format(time.DateOnly), Score: 0.25}}
	if len(pts) != len(want) {
		t.Fatalf("trend %v, want %v (the point %d days old must be trimmed)", pts, want, EPSSHistoryRetentionDays)
	}
	for i := range want {
		if pts[i] != want[i] {
			t.Errorf("trend[%d] = %v, want %v", i, pts[i], want[i])
		}
	}
}
