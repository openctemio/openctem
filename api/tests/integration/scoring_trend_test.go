package integration

import (
	"context"
	"database/sql"
	"testing"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/scoring"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// History is immutable and stamped (docs/architecture/scoring-versions.md):
// a risk snapshot records the scoring versions its numbers came from, a
// later scoring change never rewrites it, and the trend marks the change.
func TestScoringTrend_SnapshotsStampedAndChangesMarked(t *testing.T) {
	fx := newScoringFixture(t)
	ctx := context.Background()
	tid := fx.newTenant(t)
	other := fx.newTenant(t)
	t.Cleanup(func() {
		_, _ = fx.db.Exec(`DELETE FROM risk_snapshots WHERE tenant_id = ANY($1::uuid[])`, "{"+tid.String()+","+other.String()+"}")
	})
	aid := fx.newAsset(t, tid, "github.com/acme/trend")
	fx.newFinding(t, tid, aid, vulnerability.SeverityHigh, "trend-high")
	fx.drain(t, aid)
	risk := assetapp.NewAssetService(fx.assets, logger.NewNop())
	risk.SetRiskQueue(postgres.NewAssetRiskQueueRepository(&postgres.DB{DB: fx.db}), fx.assets)
	risk.SetScoringVersions(fx.scoring)
	if err := risk.UpdateRiskScores(ctx, tid, []shared.ID{aid}); err != nil {
		t.Fatal(err)
	}

	// Yesterday's snapshot was taken with older versions.
	if _, err := fx.db.Exec(`INSERT INTO risk_snapshots (tenant_id, snapshot_date, risk_score_avg, findings_open, p2_open, risk_version, priority_version)
		VALUES ($1, CURRENT_DATE - 1, 42, 1, 1, 1, 1)`, tid.String()); err != nil {
		t.Fatal(err)
	}

	snap := controller.NewRiskSnapshotController(fx.db, logger.NewNop())
	if _, err := snap.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	var rv, pv sql.NullInt64
	if err := fx.db.QueryRow(`SELECT risk_version, priority_version FROM risk_snapshots WHERE tenant_id = $1 AND snapshot_date = CURRENT_DATE`,
		tid.String()).Scan(&rv, &pv); err != nil {
		t.Fatal(err)
	}
	wantRisk, _ := fx.scoring.CurrentVersion(ctx, tid, scoring.KindAssetRisk)
	wantPrio := fx.version(t, tid)
	if !rv.Valid || rv.Int64 != wantRisk || !pv.Valid || pv.Int64 != wantPrio {
		t.Fatalf("today's snapshot versions = %v/%v, want %d/%d", rv, pv, wantRisk, wantPrio)
	}

	// A rule change today and one in another tenant.
	fx.addRule(t, tid, "high", "P0")
	fx.addRule(t, other, "high", "P0")
	fx.drain(t, aid)

	// Yesterday's row is history: untouched.
	var avg float64
	var p2 int
	if err := fx.db.QueryRow(`SELECT risk_score_avg, p2_open, priority_version FROM risk_snapshots WHERE tenant_id = $1 AND snapshot_date = CURRENT_DATE - 1`,
		tid.String()).Scan(&avg, &p2, &pv); err != nil {
		t.Fatal(err)
	}
	if avg != 42 || p2 != 1 || pv.Int64 != 1 {
		t.Fatalf("yesterday's snapshot changed: avg=%v p2=%d priority_version=%v", avg, p2, pv)
	}

	points, err := postgres.NewDashboardRepository(fx.db).GetRiskTrend(ctx, tid, 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 2 {
		t.Fatalf("points = %d, want 2", len(points))
	}
	if len(points[0].ScoringChanges) != 0 && points[0].Date != points[1].Date {
		for _, c := range points[0].ScoringChanges {
			if c.Source == "priority_rules" {
				t.Fatalf("today's rule change marked on yesterday: %+v", c)
			}
		}
	}
	rules := 0
	for _, c := range points[1].ScoringChanges {
		if c.Kind == "finding_priority" && c.Source == "priority_rules" {
			rules++
		}
	}
	if rules != 1 {
		t.Fatalf("today's point carries %d rule changes, want exactly this tenant's 1: %+v", rules, points[1].ScoringChanges)
	}
	if points[1].PriorityVersion == nil || points[0].PriorityVersion == nil || *points[0].PriorityVersion != 1 {
		t.Fatalf("versions not returned: %+v / %+v", points[0].PriorityVersion, points[1].PriorityVersion)
	}
}
