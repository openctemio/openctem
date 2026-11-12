package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// A coverage run whose every command a sensor refused (its local policy,
// its egress) or never picked up, and that then ended at its deadline, is a
// run no sensor took: the capability's hold counts it and backs off, instead
// of the planner queueing the same work again the moment it ends (research
// 511, mechanism C). A run a sensor did hold, or one still open, is not.
// Requires DATABASE_URL.
func TestQueuedRuns_RunEveryoneRefusedCountsAsUnclaimed(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	repo := NewAssetCoverageRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	scanID := seedRetryScan(ctx, t, db, tenantID, 0)

	queue := func(runID shared.ID) {
		t.Helper()
		asset := seedTestAsset(ctx, t, db, tenantID)
		if _, err := db.ExecContext(ctx, `INSERT INTO asset_coverage (tenant_id, asset_id, capability, state, queued_at, last_run_id)
			VALUES ($1, $2, 'probe.http', 'queued', now(), $3)`, tenantID.String(), asset.String(), runID.String()); err != nil {
			t.Fatal(err)
		}
	}
	ended := func(status string) shared.ID {
		t.Helper()
		id := seedActiveRun(ctx, t, db, tenantID, scanID, "system", 3*time.Hour)
		if _, err := db.ExecContext(ctx, `UPDATE scan_runs SET status = $2, completed_at = now() WHERE id = $1`, id.String(), status); err != nil {
			t.Fatal(err)
		}
		queue(id)
		return id
	}

	// Refused by the sensor and handed back, then closed at the deadline.
	refused := ended("timeout")
	cmd := seedRunCommand(ctx, t, db, tenantID, refused, "failed", false, 1)
	if _, err := db.ExecContext(ctx, `UPDATE commands SET refused_by = ARRAY[gen_random_uuid()] WHERE id = $1`, cmd.String()); err != nil {
		t.Fatal(err)
	}
	// A sensor held and ran it.
	held := ended("timeout")
	seedRunCommand(ctx, t, db, tenantID, held, "completed", true, 1)
	// Still open: not decided yet.
	open := seedActiveRun(ctx, t, db, tenantID, scanID, "system", time.Minute)
	queue(open)
	seedRunCommand(ctx, t, db, tenantID, open, "pending", false, 1)

	runs, err := repo.QueuedRuns(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[shared.ID]bool{}
	for _, rs := range runs {
		got[rs.RunID] = rs.NoSensor
	}
	if !got[refused] {
		t.Fatal("a run every sensor refused was not counted as unclaimed: coverage would queue it again at once")
	}
	if got[held] {
		t.Fatal("a run a sensor held was counted as unclaimed")
	}
	if got[open] {
		t.Fatal("an open run was counted as unclaimed")
	}

	// Another organization's commands naming the run change nothing.
	other := seedTestTenant(ctx, t, db)
	seedRunCommand(ctx, t, db, other, held, "pending", false, 0)
	if runs, err = repo.QueuedRuns(ctx, tenantID); err != nil {
		t.Fatal(err)
	}
	for _, rs := range runs {
		if rs.RunID == held && rs.NoSensor {
			t.Fatal("another organization's command changed this organization's run")
		}
	}
}
