package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A run whose work waits while another task of the tenant scans its hosts
// is not "unclaimed" (research/130): the quick scan of the live incident
// waited behind an httpx chunk, and after an hour would have failed with
// NO_SENSOR, a code that is never retried. Once its hosts are free and still
// nobody takes it, it is. Requires DATABASE_URL.
func TestAbortUnclaimedRuns_HostWaitIsNotUnclaimed(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewCommandRepository(&DB{DB: db})
	runs := NewScanRunRepository(&DB{DB: db})
	tenant, other := seedTestTenant(ctx, t, db), seedTestTenant(ctx, t, db)
	sensor := seedZoneSensor(ctx, t, db, &tenant, "s", zoneSensorOpts{tools: []string{"httpx"}})
	theirs := seedZoneSensor(ctx, t, db, &other, "o", zoneSensorOpts{tools: []string{"httpx"}})
	host := "h-" + shared.NewID().String() + ".example.test"

	stepRun := seedChunkStepRun(ctx, t, db, tenant)
	var runID string
	if err := db.QueryRowContext(ctx, `SELECT scan_run_id FROM scan_run_steps WHERE id = $1`, stepRun.String()).Scan(&runID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE scan_runs SET status = 'running', started_at = NOW() - interval '5 hours' WHERE id = $1`, runID); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"scan_run_id": runID, "scanner": "nuclei", "targets": []string{"https://" + host + "/"}})
	waiting, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, payload)
	if err != nil {
		t.Fatal(err)
	}
	waiting.HostKeys = []string{host}
	if err := repo.Create(ctx, waiting); err != nil {
		t.Fatal(err)
	}

	reaped := func() bool {
		t.Helper()
		got, err := runs.AbortUnclaimedRunsReporting(ctx, time.Minute, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range got {
			if r.RunID.String() == runID {
				return true
			}
		}
		return false
	}

	// Another tenant's task on the same host does not count: its run is
	// unclaimed only if nothing of its own tenant holds the host. Here the
	// tenant's own task holds it.
	holder := createHostChunk(ctx, t, repo, tenant, host)
	if ok, err := repo.ClaimForSensor(ctx, tenant, holder, sensor.String()); err != nil || !ok {
		t.Fatalf("holder not claimed: %v %v", ok, err)
	}
	foreign := createHostChunk(ctx, t, repo, other, host)
	if ok, err := repo.ClaimForSensor(ctx, other, foreign, theirs.String()); err != nil || !ok {
		t.Fatalf("foreign holder not claimed: %v %v", ok, err)
	}
	if reaped() {
		t.Fatal("a run waiting on its hosts was reaped as unclaimed")
	}

	// The tenant's holder ends; only the other tenant's task is left on the
	// host, which never holds this tenant back: the run is unclaimed now.
	if _, err := db.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE id = $1`, holder.String()); err != nil {
		t.Fatal(err)
	}
	if !reaped() {
		t.Fatal("a run nobody took once its hosts were free was not reaped")
	}
	var status string
	if err := db.QueryRowContext(ctx, `SELECT status FROM commands WHERE id = $1`, waiting.ID.String()).Scan(&status); err != nil || status != "failed" {
		t.Fatalf("waiting command status %q (%v)", status, err)
	}
}
