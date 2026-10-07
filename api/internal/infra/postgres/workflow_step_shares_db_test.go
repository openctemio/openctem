package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The run overlay reads how a step's chunks are spread: per tenant sensor
// with its name, queued chunks under no sensor, platform jobs without the
// platform sensor; another tenant reads nothing of the run.
// Requires DATABASE_URL (CI applies every migration first).
func TestWorkflowStepChunks_SensorShares(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	stepRun := seedChunkStepRun(ctx, t, sqlDB, tenant)
	var runIDStr string
	if err := sqlDB.QueryRowContext(ctx, `SELECT scan_run_id FROM scan_run_steps WHERE id = $1`, stepRun.String()).Scan(&runIDStr); err != nil {
		t.Fatal(err)
	}
	runID, _ := shared.IDFromString(runIDStr)

	a := seedZoneSensor(ctx, t, sqlDB, &tenant, "edge", zoneSensorOpts{tools: []string{"httpx"}})
	chunks := createStepChunks(ctx, t, cmds, tenant, stepRun, nil, 4, 10)
	for _, id := range chunks[:2] {
		if ok, err := cmds.ClaimForSensor(ctx, tenant, id, a.String()); err != nil || !ok {
			t.Fatalf("claim: %v %v", ok, err)
		}
	}
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET status = 'completed' WHERE id = $1`, chunks[1].String()); err != nil {
		t.Fatal(err)
	}
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET is_platform_job = TRUE WHERE id = $1`, chunks[3].String()); err != nil {
		t.Fatal(err)
	}

	shares, err := cmds.StepSensorShares(ctx, tenant, runID)
	if err != nil {
		t.Fatal(err)
	}
	var onA, queued, platform *command.StepSensorShare
	for i := range shares {
		sh := &shares[i]
		switch {
		case sh.Platform:
			platform = sh
		case sh.SensorID != nil && *sh.SensorID == a:
			onA = sh
		case sh.SensorID == nil:
			queued = sh
		}
		if sh.StepKey != "probe" {
			t.Errorf("share of step %q", sh.StepKey)
		}
	}
	if onA == nil || onA.Total != 2 || onA.Running != 1 || onA.Completed != 1 || onA.SensorName == "" {
		t.Fatalf("sensor share = %+v", onA)
	}
	if queued == nil || queued.Total != 1 || queued.Queued != 1 {
		t.Fatalf("queued share = %+v", queued)
	}
	if platform == nil || platform.SensorID != nil || platform.SensorName != "" || platform.Total != 1 {
		t.Fatalf("platform share = %+v", platform)
	}
	if theirs, err := cmds.StepSensorShares(ctx, other, runID); err != nil || len(theirs) != 0 {
		t.Fatalf("another tenant read %d shares of the run (err %v)", len(theirs), err)
	}
}
