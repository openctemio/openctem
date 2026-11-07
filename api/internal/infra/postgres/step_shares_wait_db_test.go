package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The run map's wait breakdown: of a step's queued chunks, those whose hosts
// another task of the tenant holds and, of the rest, those a sensor's local
// policy refused. Another tenant's task on the same hosts holds nothing and
// is never counted. Requires DATABASE_URL.
func TestStepSensorShares_WaitBreakdown(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant, other := seedTestTenant(ctx, t, sqlDB), seedTestTenant(ctx, t, sqlDB)
	busy := seedZoneSensor(ctx, t, sqlDB, &tenant, "busy", zoneSensorOpts{tools: []string{"nuclei"}})
	refuser := seedZoneSensor(ctx, t, sqlDB, &tenant, "refuser", zoneSensorOpts{tools: []string{"nuclei"}})
	o := seedZoneSensor(ctx, t, sqlDB, &other, "o", zoneSensorOpts{tools: []string{"nuclei"}})
	stepRun := seedChunkStepRun(ctx, t, sqlDB, tenant)
	var runIDStr string
	if err := sqlDB.QueryRowContext(ctx, `SELECT scan_run_id FROM scan_run_steps WHERE id = $1`, stepRun.String()).Scan(&runIDStr); err != nil {
		t.Fatal(err)
	}
	runID, _ := shared.IDFromString(runIDStr)

	runningScan(ctx, t, cmds, tenant, busy, "192.0.2.1")
	runningScan(ctx, t, cmds, other, o, "192.0.2.9")                // another tenant: holds nothing here
	stepScan(ctx, t, cmds, tenant, stepRun, "192.0.2.1")            // waits for its host
	refused := stepScan(ctx, t, cmds, tenant, stepRun, "192.0.2.5") // refused by one sensor
	stepScan(ctx, t, cmds, tenant, stepRun, "192.0.2.9")            // free (other tenant's hold)
	if _, err := sqlDB.ExecContext(ctx, `UPDATE commands SET refused_by = ARRAY[$2::uuid] WHERE id = $1`,
		refused.String(), refuser.String()); err != nil {
		t.Fatal(err)
	}

	shares, err := cmds.StepSensorShares(ctx, tenant, runID)
	if err != nil {
		t.Fatal(err)
	}
	var queued, hosts, ref int
	for _, sh := range shares {
		queued += sh.Queued
		hosts += sh.QueuedHostsBusy
		ref += sh.QueuedRefused
	}
	if queued != 3 || hosts != 1 || ref != 1 {
		t.Fatalf("queued %d hosts busy %d refused %d, want 3 1 1", queued, hosts, ref)
	}
	if theirs, err := cmds.StepSensorShares(ctx, other, runID); err != nil || len(theirs) != 0 {
		t.Fatalf("another tenant read %d shares of the run (err %v)", len(theirs), err)
	}
}
