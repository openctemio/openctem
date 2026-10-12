package integration

import (
	"context"
	"database/sql"
	"testing"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A sensor starting a step's command is what the command handlers report with
// OnStepStarted (v1 /start and the v2 start transition). Before it existed no
// code marked a step run running: a run showed every step "queued" while the
// sensor worked on it, and started_at stayed empty after the step finished,
// so no step had a duration.
func TestScanLoop_StartedCommandMarksTheStepRunning(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	svc := newTriggerService(db)
	pipeSvc := newScanRunService(db)

	tenantID := seedLifecycleTenant(ctx, t, db)
	scanID := seedLifecycleScan(ctx, t, db, tenantID)
	sensorID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status)
		 VALUES ($1, $2, $3, $4, 'p', 'active')`,
		sensorID.String(), tenantID.String(), "start-"+sensorID.String(), "h-"+sensorID.String()); err != nil {
		t.Fatalf("seed sensor: %v", err)
	}

	run, err := svc.TriggerScan(ctx, scansvc.TriggerScanExecInput{TenantID: tenantID.String(), ScanID: scanID.String()})
	if err != nil {
		t.Fatalf("TriggerScan: %v", err)
	}
	p := routingFromCommand(ctx, t, db, tenantID.String())
	var commandID string
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM commands WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 1`,
		tenantID.String()).Scan(&commandID); err != nil {
		t.Fatalf("read command: %v", err)
	}

	step := func() (status string, started sql.NullTime, sensor sql.NullString) {
		t.Helper()
		if err := db.QueryRowContext(ctx,
			`SELECT status, started_at, sensor_id FROM scan_run_steps WHERE scan_run_id = $1 AND step_key = $2`,
			run.ID.String(), p.StepKey).Scan(&status, &started, &sensor); err != nil {
			t.Fatalf("read step run: %v", err)
		}
		return status, started, sensor
	}

	if status, started, _ := step(); status == "running" || started.Valid {
		t.Fatalf("precondition: the step run is %q (started_at set: %v) before any sensor started it", status, started.Valid)
	}

	if err := pipeSvc.OnStepStarted(ctx, p.ScanRunID, p.StepKey, sensorID, shared.MustIDFromString(commandID)); err != nil {
		t.Fatalf("OnStepStarted: %v", err)
	}
	status, started, sensor := step()
	if status != "running" || !started.Valid || sensor.String != sensorID.String() {
		t.Fatalf("after the start: status=%q started_at set=%v sensor=%q, want running, set, %s",
			status, started.Valid, sensor.String, sensorID)
	}

	if err := pipeSvc.OnStepCompleted(ctx, p.ScanRunID, p.StepKey, 0, nil); err != nil {
		t.Fatalf("OnStepCompleted: %v", err)
	}
	// A start replayed after the result must not reopen the step.
	if err := pipeSvc.OnStepStarted(ctx, p.ScanRunID, p.StepKey, sensorID, shared.MustIDFromString(commandID)); err != nil {
		t.Fatalf("late OnStepStarted: %v", err)
	}
	status, after, _ := step()
	if status != "completed" || !after.Valid || !after.Time.Equal(started.Time) {
		t.Errorf("after completion: status=%q started_at=%v (was %v), want completed with the same started_at",
			status, after.Time, started.Time)
	}
}
