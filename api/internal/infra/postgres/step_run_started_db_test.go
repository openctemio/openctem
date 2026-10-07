package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A sensor starting a step's command marks the step run running, with
// started_at and the sensor. Before this nothing wrote it: every step went
// from queued straight to completed with started_at empty. A start that
// arrives after the step finished must not reopen it.
func TestStepRunAssignSensor_MarksStartedOnlyFromPendingOrQueued(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	repo := NewStepRunRepository(&DB{DB: db})
	tenantID := seedTestTenant(ctx, t, db)
	templateID := seedTimeoutTemplate(ctx, t, db, tenantID)
	runID := seedRun(ctx, t, db, tenantID, templateID, nil, "running", 0)

	sensorID := shared.NewID()
	mustExec(t, db, `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status)
		VALUES ($1, $2, $3, $4, 'p', 'active')`,
		sensorID.String(), tenantID.String(), "start-probe-"+sensorID.String(), "h-"+sensorID.String())

	seedStep := func(key, status string) (stepRunID, commandID shared.ID) {
		stepID, stepRunID, commandID := shared.NewID(), shared.NewID(), shared.NewID()
		mustExec(t, db, `INSERT INTO scan_workflow_steps (id, scan_workflow_id, step_key, name, step_order)
			VALUES ($1, $2, $3, $3, 1)`, stepID.String(), templateID.String(), key)
		mustExec(t, db, `INSERT INTO commands (id, tenant_id, sensor_id, type, status, payload)
			VALUES ($1, $2, $3, 'scan', 'running', '{}'::jsonb)`,
			commandID.String(), tenantID.String(), sensorID.String())
		mustExec(t, db, `INSERT INTO scan_run_steps (id, scan_run_id, step_id, step_key, step_order, status)
			VALUES ($1, $2, $3, $4, 1, $5)`,
			stepRunID.String(), runID.String(), stepID.String(), key, status)
		return stepRunID, commandID
	}

	type row struct {
		status    string
		started   bool
		sensorSet bool
	}
	read := func(id shared.ID) row {
		var r row
		var sensor sql.NullString
		var started sql.NullTime
		if err := db.QueryRowContext(ctx, `SELECT status, started_at, sensor_id FROM scan_run_steps WHERE id = $1`,
			id.String()).Scan(&r.status, &started, &sensor); err != nil {
			t.Fatalf("read step run: %v", err)
		}
		r.started, r.sensorSet = started.Valid, sensor.Valid
		return r
	}

	for _, from := range []string{"pending", "queued"} {
		id, cmd := seedStep("start-"+from, from)
		if err := repo.AssignSensor(ctx, id, sensorID, cmd); err != nil {
			t.Fatalf("AssignSensor(%s): %v", from, err)
		}
		if got := read(id); got != (row{"running", true, true}) {
			t.Errorf("from %s: got %+v, want running with started_at and sensor", from, got)
		}
	}

	for _, from := range []string{"completed", "failed", "canceled"} {
		id, cmd := seedStep("late-"+from, from)
		if err := repo.AssignSensor(ctx, id, sensorID, cmd); err != nil {
			t.Fatalf("AssignSensor(%s): %v", from, err)
		}
		if got := read(id); got.status != from || got.started {
			t.Errorf("a late start reopened a %s step run: %+v", from, got)
		}
	}
}
