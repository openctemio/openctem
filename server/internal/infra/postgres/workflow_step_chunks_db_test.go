package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Workflow step chunks (research/49 W27) against a real schema: a step's
// chunks are unpinned commands under one step run, so every sensor of the
// tenant that has the tool takes a share; a sensor without the tool, a
// sensor of another tenant and a sensor outside the run's zone take none;
// a dead sensor's chunk goes back to the pool; the step sees every chunk.
// Requires DATABASE_URL (CI applies every migration first).

func seedChunkStepRun(ctx context.Context, t *testing.T, db *sql.DB, tenant shared.ID) shared.ID {
	t.Helper()
	var runID, stepID, stepRunID string
	if err := db.QueryRowContext(ctx,
		`INSERT INTO scan_runs (scan_workflow_id, tenant_id, status, trigger_type)
		 VALUES ('00000000-0000-0000-0000-000000000001', $1, 'running', 'manual') RETURNING id`,
		tenant.String()).Scan(&runID); err != nil {
		t.Skipf("seed run (quick-scan template missing?): %v", err)
	}
	if err := db.QueryRowContext(ctx,
		`SELECT id FROM scan_workflow_steps WHERE scan_workflow_id = '00000000-0000-0000-0000-000000000001' LIMIT 1`).Scan(&stepID); err != nil {
		t.Skipf("quick-scan template has no step: %v", err)
	}
	if err := db.QueryRowContext(ctx,
		`INSERT INTO scan_run_steps (scan_run_id, step_id, step_key, step_order) VALUES ($1, $2, 'probe', 1) RETURNING id`,
		runID, stepID).Scan(&stepRunID); err != nil {
		t.Fatal(err)
	}
	id, _ := shared.IDFromString(stepRunID)
	return id
}

// createStepChunks creates n chunk commands of chunkSize targets each, in the
// shape the step dispatcher writes: unpinned, the tool in scanner and
// preferred_tool, the step run named, optionally stamped with a zone.
func createStepChunks(ctx context.Context, t *testing.T, repo *CommandRepository, tenant, stepRun shared.ID, zone *shared.ID, n, chunkSize int) []shared.ID {
	t.Helper()
	ids := make([]shared.ID, 0, n)
	for i := 0; i < n; i++ {
		targets := make([]string, chunkSize)
		for j := range targets {
			targets[j] = fmt.Sprintf("h%04d.example.test", i*chunkSize+j)
		}
		raw, _ := json.Marshal(map[string]any{
			"scanner": "httpx", "preferred_tool": "httpx", "step_key": "probe",
			"scan_run_step_id": stepRun.String(), "targets": targets,
		})
		cmd, err := command.NewCommand(tenant, command.CommandTypeScan, command.CommandPriorityNormal, raw)
		if err != nil {
			t.Fatal(err)
		}
		cmd.SetStepRunID(stepRun)
		if zone != nil {
			cmd.SetScanZone(*zone)
		}
		if err := repo.Create(ctx, cmd); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, cmd.ID)
	}
	return ids
}

// claimOne polls as sensor and claims the first command offered; false when
// nothing is offered.
func claimOne(ctx context.Context, t *testing.T, repo *CommandRepository, tenant, sensor shared.ID) (shared.ID, bool) {
	t.Helper()
	offered, err := repo.GetPendingForSensor(ctx, tenant, &sensor, nil, 1)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	for _, c := range offered {
		ok, err := repo.ClaimForSensor(ctx, tenant, c.ID, sensor.String())
		if err != nil {
			t.Fatalf("claim: %v", err)
		}
		if ok {
			return c.ID, true
		}
	}
	return shared.ID{}, false
}

func TestWorkflowStepChunks_EverySensorTakesAShare(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	cmds := NewCommandRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	stepRun := seedChunkStepRun(ctx, t, sqlDB, tenant)

	sensors := []shared.ID{
		seedZoneSensor(ctx, t, sqlDB, &tenant, "a", zoneSensorOpts{tools: []string{"httpx"}}),
		seedZoneSensor(ctx, t, sqlDB, &tenant, "b", zoneSensorOpts{tools: []string{"httpx", "nuclei"}}),
		seedZoneSensor(ctx, t, sqlDB, &tenant, "c", zoneSensorOpts{tools: []string{"httpx"}}),
	}
	noTool := seedZoneSensor(ctx, t, sqlDB, &tenant, "no-httpx", zoneSensorOpts{tools: []string{"nuclei"}})
	foreign := seedZoneSensor(ctx, t, sqlDB, &other, "other-tenant", zoneSensorOpts{tools: []string{"httpx"}})

	// A 2 000-target HTTP probe step: 10 chunks of 200 (probe.http).
	chunks := createStepChunks(ctx, t, cmds, tenant, stepRun, nil, 10, 200)

	if got := polledIDs(ctx, t, cmds, tenant, noTool); len(got) != 0 {
		t.Fatalf("a sensor without httpx was offered %d chunks", len(got))
	}
	if got := polledIDs(ctx, t, cmds, other, foreign); len(got) != 0 {
		t.Fatalf("another tenant's sensor was offered %d chunks", len(got))
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, chunks[0], foreign.String()); err != nil || ok {
		t.Fatalf("another tenant's sensor claimed a chunk: ok=%v err=%v", ok, err)
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, chunks[0], noTool.String()); err != nil || ok {
		t.Fatalf("a sensor without httpx claimed a chunk: ok=%v err=%v", ok, err)
	}

	// The sensors poll in turn, one chunk at a time, until the pool is empty.
	held := map[shared.ID][]shared.ID{}
	for claimed := 0; claimed < len(chunks); {
		progress := false
		for _, s := range sensors {
			if id, ok := claimOne(ctx, t, cmds, tenant, s); ok {
				held[s] = append(held[s], id)
				claimed++
				progress = true
			}
		}
		if !progress {
			t.Fatalf("pool stalled with %d of %d chunks claimed", claimed, len(chunks))
		}
	}
	for i, s := range sensors {
		if len(held[s]) == 0 {
			t.Fatalf("sensor %d took no chunk; shares %v", i, held)
		}
	}

	// Sensor a dies: its leases run out and its chunks go back to the pool,
	// unpinned, for the others.
	if _, err := sqlDB.ExecContext(ctx,
		`UPDATE commands SET lease_expires_at = NOW() - interval '1 second' WHERE sensor_id = $1 AND tenant_id = $2`,
		sensors[0].String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := cmds.RequeueExpiredLeases(ctx); err != nil {
		t.Fatal(err)
	}
	if id, ok := claimOne(ctx, t, cmds, tenant, sensors[1]); !ok || !containsID(held[sensors[0]], id) {
		t.Fatalf("the dead sensor's chunk was not handed to another sensor (ok=%v id=%v)", ok, id)
	}

	b, err := cmds.StepBatchState(ctx, tenant, stepRun)
	if err != nil {
		t.Fatal(err)
	}
	if b.Total != 10 || b.Active != 10 {
		t.Fatalf("step batch state = %+v, want 10 chunks all active", b)
	}
}

func TestWorkflowStepChunks_StayInTheRunsZone(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	db := &DB{DB: sqlDB}
	zones := NewScanZoneRepository(db)
	cmds := NewCommandRepository(db)
	tenant := seedTestTenant(ctx, t, sqlDB)
	stepRun := seedChunkStepRun(ctx, t, sqlDB, tenant)

	zone := newTestZone(t, tenant, "dc1", false, "10.9.0.0/16")
	if err := zones.Create(ctx, zone); err != nil {
		t.Fatal(err)
	}
	in1 := seedZoneSensor(ctx, t, sqlDB, &tenant, "in1", zoneSensorOpts{tools: []string{"httpx"}})
	in2 := seedZoneSensor(ctx, t, sqlDB, &tenant, "in2", zoneSensorOpts{tools: []string{"httpx"}})
	outside := seedZoneSensor(ctx, t, sqlDB, &tenant, "outside", zoneSensorOpts{tools: []string{"httpx"}})
	for _, s := range []shared.ID{in1, in2} {
		if err := zones.AssignSensor(ctx, tenant, zone.ID, s, nil); err != nil {
			t.Fatal(err)
		}
	}

	chunks := createStepChunks(ctx, t, cmds, tenant, stepRun, &zone.ID, 4, 50)
	if got := polledIDs(ctx, t, cmds, tenant, outside); len(got) != 0 {
		t.Fatalf("a sensor outside the zone was offered %d chunks", len(got))
	}
	if ok, err := cmds.ClaimForSensor(ctx, tenant, chunks[0], outside.String()); err != nil || ok {
		t.Fatalf("a sensor outside the zone claimed a chunk: ok=%v err=%v", ok, err)
	}
	took := map[shared.ID]int{}
	for i := 0; i < len(chunks); i++ {
		s := []shared.ID{in1, in2}[i%2]
		if _, ok := claimOne(ctx, t, cmds, tenant, s); !ok {
			t.Fatalf("zone sensor %d got no chunk", i%2)
		}
		took[s]++
	}
	if took[in1] != 2 || took[in2] != 2 {
		t.Fatalf("zone shares = %v, want 2 each", took)
	}
}

func containsID(xs []shared.ID, x shared.ID) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
