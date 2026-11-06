package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Every change of a command is one event of its run's timeline (research/62
// P0-4), whoever wrote it: claim, start, a refusal, a release back to the
// queue, the end. Another tenant reads none of them.
func TestCommandEvents_RecordTheLifecycle(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	tenant := seedScanTriggerTenant(ctx, t, db)
	sensor := seedJobSensor(ctx, t, db, tenant)
	run, cmd := shared.NewID(), shared.NewID()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}

	exec(`INSERT INTO commands (id, tenant_id, type, status, payload) VALUES ($1, $2, 'scan', 'pending', jsonb_build_object('scan_run_id', $3::text))`,
		cmd.String(), tenant.String(), run.String())
	exec(`UPDATE commands SET status = 'acknowledged', sensor_id = $2, dispatch_attempts = 1 WHERE id = $1`, cmd.String(), sensor.String())
	// The sensor refuses it (sensor-local policy) and it goes back to the queue.
	exec(`UPDATE commands SET status = 'pending', sensor_id = NULL, refused_by = array_append(refused_by, $2::uuid),
	        refusals = refusals || jsonb_build_array(jsonb_build_object('sensor_id', $2::text, 'layer', 'local_policy', 'rule', 'deny_private', 'detail', 'private target'))
	      WHERE id = $1`, cmd.String(), sensor.String())
	exec(`UPDATE commands SET status = 'acknowledged', sensor_id = $2, dispatch_attempts = 2 WHERE id = $1`, cmd.String(), sensor.String())
	repo := NewCommandRepository(&DB{DB: db})
	if ok, err := repo.ReleaseForSensor(ctx, tenant, cmd, sensor.String(), "sensor shutting down"); err != nil || !ok {
		t.Fatalf("release: %v %v", ok, err)
	}
	exec(`UPDATE commands SET status = 'acknowledged', sensor_id = $2 WHERE id = $1`, cmd.String(), sensor.String())
	exec(`UPDATE commands SET status = 'running' WHERE id = $1`, cmd.String())
	exec(`UPDATE commands SET payload = payload || '{"x":1}' WHERE id = $1`, cmd.String()) // no event
	exec(`UPDATE commands SET status = 'failed', error_message = 'nuclei exited 2' WHERE id = $1`, cmd.String())

	events := NewCommandEventRepository(&DB{DB: db})
	got, truncated, err := events.ListForRun(ctx, tenant, run, 0)
	if err != nil || truncated {
		t.Fatalf("list: %v %v", err, truncated)
	}
	want := []string{"queued", "claimed", "refused", "claimed", "requeued", "claimed", "started", "failed"}
	if len(got) != len(want) {
		t.Fatalf("events = %+v, want %v", got, want)
	}
	for i, e := range got {
		if e.Event != want[i] || e.CommandID != cmd {
			t.Fatalf("event %d = %s (%s), want %s", i, e.Event, e.CommandID, want[i])
		}
	}
	if r := got[2]; r.Code != "local_policy.deny_private" || r.Message != "private target" || r.SensorID == nil || *r.SensorID != sensor {
		t.Errorf("refusal event = %+v", r)
	}
	if r := got[4]; r.Message != "sensor shutting down" || r.SensorID == nil || *r.SensorID != sensor {
		t.Errorf("requeue event = %+v (want the releasing sensor and its reason)", r)
	}
	if f := got[7]; f.Message != "nuclei exited 2" || f.Attempt != 2 {
		t.Errorf("failed event = %+v", f)
	}

	other := seedScanTriggerTenant(ctx, t, db)
	if got, _, err := events.ListForRun(ctx, other, run, 0); err != nil || len(got) != 0 {
		t.Fatalf("another tenant reads %d events (%v)", len(got), err)
	}

	// Retention removes old events only.
	exec(`UPDATE command_events SET created_at = now() - interval '40 days' WHERE command_id = $1 AND event = 'queued'`, cmd.String())
	if n, err := events.DeleteOlderThan(ctx, time.Now().AddDate(0, 0, -30), 100); err != nil || n != 1 {
		t.Fatalf("retention deleted %d (%v), want 1", n, err)
	}
}

// A command that is not part of a run still has events, without a run.
func TestCommandEvents_WithoutARun(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	tenant := seedScanTriggerTenant(ctx, t, db)
	cmd := shared.NewID()
	if _, err := db.ExecContext(ctx, `INSERT INTO commands (id, tenant_id, type, status, payload) VALUES ($1, $2, 'scan', 'pending', '{"scan_run_id":"not-a-uuid"}')`,
		cmd.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM command_events WHERE command_id = $1 AND run_id IS NULL`, cmd.String()).Scan(&n); err != nil || n != 1 {
		t.Fatalf("events without a run = %d (%v), want 1", n, err)
	}
}
