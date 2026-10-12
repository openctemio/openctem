package postgres

// The heartbeat ladder against a real database
// (docs/rfcs/RFC-035-sensor-control-plane-under-load.md §5.6): the deadline a
// heartbeat stores, the controller's guarded writes, and what late and stale
// mean for dispatch and pinned work.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func findCandidate(cands []sensor.LivenessCandidate, id shared.ID) (sensor.LivenessCandidate, bool) {
	for _, c := range cands {
		if c.ID == id {
			return c, true
		}
	}
	return sensor.LivenessCandidate{}, false
}

func TestUpdateHeartbeat_StoresDeadlineAndControl(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := &SensorRepository{db: &DB{DB: db}}

	tenantID := seedTestTenant(ctx, t, db)
	id := seedSensor(ctx, t, db, tenantID, "stale", nil, "nuclei", 0)

	ok, err := repo.UpdateHeartbeat(ctx, id, sensor.HeartbeatUpdate{
		TenantID: &tenantID,
		Interval: 45 * time.Second,
		Control:  &sensor.ControlReport{IntervalSeconds: 45, GapSeconds: 45.5, LagMillis: 3, BuildMillis: 7, RTTMillis: 11, Failures: 1},
	})
	if err != nil || !ok {
		t.Fatalf("UpdateHeartbeat: ok=%v err=%v", ok, err)
	}
	a, err := repo.GetByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if a.Health != sensor.SensorHealthOnline {
		t.Errorf("health = %q, want online", a.Health)
	}
	if a.HeartbeatInterval != 45*time.Second || a.HeartbeatDueAt == nil || a.LastSeenAt == nil {
		t.Fatalf("interval %s, due %v, last seen %v", a.HeartbeatInterval, a.HeartbeatDueAt, a.LastSeenAt)
	}
	if d := a.HeartbeatDueAt.Sub(*a.LastSeenAt); d != 45*time.Second {
		t.Errorf("due - last seen = %s, want 45s", d)
	}
	if a.Control == nil || a.Control.GapSeconds != 45.5 || a.Control.Failures != 1 || a.Control.ReportedAt == nil {
		t.Errorf("control = %+v", a.Control)
	}

	// A heartbeat without a control report keeps the stored one; an
	// interval out of range is clamped (300 s), never rejected.
	if _, err := repo.UpdateHeartbeat(ctx, id, sensor.HeartbeatUpdate{TenantID: &tenantID, Interval: time.Hour}); err != nil {
		t.Fatal(err)
	}
	a, _ = repo.GetByID(ctx, id)
	if a.Control == nil || a.HeartbeatInterval != sensor.MaxHeartbeatInterval {
		t.Errorf("after a heartbeat without control: control %+v, interval %s", a.Control, a.HeartbeatInterval)
	}
}

func TestApplyLiveness_GuardedByLastSeen(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, db)()
	repo := &SensorRepository{db: &DB{DB: db}}

	tenantID := seedTestTenant(ctx, t, db)
	seen := time.Now().Add(-10 * time.Minute)
	id := seedSensor(ctx, t, db, tenantID, "online", &seen, "nuclei", 0)

	now, cands, err := repo.ListLivenessCandidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := findCandidate(cands, id)
	if !ok {
		t.Fatal("online sensor not listed")
	}
	if got := sensor.Ladder(now, c.Deadline).State; got != sensor.SensorHealthOffline {
		t.Fatalf("10 min silent on the default interval: %q, want offline", got)
	}

	// A request lands between the read and the write: the write loses.
	if _, err := db.ExecContext(ctx, `UPDATE sensors SET last_seen_at = NOW() WHERE id = $1`, id.String()); err != nil {
		t.Fatal(err)
	}
	moved, err := repo.ApplyLiveness(ctx, sensor.SensorHealthOffline, []sensor.LivenessCandidate{c})
	if err != nil {
		t.Fatal(err)
	}
	if len(moved) != 0 || sensorHealth(ctx, t, db, id) != "online" {
		t.Fatalf("moved %v, health %q; a request after the read must win", moved, sensorHealth(ctx, t, db, id))
	}

	// Re-read and apply: late, then stale, then offline (with last_offline_at).
	for _, step := range []sensor.SensorHealth{sensor.SensorHealthLate, sensor.SensorHealthStale, sensor.SensorHealthOffline} {
		_, cands, err = repo.ListLivenessCandidates(ctx)
		if err != nil {
			t.Fatal(err)
		}
		c, _ = findCandidate(cands, id)
		moved, err = repo.ApplyLiveness(ctx, step, []sensor.LivenessCandidate{c})
		if err != nil || len(moved) != 1 {
			t.Fatalf("move to %s: moved %v err %v", step, moved, err)
		}
		if got := sensorHealth(ctx, t, db, id); got != string(step) {
			t.Fatalf("health = %q, want %q", got, step)
		}
	}
	var offlineAt *time.Time
	if err := db.QueryRowContext(ctx, `SELECT last_offline_at FROM sensors WHERE id = $1`, id.String()).Scan(&offlineAt); err != nil || offlineAt == nil {
		t.Fatalf("last_offline_at = %v (%v)", offlineAt, err)
	}
	// An offline sensor is no longer watched: a second move does nothing.
	if moved, _ := repo.ApplyLiveness(ctx, sensor.SensorHealthOffline, []sensor.LivenessCandidate{c}); len(moved) != 0 {
		t.Fatalf("offline sensor moved again: %v", moved)
	}
	if _, err := repo.ApplyLiveness(ctx, sensor.SensorHealthOnline, []sensor.LivenessCandidate{c}); err == nil {
		t.Fatal("the ladder never moves a sensor up; online must be refused")
	}
}

func TestMarkStaleSensorsOffline_UsesTheStoredDeadline(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, db)()
	repo := &SensorRepository{db: &DB{DB: db}}

	tenantID := seedTestTenant(ctx, t, db)
	seen := time.Now().Add(-100 * time.Second)
	// Told to come back in 45 s: 100 s after its heartbeat it is late, not
	// offline (the old fixed 90 s convicted it).
	loaded := seedSensor(ctx, t, db, tenantID, "online", &seen, "nuclei", 0)
	// A busy sensor (5 s) silent for 100 s is past its offline step (95 s).
	busy := seedSensor(ctx, t, db, tenantID, "online", &seen, "nuclei", 0)
	for id, iv := range map[shared.ID]int{loaded: 45, busy: 5} {
		if _, err := db.ExecContext(ctx, `UPDATE sensors SET heartbeat_interval_seconds = $2::integer,
			heartbeat_due_at = last_seen_at + make_interval(secs => $2::integer) WHERE id = $1`, id.String(), iv); err != nil {
			t.Fatal(err)
		}
	}

	ids, err := repo.MarkStaleSensorsOffline(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[shared.ID]bool{}
	for _, id := range ids {
		got[id] = true
	}
	if got[loaded] || sensorHealth(ctx, t, db, loaded) != "online" {
		t.Errorf("the 45 s sensor was convicted 100 s after its heartbeat")
	}
	if !got[busy] || sensorHealth(ctx, t, db, busy) != "offline" {
		t.Errorf("the 5 s sensor silent for 100 s was not convicted")
	}
}

func TestDispatch_LateTakesWorkStaleDoesNot(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, db)()
	repo := &SensorRepository{db: &DB{DB: db}}

	tenantID := seedTestTenant(ctx, t, db)
	now := time.Now()
	stale := seedSensor(ctx, t, db, tenantID, "stale", &now, "nuclei", 0)
	got, err := repo.FindAvailableWithTool(ctx, tenantID, "nuclei")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("dispatch picked %s; a stale sensor takes no new work", got.ID)
	}
	tools, _ := repo.GetAvailableToolsForTenant(ctx, tenantID)
	if len(tools) != 0 {
		t.Fatalf("stale sensor advertises %v", tools)
	}

	late := seedSensor(ctx, t, db, tenantID, "late", &now, "nuclei", 0)
	got, err = repo.FindAvailableWithTool(ctx, tenantID, "nuclei")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.ID != late {
		t.Fatalf("dispatch picked %v, want the late sensor %s (still dispatchable)", got, late)
	}
	_ = stale
}

func TestReleasePending_StaleReleasesLateKeeps(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	defer lockGlobalSweep(ctx, t, db)()
	cmds := &CommandRepository{db: &DB{DB: db}}

	tenantID := seedTestTenant(ctx, t, db)
	now := time.Now()
	late := seedSensor(ctx, t, db, tenantID, "late", &now, "nuclei", 0)
	stale := seedSensor(ctx, t, db, tenantID, "stale", &now, "nuclei", 0)

	pin := func(sensorID shared.ID) shared.ID {
		t.Helper()
		id := shared.NewID()
		if _, err := db.ExecContext(ctx, `INSERT INTO commands (id, tenant_id, sensor_id, type, status, payload)
			VALUES ($1, $2, $3, 'scan', 'pending', '{"scan_run_id":"x"}'::jsonb)`,
			id.String(), tenantID.String(), sensorID.String()); err != nil {
			t.Fatalf("seed command: %v", err)
		}
		t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM commands WHERE id = $1`, id.String()) })
		return id
	}
	onLate, onStale := pin(late), pin(stale)

	if _, err := cmds.ReleasePendingFromUnavailableSensors(ctx); err != nil {
		t.Fatal(err)
	}
	holder := func(id shared.ID) *string {
		var s *string
		if err := db.QueryRowContext(ctx, `SELECT sensor_id::text FROM commands WHERE id = $1`, id.String()).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	if h := holder(onLate); h == nil || *h != late.String() {
		t.Errorf("a late sensor's pinned work was released")
	}
	if h := holder(onStale); h != nil {
		t.Errorf("a stale sensor's pinned work is still pinned to %s", *h)
	}
}
