package unit

// The health controller walks a silent sensor down the heartbeat ladder
// (docs/rfcs/RFC-035-sensor-control-plane-under-load.md §5.6, decisions D1
// and D3): online -> late -> stale -> offline against its own deadline, with
// sensor.offline notified exactly once, at offline, and never while the
// platform itself is degraded.

import (
	"context"
	"testing"
	"time"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ladderFixture is one tenant sensor that heartbeated at t0 on a 30 s
// interval (due t0+30 s: late after 40 s, stale after 100 s, offline after
// 120 s).
func ladderFixture(t *testing.T) (*sensorSvcMockRepo, *sensor.Sensor, time.Time) {
	t.Helper()
	repo := newSensorSvcMockRepo()
	a := repo.seedSensor(shared.NewID(), "edge-scanner", sensor.SensorTypeWorker)
	t0 := time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)
	due := t0.Add(30 * time.Second)
	a.Health, a.LastSeenAt, a.HeartbeatDueAt, a.HeartbeatInterval = sensor.SensorHealthOnline, &t0, &due, 30*time.Second
	return repo, a, t0
}

func TestSensorHealthLadder_WalksDownAndNotifiesOnceAtOffline(t *testing.T) {
	repo, a, t0 := ladderFixture(t)
	notifier := &recordingEnqueuer{}
	ctrl := controller.NewSensorHealthController(repo, nil, &controller.SensorHealthControllerConfig{Logger: logger.NewNop()})
	ctrl.SetNotifier(notifier)

	steps := []struct {
		after time.Duration
		want  sensor.SensorHealth
	}{
		{30 * time.Second, sensor.SensorHealthOnline},
		{40 * time.Second, sensor.SensorHealthOnline},
		{41 * time.Second, sensor.SensorHealthLate},
		{100 * time.Second, sensor.SensorHealthLate},
		{101 * time.Second, sensor.SensorHealthStale},
		{120 * time.Second, sensor.SensorHealthStale},
		{121 * time.Second, sensor.SensorHealthOffline},
		{10 * time.Minute, sensor.SensorHealthOffline},
	}
	for _, s := range steps {
		repo.livenessNow = t0.Add(s.after)
		if _, err := ctrl.Reconcile(context.Background()); err != nil {
			t.Fatalf("Reconcile at +%s: %v", s.after, err)
		}
		if a.Health != s.want {
			t.Fatalf("at +%s health = %q, want %q", s.after, a.Health, s.want)
		}
		wantNotes := 0
		if s.want == sensor.SensorHealthOffline {
			wantNotes = 1
		}
		if len(notifier.calls) != wantNotes {
			t.Fatalf("at +%s (%s): %d sensor.offline notifications, want %d", s.after, s.want, len(notifier.calls), wantNotes)
		}
	}
	if a.LastOfflineAt == nil {
		t.Error("last_offline_at not stamped at offline")
	}
}

func TestSensorHealthLadder_AHeartbeatInBetweenWins(t *testing.T) {
	repo, a, t0 := ladderFixture(t)
	ctrl := controller.NewSensorHealthController(repo, nil, &controller.SensorHealthControllerConfig{Logger: logger.NewNop()})

	repo.livenessNow = t0.Add(101 * time.Second)
	if _, err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.Health != sensor.SensorHealthStale {
		t.Fatalf("health = %q, want stale", a.Health)
	}
	// The sensor heartbeats again: health online, new deadline.
	seen := t0.Add(110 * time.Second)
	due := seen.Add(30 * time.Second)
	a.Health, a.LastSeenAt, a.HeartbeatDueAt = sensor.SensorHealthOnline, &seen, &due
	repo.livenessNow = t0.Add(125 * time.Second)
	if _, err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.Health != sensor.SensorHealthOnline {
		t.Fatalf("after a fresh heartbeat health = %q, want online", a.Health)
	}
}

func TestSensorHealthLadder_HoldsOfflineWhilePlatformDegraded(t *testing.T) {
	repo, a, t0 := ladderFixture(t)
	clock := t0
	guard := sensorapp.NewPlatformHealthForTest(sensorapp.PlatformHealthConfig{StartupGrace: 5 * time.Minute}, func() time.Time { return clock })
	notifier := &recordingEnqueuer{}
	ctrl := controller.NewSensorHealthController(repo, nil, &controller.SensorHealthControllerConfig{
		Interval: 30 * time.Second, Logger: logger.NewNop(),
	})
	ctrl.SetNotifier(notifier)
	ctrl.SetPlatformHealth(guard)

	tick := func(after time.Duration) {
		t.Helper()
		clock, repo.livenessNow = t0.Add(after), t0.Add(after)
		if _, err := ctrl.Reconcile(context.Background()); err != nil {
			t.Fatal(err)
		}
	}

	// Ticks every 30 s. Past the offline step from +121 s, but the API
	// started at t0 with a 5 min startup grace: held at stale.
	for after := 120 * time.Second; after < 5*time.Minute; after += 30 * time.Second {
		tick(after)
		if after > 100*time.Second && (a.Health != sensor.SensorHealthStale || len(notifier.calls) != 0) {
			t.Fatalf("+%s during startup grace: health %q, %d notifications; want stale and none", after, a.Health, len(notifier.calls))
		}
	}

	// Slow heartbeats keep holding it after the grace.
	clock = t0.Add(5 * time.Minute)
	for range 10 {
		guard.ObserveHeartbeat(3 * time.Second)
	}
	for _, after := range []time.Duration{5*time.Minute + 30*time.Second, 6 * time.Minute, 6*time.Minute + 30*time.Second} {
		tick(after)
		if a.Health != sensor.SensorHealthStale || len(notifier.calls) != 0 {
			t.Fatalf("+%s with slow heartbeats: health %q, %d notifications; want stale and none", after, a.Health, len(notifier.calls))
		}
	}

	// The slow samples age out of the 2 min window: the platform is healthy
	// and the sensor is convicted, once.
	for _, after := range []time.Duration{7 * time.Minute, 7*time.Minute + 30*time.Second, 8 * time.Minute} {
		tick(after)
	}
	if a.Health != sensor.SensorHealthOffline || len(notifier.calls) != 1 {
		t.Fatalf("healthy platform: health %q, %d notifications; want offline and exactly 1", a.Health, len(notifier.calls))
	}
}

func TestSensorHealthLadder_HoldsOneTickAfterAStall(t *testing.T) {
	repo, a, t0 := ladderFixture(t)
	clock := t0.Add(-time.Hour) // the API has been up for long
	guard := sensorapp.NewPlatformHealthForTest(sensorapp.PlatformHealthConfig{}, func() time.Time { return clock })
	ctrl := controller.NewSensorHealthController(repo, nil, &controller.SensorHealthControllerConfig{
		Interval: 30 * time.Second, Logger: logger.NewNop(),
	})
	ctrl.SetPlatformHealth(guard)

	clock, repo.livenessNow = t0.Add(10*time.Second), t0.Add(10*time.Second)
	if _, err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The next tick comes 3 min later: the process was stalled.
	clock, repo.livenessNow = t0.Add(190*time.Second), t0.Add(190*time.Second)
	if _, err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.Health != sensor.SensorHealthStale {
		t.Fatalf("after a stall health = %q, want stale (conviction held)", a.Health)
	}
	clock, repo.livenessNow = t0.Add(220*time.Second), t0.Add(220*time.Second)
	if _, err := ctrl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.Health != sensor.SensorHealthOffline {
		t.Fatalf("next regular tick health = %q, want offline", a.Health)
	}
}

func TestSensorHealthLadder_LooksUpRepositoryLoudly(t *testing.T) {
	// A repository without deadlines cannot be judged: Reconcile fails
	// instead of silently doing nothing.
	ctrl := controller.NewSensorHealthController(sensorRepoWithoutLiveness{newSensorSvcMockRepo()}, nil,
		&controller.SensorHealthControllerConfig{Logger: logger.NewNop()})
	if _, err := ctrl.Reconcile(context.Background()); err == nil {
		t.Fatal("Reconcile without a LivenessRepository returned no error")
	}
}

// sensorRepoWithoutLiveness hides the mock's LivenessRepository methods.
type sensorRepoWithoutLiveness struct{ sensor.Repository }

// The heartbeat stores the interval the sensor will follow: its reported
// control interval or, when it follows the advice, the advised one,
// whichever is longer; 60s for a sensor that ignores hints.
func TestUpdateHeartbeat_StoresFollowedInterval(t *testing.T) {
	cases := []struct {
		name string
		data sensorapp.SensorHeartbeatData
		want time.Duration
	}{
		{"ignores hints", sensorapp.SensorHeartbeatData{AdvisedSeconds: 30}, 60 * time.Second},
		{"follows the advice", sensorapp.SensorHeartbeatData{AdvisedSeconds: 30, DoorbellAware: true}, 30 * time.Second},
		{"reports its interval", sensorapp.SensorHeartbeatData{Control: &sensor.ControlReport{IntervalSeconds: 20}}, 20 * time.Second},
		{"fresh longer advice wins over the report", sensorapp.SensorHeartbeatData{Control: &sensor.ControlReport{IntervalSeconds: 5}, AdvisedSeconds: 45, DoorbellAware: true}, 45 * time.Second},
	}
	for _, c := range cases {
		repo := newSensorSvcMockRepo()
		svc := sensorapp.NewSensorService(repo, nil, logger.NewNop())
		a := repo.seedSensor(shared.NewID(), "s", sensor.SensorTypeWorker)
		if err := svc.UpdateHeartbeat(context.Background(), a.ID, c.data); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := repo.lastHeartbeat.Interval; got != c.want {
			t.Errorf("%s: stored interval %s, want %s", c.name, got, c.want)
		}
		if c.data.Control != nil && repo.lastHeartbeat.Control != c.data.Control {
			t.Errorf("%s: control report not passed to the repository", c.name)
		}
	}
}

// A late or stale sensor never disconnected: its next heartbeat is not a
// reconnect (no sensor.connected audit row).
func TestUpdateHeartbeat_LateIsNotAReconnect(t *testing.T) {
	for _, h := range []sensor.SensorHealth{sensor.SensorHealthLate, sensor.SensorHealthStale, sensor.SensorHealthOffline} {
		auditSvc, auditRepo := newTestAuditService()
		repo := newSensorSvcMockRepo()
		svc := sensorapp.NewSensorService(repo, auditSvc, logger.NewNop())
		a := repo.seedSensor(shared.NewID(), "s", sensor.SensorTypeWorker)
		a.Health = h
		if err := svc.UpdateHeartbeat(context.Background(), a.ID, sensorapp.SensorHeartbeatData{}); err != nil {
			t.Fatal(err)
		}
		want := 0
		if h == sensor.SensorHealthOffline {
			want = 1
		}
		if auditRepo.createCalls != want {
			t.Errorf("heartbeat after %s: %d connect audit rows, want %d", h, auditRepo.createCalls, want)
		}
	}
}
