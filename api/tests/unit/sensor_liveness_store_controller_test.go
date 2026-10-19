package unit

// The health controller over the liveness store (docs/architecture/sensors.md,
// "Heartbeat soft state"): it judges from the store's deadlines merged with
// Postgres's, never from a Postgres checkpoint alone, holds every move while
// the store is unreachable or rebuilding, and lets a heartbeat that landed
// since win.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeLivenessStore is an in-memory sensor.LivenessStore.
type fakeLivenessStore struct {
	mu       sync.Mutex
	snaps    map[shared.ID]sensor.LivenessSnapshot
	down     bool
	created  bool
	grace    bool
	refuse   bool // Judge answers "heartbeated since"
	seeded   []sensor.LivenessSeed
	unwatch  []sensor.LivenessKey
	judged   int
	graceSet int
}

func newFakeLivenessStore() *fakeLivenessStore {
	return &fakeLivenessStore{snaps: map[shared.ID]sensor.LivenessSnapshot{}}
}

var errFakeDown = errors.New("fake store down")

func (f *fakeLivenessStore) err() error {
	if f.down {
		return errFakeDown
	}
	return nil
}
func (f *fakeLivenessStore) Beat(context.Context, sensor.LivenessBeat) (sensor.LivenessBeatResult, error) {
	return sensor.LivenessBeatResult{}, f.err()
}
func (f *fakeLivenessStore) Touch(context.Context, sensor.LivenessKey, string) (bool, string, error) {
	return true, "", f.err()
}
func (f *fakeLivenessStore) Invalidate(context.Context, sensor.LivenessKey) error { return f.err() }
func (f *fakeLivenessStore) Snapshots(_ context.Context, keys []sensor.LivenessKey) (map[shared.ID]sensor.LivenessSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errFakeDown
	}
	out := map[shared.ID]sensor.LivenessSnapshot{}
	for _, k := range keys {
		if s, ok := f.snaps[k.Sensor]; ok {
			out[k.Sensor] = s
		}
	}
	return out, nil
}
func (f *fakeLivenessStore) Overdue(context.Context, time.Duration, int) (time.Time, []sensor.LivenessOverdue, error) {
	return time.Time{}, nil, f.err()
}
func (f *fakeLivenessStore) Judge(context.Context, sensor.LivenessKey, time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.judged++
	return !f.refuse, f.err()
}
func (f *fakeLivenessStore) Unwatch(_ context.Context, keys []sensor.LivenessKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unwatch = append(f.unwatch, keys...)
	return f.err()
}
func (f *fakeLivenessStore) Generation(context.Context) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return "", false, errFakeDown
	}
	c := f.created
	f.created = false
	return "gen-1", c, nil
}
func (f *fakeLivenessStore) Seed(_ context.Context, seeds []sensor.LivenessSeed) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seeded = append(f.seeded, seeds...)
	return f.err()
}
func (f *fakeLivenessStore) StartGrace(context.Context, time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.grace = true
	f.graceSet++
	return f.err()
}
func (f *fakeLivenessStore) InGrace(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.grace, f.err()
}
func (f *fakeLivenessStore) Watched(context.Context) (int64, error) {
	return int64(len(f.snaps)), f.err()
}

type recordingExpirer struct{ ids []shared.ID }

func (r *recordingExpirer) ExpireLeasesHeldBy(_ context.Context, id shared.ID) (int64, error) {
	r.ids = append(r.ids, id)
	return 1, nil
}

// storeFixture: a sensor whose Postgres row holds a checkpoint from 9
// minutes ago (30 s interval: far past offline by Postgres alone).
func storeFixture(t *testing.T) (*sensorSvcMockRepo, *sensor.Sensor, *fakeLivenessStore, *controller.SensorHealthController, time.Time) {
	t.Helper()
	repo, a, t0 := ladderFixture(t)
	now := t0.Add(9 * time.Minute)
	repo.livenessNow = now
	store := newFakeLivenessStore()
	ctrl := controller.NewSensorHealthController(repo, nil, &controller.SensorHealthControllerConfig{Logger: logger.NewNop()})
	ctrl.SetLiveness(sensor.LivenessRedis, store)
	return repo, a, store, ctrl, now
}

func reconcile(t *testing.T, c *controller.SensorHealthController) {
	t.Helper()
	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Postgres holds only a checkpoint; the store says the sensor heartbeated
// 5 s ago: it stays online. Judged from Postgres alone (postgres mode) the
// same row is convicted.
func TestLivenessStore_JudgesFromStoreNotCheckpoint(t *testing.T) {
	_, a, store, ctrl, now := storeFixture(t)
	store.snaps[a.ID] = sensor.LivenessSnapshot{SeenAt: now.Add(-5 * time.Second), DueAt: now.Add(25 * time.Second), Interval: 30 * time.Second}
	reconcile(t, ctrl)
	if a.Health != sensor.SensorHealthOnline {
		t.Fatalf("a sensor heartbeating into the store was moved to %s from its Postgres checkpoint", a.Health)
	}

	// The same row judged from Postgres alone is convicted.
	repo, b, _, _, _ := storeFixture(t)
	pg := controller.NewSensorHealthController(repo, nil, &controller.SensorHealthControllerConfig{Logger: logger.NewNop()})
	reconcile(t, pg)
	if b.Health != sensor.SensorHealthOffline {
		t.Fatalf("postgres mode: health = %s, want offline", b.Health)
	}
}

// Silent in both: convicted offline once, its leases ended, and dropped
// from the due index.
func TestLivenessStore_SilentInBothIsConvicted(t *testing.T) {
	_, a, store, ctrl, now := storeFixture(t)
	exp := &recordingExpirer{}
	ctrl.SetLeaseExpirer(exp)
	store.snaps[a.ID] = sensor.LivenessSnapshot{SeenAt: now.Add(-8 * time.Minute), DueAt: now.Add(-7*time.Minute - 30*time.Second), Interval: 30 * time.Second}
	reconcile(t, ctrl)
	if a.Health != sensor.SensorHealthOffline {
		t.Fatalf("health = %s, want offline", a.Health)
	}
	if store.judged != 1 {
		t.Fatalf("verdicts recorded in the store: %d, want 1", store.judged)
	}
	if len(exp.ids) != 1 || exp.ids[0] != a.ID {
		t.Fatalf("leases ended: %v", exp.ids)
	}
	if len(store.unwatch) != 1 || store.unwatch[0].Sensor != a.ID {
		t.Fatalf("unwatched: %v", store.unwatch)
	}
}

// A heartbeat that fell back to Postgres while the store missed it counts:
// the later of the two deadlines wins.
func TestLivenessStore_PostgresFallbackCounts(t *testing.T) {
	_, a, store, ctrl, now := storeFixture(t)
	seen, due := now.Add(-5*time.Second), now.Add(25*time.Second)
	a.LastSeenAt, a.HeartbeatDueAt = &seen, &due
	store.snaps[a.ID] = sensor.LivenessSnapshot{SeenAt: now.Add(-8 * time.Minute), DueAt: now.Add(-7 * time.Minute), Interval: 30 * time.Second}
	reconcile(t, ctrl)
	if a.Health != sensor.SensorHealthOnline {
		t.Fatalf("health = %s, want online (Postgres has the newer heartbeat)", a.Health)
	}
}

// Store unreachable: nobody is moved, however old Postgres's checkpoint.
// Back up: rebuilt from Postgres, and the grace holds every move.
func TestLivenessStore_HoldsWhileDownAndRebuilds(t *testing.T) {
	_, a, store, ctrl, _ := storeFixture(t)
	store.down = true
	for i := 0; i < 3; i++ {
		reconcile(t, ctrl)
	}
	if a.Health != sensor.SensorHealthOnline {
		t.Fatalf("a sensor was moved to %s while the store was unreachable", a.Health)
	}
	store.down = false
	reconcile(t, ctrl)
	if len(store.seeded) != 1 || store.seeded[0].Key.Sensor != a.ID || store.graceSet != 1 {
		t.Fatalf("store not rebuilt after the outage: seeds %v grace %d", store.seeded, store.graceSet)
	}
	if a.Health != sensor.SensorHealthOnline {
		t.Fatalf("moved to %s during the cold-start grace", a.Health)
	}
	// The seed's deadline is no earlier than the end of the grace.
	if !store.seeded[0].DueAt.After(*a.LastSeenAt) {
		t.Fatalf("seeded due %v", store.seeded[0].DueAt)
	}
}

// An emptied store (FLUSHALL, restart without data): rebuilt, grace, no
// convictions.
func TestLivenessStore_ColdStartNoMassOffline(t *testing.T) {
	repo, a, store, ctrl, _ := storeFixture(t)
	others := make([]*sensor.Sensor, 0, 20)
	for i := 0; i < 20; i++ {
		o := repo.seedSensor(shared.NewID(), "fleet", sensor.SensorTypeWorker)
		o.Health, o.LastSeenAt, o.HeartbeatDueAt, o.HeartbeatInterval = a.Health, a.LastSeenAt, a.HeartbeatDueAt, a.HeartbeatInterval
		others = append(others, o)
	}
	store.created = true
	reconcile(t, ctrl)
	if len(store.seeded) != 21 {
		t.Fatalf("seeded %d sensors, want 21", len(store.seeded))
	}
	for _, o := range append(others, a) {
		if o.Health != sensor.SensorHealthOnline {
			t.Fatalf("cold start moved a sensor to %s", o.Health)
		}
	}
}

// A heartbeat between the read and the verdict wins: the store refuses the
// verdict and the sensor is not moved.
func TestLivenessStore_HeartbeatSinceWins(t *testing.T) {
	_, a, store, ctrl, now := storeFixture(t)
	store.snaps[a.ID] = sensor.LivenessSnapshot{SeenAt: now.Add(-8 * time.Minute), DueAt: now.Add(-7 * time.Minute), Interval: 30 * time.Second}
	store.refuse = true
	reconcile(t, ctrl)
	if a.Health != sensor.SensorHealthOnline {
		t.Fatalf("health = %s, want online (a heartbeat landed since)", a.Health)
	}
}

// Shadow mode: Postgres decides, and a differing store verdict is counted.
func TestLivenessStore_ShadowCountsDisagreements(t *testing.T) {
	repo, a, t0 := ladderFixture(t)
	now := t0.Add(20 * time.Second) // online by Postgres
	repo.livenessNow = now
	store := newFakeLivenessStore()
	store.snaps[a.ID] = sensor.LivenessSnapshot{SeenAt: t0.Add(-10 * time.Minute), DueAt: t0.Add(-9 * time.Minute), Interval: 30 * time.Second}
	ctrl := controller.NewSensorHealthController(repo, nil, &controller.SensorHealthControllerConfig{Logger: logger.NewNop()})
	ctrl.SetLiveness(sensor.LivenessShadow, store)
	before := testutil.ToFloat64(metrics.SensorLivenessDisagreementsTotal.WithLabelValues("online", "offline"))
	reconcile(t, ctrl)
	if a.Health != sensor.SensorHealthOnline {
		t.Fatalf("shadow mode moved the sensor to %s", a.Health)
	}
	if got := testutil.ToFloat64(metrics.SensorLivenessDisagreementsTotal.WithLabelValues("online", "offline")) - before; got != 1 {
		t.Fatalf("disagreements counted: %v, want 1", got)
	}
}
