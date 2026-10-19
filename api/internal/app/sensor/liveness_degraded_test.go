package sensor

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// failingBeatStore fails every Beat and records the degraded marker.
type failingBeatStore struct {
	sensordom.LivenessStore
	marks atomic.Int32
	ttl   atomic.Int64
}

func (f *failingBeatStore) Beat(context.Context, sensordom.LivenessBeat) (sensordom.LivenessBeatResult, error) {
	return sensordom.LivenessBeatResult{}, errors.New("store down")
}

func (f *failingBeatStore) MarkDegraded(_ context.Context, ttl time.Duration) error {
	f.marks.Add(1)
	f.ttl.Store(int64(ttl))
	return nil
}

func (f *failingBeatStore) Degraded(context.Context) (bool, error) { return f.marks.Load() > 0, nil }

// A heartbeat whose store write fails tells the other replicas (so their
// health controller holds convictions), at most once per throttle window.
func TestLiveness_FailedHeartbeatWriteMarksTheStoreDegraded(t *testing.T) {
	store := &failingBeatStore{}
	p := &livenessPlane{
		mode: sensordom.LivenessRedis, store: store, log: logger.NewNop(),
		fallbackAll:  rate.NewLimiter(rate.Limit(livenessFallbackPerSecond), livenessFallbackPerSecond),
		fallbackLast: keyUseDebouncer{window: livenessFallbackPerSensor},
	}
	s := &SensorService{live: p}
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	a := &sensordom.Sensor{ID: shared.NewID()}

	s.planHeartbeatWrite(context.Background(), a, sensordom.HeartbeatUpdate{}, now)
	waitFor(t, func() bool { return store.marks.Load() == 1 })
	if time.Duration(store.ttl.Load()) != sensordom.LivenessDegradedTTL {
		t.Fatalf("marker ttl = %v", time.Duration(store.ttl.Load()))
	}

	// Within the throttle window another failure does not write again.
	s.planHeartbeatWrite(context.Background(), &sensordom.Sensor{ID: shared.NewID()}, sensordom.HeartbeatUpdate{}, now.Add(time.Second))
	time.Sleep(50 * time.Millisecond)
	if n := store.marks.Load(); n != 1 {
		t.Fatalf("marker written %d times inside the throttle window", n)
	}
	// After it, it is refreshed.
	s.planHeartbeatWrite(context.Background(), &sensordom.Sensor{ID: shared.NewID()}, sensordom.HeartbeatUpdate{}, now.Add(livenessDegradedEvery+time.Second))
	waitFor(t, func() bool { return store.marks.Load() == 2 })
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition not met")
}
