package sensor

import (
	"testing"
	"time"

	"golang.org/x/time/rate"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The replica's fallback budget never lets a live sensor walk to stale
// while the store is unreachable: once the budget is spent, a sensor whose
// Postgres deadline would pass before its next allowed write is still
// written; one with time to spare is dropped; the per-sensor bound holds.
func TestLivenessFallback_BudgetNeverStalesALiveSensor(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	p := &livenessPlane{
		fallbackAll:  rate.NewLimiter(rate.Limit(livenessFallbackPerSecond), 1),
		fallbackLast: keyUseDebouncer{window: livenessFallbackPerSensor},
	}
	if !p.fallbackAll.AllowN(now, 1) {
		t.Fatal("budget not available")
	}
	sensorAt := func(seen time.Time) *sensordom.Sensor {
		due := seen.Add(30 * time.Second)
		return &sensordom.Sensor{ID: shared.NewID(), LastSeenAt: &seen, HeartbeatDueAt: &due, HeartbeatInterval: 30 * time.Second}
	}

	// Just written to Postgres: plenty of time, the spent budget drops it.
	if p.allowFallback(sensorAt(now.Add(-5*time.Second)), now) {
		t.Fatal("a fresh sensor bypassed the spent budget")
	}

	// Last written 40 s ago on a 30 s interval: stale in 60 s, before its
	// next allowed write a minute from now. Written despite the budget.
	urgent := sensorAt(now.Add(-40 * time.Second))
	if !p.allowFallback(urgent, now) {
		t.Fatal("a sensor about to go stale was dropped: the controller would convict it")
	}
	// ... but still at most once per sensor per window.
	if p.allowFallback(urgent, now.Add(time.Second)) {
		t.Fatal("the per-sensor bound was bypassed")
	}

	// A sensor already past its deadline (never seen, or offline) is urgent.
	if !p.allowFallback(&sensordom.Sensor{ID: shared.NewID()}, now) {
		t.Fatal("a never-seen sensor was dropped")
	}
}
