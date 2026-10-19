package sensor

import (
	"context"
	"testing"
	"time"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Waiting work rings the sensor again soon only when it has room for it and
// no control stream would wake it: a full sensor, or one on the gRPC
// binding, keeps the idle interval.
func TestDoorbell_BusyOnlyWithFreeSlotsAndNoStream(t *testing.T) {
	src := &fakeWork{work: sensordom.PendingWork{Count: 3}}
	d := newTestDoorbell(src)
	cases := []struct {
		name string
		req  DoorbellRequest
		want int
	}{
		{"free slots, v2", DoorbellRequest{Aware: true}, 5},
		{"no free slots", DoorbellRequest{Aware: true, NoFreeSlots: true}, 30},
		{"streaming", DoorbellRequest{Aware: true, Streaming: true}, 30},
	}
	for _, c := range cases {
		c.req.Identity = SensorIdentity{Sensor: testSensor()}
		if h := d.Ring(context.Background(), c.req); h.NextHeartbeatSeconds != c.want || h.PendingJobs != 3 {
			t.Errorf("%s: next=%d pending=%d, want next=%d pending=3", c.name, h.NextHeartbeatSeconds, h.PendingJobs, c.want)
		}
	}
	// A canceled command still rings soon (the cancel must arrive quickly).
	src.work = sensordom.PendingWork{RecentlyCanceled: 1}
	h := d.Ring(context.Background(), DoorbellRequest{Aware: true, Streaming: true, NoFreeSlots: true, Identity: SensorIdentity{Sensor: testSensor()}})
	if h.NextHeartbeatSeconds != 5 {
		t.Errorf("recently canceled: next=%d, want 5", h.NextHeartbeatSeconds)
	}
}

// The idle interval stretches with the live fleet, inside the safe maximum.
func TestDoorbell_IdleFollowsFleetSize(t *testing.T) {
	cfg := DefaultDoorbellConfig().Normalized(5*time.Minute, 3*time.Minute) // max = lease/3 = 60 s
	for _, c := range []struct {
		fleet int64
		want  int
	}{
		{100, 30},    // 100 / 50 = 2 s: the configured 30 s stands
		{2000, 40},   // 2000 / 50 = 40 s
		{100000, 60}, // capped at the derived maximum
	} {
		d := NewDoorbell(&fakeWork{}, cfg, logger.NewNop())
		n := c.fleet
		d.SetFleetSize(func(context.Context) (int64, error) { return n, nil }, nil)
		h := d.Ring(context.Background(), DoorbellRequest{Aware: true, Identity: SensorIdentity{Sensor: testSensor()}})
		if h.NextHeartbeatSeconds != c.want {
			t.Errorf("fleet %d: next=%d, want %d", c.fleet, h.NextHeartbeatSeconds, c.want)
		}
	}
	// More replicas share the budget.
	d := NewDoorbell(&fakeWork{}, cfg, logger.NewNop())
	d.SetFleetSize(func(context.Context) (int64, error) { return 2000, nil }, func() int { return 2 })
	if h := d.Ring(context.Background(), DoorbellRequest{Aware: true, Identity: SensorIdentity{Sensor: testSensor()}}); h.NextHeartbeatSeconds != 30 {
		t.Errorf("2000 sensors on 2 replicas: next=%d, want 30", h.NextHeartbeatSeconds)
	}
}

// Jitter spreads the advice by at most ±10 % and never past the maximum.
func TestDoorbell_JitterBounded(t *testing.T) {
	cfg := DefaultDoorbellConfig().Normalized(5*time.Minute, 3*time.Minute)
	d := NewDoorbell(&fakeWork{}, cfg, logger.NewNop())
	d.SetJitter(0.10)
	seen := map[int]bool{}
	for i := 0; i < 500; i++ {
		h := d.Ring(context.Background(), DoorbellRequest{Aware: true, Identity: SensorIdentity{Sensor: testSensor()}})
		if h.NextHeartbeatSeconds < 27 || h.NextHeartbeatSeconds > 33 {
			t.Fatalf("jittered idle interval %d outside 30 s ±10 %%", h.NextHeartbeatSeconds)
		}
		seen[h.NextHeartbeatSeconds] = true
	}
	if len(seen) < 3 {
		t.Fatalf("jitter produced only %v", seen)
	}
	d.SetFleetSize(func(context.Context) (int64, error) { return 1_000_000, nil }, nil)
	for i := 0; i < 200; i++ {
		h := d.Ring(context.Background(), DoorbellRequest{Aware: true, Identity: SensorIdentity{Sensor: testSensor()}})
		if time.Duration(h.NextHeartbeatSeconds)*time.Second > cfg.MaxInterval {
			t.Fatalf("jitter crossed the maximum: %d s > %s", h.NextHeartbeatSeconds, cfg.MaxInterval)
		}
	}
}
