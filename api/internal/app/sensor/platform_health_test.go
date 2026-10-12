package sensor

import (
	"strings"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func newGuard(cfg PlatformHealthConfig) (*PlatformHealth, *fakeClock) {
	c := &fakeClock{t: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	return newPlatformHealthAt(cfg, c.now), c
}

func TestPlatformHealth_Defaults(t *testing.T) {
	c := PlatformHealthConfig{}.Normalized()
	if c.StartupGrace != 4*time.Minute || c.SlowHeartbeat != 2*time.Second || c.Window != 2*time.Minute ||
		c.MinSamples != 5 || c.StallFactor != 2 {
		t.Errorf("defaults = %+v", c)
	}
}

func TestPlatformHealth_StartupGrace(t *testing.T) {
	g, clock := newGuard(PlatformHealthConfig{StartupGrace: time.Minute})
	clock.t = clock.t.Add(59 * time.Second)
	if r := g.HoldConvictions(30 * time.Second); !strings.Contains(r, "started") {
		t.Fatalf("inside the grace: %q", r)
	}
	clock.t = clock.t.Add(2 * time.Second)
	if r := g.HoldConvictions(30 * time.Second); r != "" {
		t.Fatalf("after the grace: %q", r)
	}
}

func TestPlatformHealth_Stall(t *testing.T) {
	g, clock := newGuard(PlatformHealthConfig{StartupGrace: time.Second})
	clock.t = clock.t.Add(time.Minute)
	if r := g.HoldConvictions(30 * time.Second); r != "" {
		t.Fatalf("first tick: %q", r)
	}
	clock.t = clock.t.Add(60 * time.Second) // exactly 2 intervals: fine
	if r := g.HoldConvictions(30 * time.Second); r != "" {
		t.Fatalf("2 intervals: %q", r)
	}
	clock.t = clock.t.Add(61 * time.Second)
	if r := g.HoldConvictions(30 * time.Second); !strings.Contains(r, "stalled") {
		t.Fatalf("stalled tick: %q", r)
	}
	clock.t = clock.t.Add(30 * time.Second)
	if r := g.HoldConvictions(30 * time.Second); r != "" {
		t.Fatalf("next regular tick: %q", r)
	}
}

func TestPlatformHealth_SlowHeartbeats(t *testing.T) {
	g, clock := newGuard(PlatformHealthConfig{StartupGrace: time.Second, SlowHeartbeat: time.Second})
	clock.t = clock.t.Add(time.Minute)

	// Too few samples say nothing.
	for range 4 {
		g.ObserveHeartbeat(5 * time.Second)
	}
	if r := g.HoldConvictions(30 * time.Second); r != "" {
		t.Fatalf("4 samples: %q", r)
	}

	// 95 fast and 5 slow: p95 is fast.
	g2, clock2 := newGuard(PlatformHealthConfig{StartupGrace: time.Second, SlowHeartbeat: time.Second})
	clock2.t = clock2.t.Add(time.Minute)
	for range 95 {
		g2.ObserveHeartbeat(10 * time.Millisecond)
	}
	for range 5 {
		g2.ObserveHeartbeat(5 * time.Second)
	}
	if p95, n := g2.HeartbeatP95(); p95 != 10*time.Millisecond || n != 100 {
		t.Fatalf("p95 = %s over %d", p95, n)
	}
	if r := g2.HoldConvictions(30 * time.Second); r != "" {
		t.Fatalf("5%% slow: %q", r)
	}
	// One more slow sample tips p95 over.
	g2.ObserveHeartbeat(5 * time.Second)
	if r := g2.HoldConvictions(30 * time.Second); !strings.Contains(r, "slow") {
		t.Fatalf("6%% slow: %q", r)
	}

	// Samples older than the window no longer count.
	clock2.t = clock2.t.Add(2*time.Minute + time.Second)
	if p95, n := g2.HeartbeatP95(); n != 0 || p95 != 0 {
		t.Fatalf("aged out: p95 %s over %d", p95, n)
	}
}

func TestPlatformHealth_RingIsBounded(t *testing.T) {
	g, _ := newGuard(PlatformHealthConfig{})
	for range 3 * maxHeartbeatSamples {
		g.ObserveHeartbeat(time.Millisecond)
	}
	if _, n := g.HeartbeatP95(); n != maxHeartbeatSamples {
		t.Fatalf("kept %d samples, want %d", n, maxHeartbeatSamples)
	}
}

func TestPlatformHealth_NilIsHealthy(t *testing.T) {
	var g *PlatformHealth
	g.ObserveHeartbeat(time.Hour)
	if r := g.HoldConvictions(time.Second); r != "" {
		t.Fatalf("nil guard held: %q", r)
	}
}
