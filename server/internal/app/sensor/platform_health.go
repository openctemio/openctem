package sensor

// Platform-health guard for sensor convictions
// (docs/rfcs/RFC-035-sensor-control-plane-under-load.md §5.6.4, owner
// decision D3; Lifeguard's local health awareness).
//
// A platform that cannot process heartbeats must not convict sensors for it.
// The health controller asks the guard each tick whether it may move sensors
// to offline; while the platform itself is degraded it still moves them to
// late and stale (which notify nobody) but holds the offline step, so no
// sensor.offline is sent for an outage that is the platform's own.

import (
	"fmt"
	"slices"
	"sync"
	"time"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// PlatformHealthConfig tunes the guard. Zero values take the defaults.
type PlatformHealthConfig struct {
	// StartupGrace: no offline conviction until the API has run this long, so
	// every sensor has had the chance to heartbeat to the new process.
	// Default: the offline distance of a sensor on the SDK's default
	// interval (sensordom.OfflineDistance(60 s) = 4 min).
	StartupGrace time.Duration
	// SlowHeartbeat: the heartbeat handler's p95 latency over Window at or
	// above this means the platform is slow (SENSOR_HEALTH_SLOW_HEARTBEAT,
	// default 2 s).
	SlowHeartbeat time.Duration
	// Window is how far back heartbeat latencies count (default 2 min).
	Window time.Duration
	// MinSamples: fewer heartbeats than this in Window say nothing about
	// latency (default 5).
	MinSamples int
	// StallFactor: a controller tick that comes more than this many
	// intervals after the previous one means the process was stalled
	// (default 2).
	StallFactor float64
}

// Defaults for PlatformHealthConfig.
const (
	DefaultSlowHeartbeat     = 2 * time.Second
	DefaultHealthWindow      = 2 * time.Minute
	DefaultHealthMinSamples  = 5
	DefaultHealthStallFactor = 2.0
	// maxHeartbeatSamples bounds the latency memory.
	maxHeartbeatSamples = 1024
)

// Normalized fills unset values with the defaults.
func (c PlatformHealthConfig) Normalized() PlatformHealthConfig {
	if c.StartupGrace <= 0 {
		c.StartupGrace = sensordom.OfflineDistance(sensordom.DefaultHeartbeatInterval)
	}
	if c.SlowHeartbeat <= 0 {
		c.SlowHeartbeat = DefaultSlowHeartbeat
	}
	if c.Window <= 0 {
		c.Window = DefaultHealthWindow
	}
	if c.MinSamples <= 0 {
		c.MinSamples = DefaultHealthMinSamples
	}
	if c.StallFactor <= 1 {
		c.StallFactor = DefaultHealthStallFactor
	}
	return c
}

type latencySample struct {
	at time.Time
	d  time.Duration
}

// PlatformHealth is the guard: the heartbeat handlers feed it their latency
// and the health controller consults it. Safe for concurrent use; a nil
// *PlatformHealth never holds anything.
type PlatformHealth struct {
	cfg     PlatformHealthConfig
	started time.Time
	now     func() time.Time

	mu       sync.Mutex
	samples  []latencySample // ring buffer
	next     int
	lastTick time.Time
}

// NewPlatformHealth returns a guard whose process started now.
func NewPlatformHealth(cfg PlatformHealthConfig) *PlatformHealth {
	return newPlatformHealthAt(cfg, time.Now)
}

func newPlatformHealthAt(cfg PlatformHealthConfig, now func() time.Time) *PlatformHealth {
	return &PlatformHealth{cfg: cfg.Normalized(), started: now(), now: now}
}

// NewPlatformHealthForTest returns a guard on a fake clock.
func NewPlatformHealthForTest(cfg PlatformHealthConfig, now func() time.Time) *PlatformHealth {
	return newPlatformHealthAt(cfg, now)
}

// Config returns the effective configuration.
func (p *PlatformHealth) Config() PlatformHealthConfig {
	if p == nil {
		return PlatformHealthConfig{}.Normalized()
	}
	return p.cfg
}

// ObserveHeartbeat records how long one heartbeat took to handle (the write
// and the doorbell query).
func (p *PlatformHealth) ObserveHeartbeat(d time.Duration) {
	if p == nil || d < 0 {
		return
	}
	s := latencySample{at: p.now(), d: d}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.samples) < maxHeartbeatSamples {
		p.samples = append(p.samples, s)
		return
	}
	p.samples[p.next] = s
	p.next = (p.next + 1) % maxHeartbeatSamples
}

// HoldConvictions is asked by the health controller once per tick (interval
// is its tick interval). It returns a reason when no sensor may be moved to
// offline this tick: the API started less than StartupGrace ago, the
// previous tick was more than StallFactor intervals ago (the process was
// stalled), or the heartbeat handler's p95 latency over Window is at or
// above SlowHeartbeat. "" means the platform is healthy.
func (p *PlatformHealth) HoldConvictions(interval time.Duration) string {
	if p == nil {
		return ""
	}
	now := p.now()
	p.mu.Lock()
	defer p.mu.Unlock()

	prev := p.lastTick
	p.lastTick = now

	if up := now.Sub(p.started); up < p.cfg.StartupGrace {
		return fmt.Sprintf("the API started %s ago (startup grace %s)", up.Round(time.Second), p.cfg.StartupGrace)
	}
	if !prev.IsZero() && interval > 0 {
		if gap := now.Sub(prev); float64(gap) > p.cfg.StallFactor*float64(interval) {
			return fmt.Sprintf("the previous health check ran %s ago, expected every %s (the platform was stalled)",
				gap.Round(time.Second), interval)
		}
	}
	if p95, n := p.heartbeatP95Locked(now); n >= p.cfg.MinSamples && p95 >= p.cfg.SlowHeartbeat {
		return fmt.Sprintf("heartbeat handling is slow (p95 %s over %d heartbeats, threshold %s)",
			p95.Round(time.Millisecond), n, p.cfg.SlowHeartbeat)
	}
	return ""
}

// HeartbeatP95 returns the p95 heartbeat latency over Window and the number
// of samples it is computed from.
func (p *PlatformHealth) HeartbeatP95() (time.Duration, int) {
	if p == nil {
		return 0, 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.heartbeatP95Locked(p.now())
}

func (p *PlatformHealth) heartbeatP95Locked(now time.Time) (time.Duration, int) {
	cutoff := now.Add(-p.cfg.Window)
	ds := make([]time.Duration, 0, len(p.samples))
	for _, s := range p.samples {
		if !s.at.Before(cutoff) {
			ds = append(ds, s.d)
		}
	}
	if len(ds) == 0 {
		return 0, 0
	}
	slices.Sort(ds)
	// Nearest-rank p95.
	idx := (95*len(ds) + 99) / 100
	return ds[max(idx-1, 0)], len(ds)
}
