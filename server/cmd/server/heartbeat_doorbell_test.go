package main

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/domain/command"
)

// No advised heartbeat interval reaches half of the health controller's
// offline mark: with the defaults the "loaded" advice (120 s) used to
// outlast the 90 s mark, so every sensor that followed it was marked offline
// once per cycle (RFC-035 B1, decision D2).
func TestHeartbeatDoorbellConfig_AdviceStaysInsideTheOfflineMark(t *testing.T) {
	cfg := &config.Config{}
	cfg.SensorConfig.HeartbeatInterval = 30 * time.Second
	cfg.SensorConfig.HeartbeatBusyInterval = 5 * time.Second
	cfg.SensorConfig.HeartbeatMinInterval = 5 * time.Second
	cfg.SensorConfig.HeartbeatMaxInterval = 5 * time.Minute
	cfg.SensorConfig.CommandLease = 3 * time.Minute
	cfg.Worker.HeartbeatTimeout = 5 * time.Minute

	c := heartbeatDoorbellConfig(cfg)
	if c.MaxInterval != sensorStaleTimeout/2 {
		t.Fatalf("MaxInterval = %s, want %s (half of the %s offline mark)", c.MaxInterval, sensorStaleTimeout/2, sensorStaleTimeout)
	}
	for name, d := range map[string]time.Duration{"idle": c.IdleInterval, "busy": c.BusyInterval, "max": c.MaxInterval} {
		if adv := min(max(d, c.MinInterval), c.MaxInterval); adv*2 > sensorStaleTimeout {
			t.Errorf("%s advice %s: two of them outlast the %s offline mark", name, adv, sensorStaleTimeout)
		}
	}

	// A shorter WORKER_HEARTBEAT_TIMEOUT bounds it further.
	cfg.Worker.HeartbeatTimeout = time.Minute
	if c := heartbeatDoorbellConfig(cfg); c.MaxInterval != 30*time.Second {
		t.Fatalf("with a 1m timeout MaxInterval = %s, want 30s", c.MaxInterval)
	}
}

// The maximum interval is derived from the command lease too: raising the
// offline mark, the configured maximum or the lease never lets the doorbell
// advise more than a third of the lease the command repository applies
// (after its own 1m-30m clamp), so a running command is never re-queued
// between two heartbeats (RFC-074).
func TestHeartbeatDoorbellConfig_MaxIntervalFollowsTheLease(t *testing.T) {
	for _, lease := range []time.Duration{0, time.Second, time.Minute, 3 * time.Minute, 30 * time.Minute, 24 * time.Hour} {
		for _, timeout := range []time.Duration{0, time.Minute, 5 * time.Minute, time.Hour} {
			cfg := &config.Config{}
			cfg.SensorConfig.HeartbeatInterval = time.Hour
			cfg.SensorConfig.HeartbeatBusyInterval = time.Hour
			cfg.SensorConfig.HeartbeatMinInterval = time.Hour
			cfg.SensorConfig.HeartbeatMaxInterval = 24 * time.Hour
			cfg.SensorConfig.CommandLease = lease
			cfg.Worker.HeartbeatTimeout = timeout

			c := heartbeatDoorbellConfig(cfg)
			applied := command.ClampLeaseDuration(lease)
			if c.MaxInterval > applied/3 || c.MinInterval > c.MaxInterval {
				t.Fatalf("lease %s (applied %s), timeout %s: min %s max %s, want max <= %s",
					lease, applied, timeout, c.MinInterval, c.MaxInterval, applied/3)
			}
			if c.MaxInterval > offlineMark(timeout)/2 {
				t.Fatalf("lease %s, timeout %s: max %s above half the offline mark", lease, timeout, c.MaxInterval)
			}
		}
	}

	// The 1m lease floor binds below the 90 s offline mark: 20 s.
	cfg := &config.Config{}
	cfg.SensorConfig.CommandLease = time.Minute
	if c := heartbeatDoorbellConfig(cfg); c.MaxInterval != 20*time.Second {
		t.Fatalf("with a 1m lease MaxInterval = %s, want 20s", c.MaxInterval)
	}
}
