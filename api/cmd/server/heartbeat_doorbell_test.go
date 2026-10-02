package main

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
)

// No advised heartbeat interval reaches half of the health controller's
// offline mark: with the defaults the "loaded" advice (120 s) used to
// outlast the 90 s mark, so every sensor that followed it was marked offline
// once per cycle (RFC-035 B1, decision D2).
func TestHeartbeatDoorbellConfig_AdviceStaysInsideTheOfflineMark(t *testing.T) {
	cfg := &config.Config{}
	cfg.SensorConfig.HeartbeatInterval = 30 * time.Second
	cfg.SensorConfig.HeartbeatBusyInterval = 5 * time.Second
	cfg.SensorConfig.HeartbeatLoadedInterval = 2 * time.Minute
	cfg.SensorConfig.HeartbeatMinInterval = 5 * time.Second
	cfg.SensorConfig.HeartbeatMaxInterval = 5 * time.Minute
	cfg.Worker.HeartbeatTimeout = 5 * time.Minute

	c := heartbeatDoorbellConfig(cfg)
	if c.MaxInterval != sensorStaleTimeout/2 {
		t.Fatalf("MaxInterval = %s, want %s (half of the %s offline mark)", c.MaxInterval, sensorStaleTimeout/2, sensorStaleTimeout)
	}
	for name, d := range map[string]time.Duration{"idle": c.IdleInterval, "busy": c.BusyInterval, "loaded": c.LoadedInterval} {
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
