package main

import (
	"testing"
	"time"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/logger"
)

func TestSensorHealthPolicy_FromConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Worker.HeartbeatTimeout = 10 * time.Minute
	cfg.SensorConfig.HeartbeatInterval = time.Minute
	cfg.SensorConfig.LatestVersion = "0.4.2"
	cfg.SensorConfig.MinVersion = "latest" // not a version: ignored with a warning

	p := sensorHealthPolicy(cfg, logger.NewNop())
	if p.OfflineAfter != 10*time.Minute {
		t.Errorf("offline after = %s, want the heartbeat timeout", p.OfflineAfter)
	}
	if p.OnlineWindow != 3*time.Minute {
		t.Errorf("online window = %s, want three 1m heartbeats", p.OnlineWindow)
	}
	if p.LatestVersion != "v0.4.2" || p.MinVersion != "" {
		t.Errorf("channel = %q / %q", p.LatestVersion, p.MinVersion)
	}
}
