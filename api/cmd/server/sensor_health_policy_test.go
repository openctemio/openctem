package main

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/logger"
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

func TestSensorInstallImage(t *testing.T) {
	cases := []struct{ image, latest, want string }{
		{"ghcr.io/openctemio/sensor", "v0.4.2", "ghcr.io/openctemio/sensor:v0.4.2"},
		{"registry.local:5000/sec/sensor", "0.5.0", "registry.local:5000/sec/sensor:v0.5.0"},
		// A tag in SENSOR_IMAGE is replaced by the channel's.
		{"ghcr.io/openctemio/sensor:latest", "v0.4.2", "ghcr.io/openctemio/sensor:v0.4.2"},
		// Channel off: the compiled-in release, never "latest".
		{"ghcr.io/openctemio/sensor", "", "ghcr.io/openctemio/sensor:" + config.DefaultSensorLatestVersion},
		// Not an image reference (would land in a shell line): the default.
		{"evil; rm -rf /", "v0.4.2", config.DefaultSensorImageRepository + ":v0.4.2"},
		{"", "v0.4.2", config.DefaultSensorImageRepository + ":v0.4.2"},
	}
	for _, c := range cases {
		cfg := &config.Config{}
		cfg.SensorConfig.Image, cfg.SensorConfig.LatestVersion = c.image, c.latest
		if got := sensorInstallImage(cfg, logger.NewNop()); got != c.want {
			t.Errorf("image %q latest %q -> %q, want %q", c.image, c.latest, got, c.want)
		}
	}
}
