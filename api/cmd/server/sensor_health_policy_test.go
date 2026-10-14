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
	if p.OnlineWindow != 72*time.Second {
		t.Errorf("online window = %s, want the 1m interval plus its 12s grace", p.OnlineWindow)
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

func TestCollectorInstallImage(t *testing.T) {
	for in, want := range map[string]string{
		"ghcr.io/openctemio/asset-collector:v0.2.0": "ghcr.io/openctemio/asset-collector:v0.2.0",
		"registry.local:5000/sec/collector:v1":      "registry.local:5000/sec/collector:v1",
		// Not an image reference (would land in a shell line): the default.
		"evil; rm -rf /":       config.DefaultCollectorImage,
		"":                     config.DefaultCollectorImage,
		"ghcr.io/x@sha256:abc": config.DefaultCollectorImage,
	} {
		cfg := &config.Config{}
		cfg.SensorConfig.CollectorImage = in
		if got := collectorInstallImage(cfg, logger.NewNop()); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

// CI runners are judged against their own release settings, never the
// sensor's: the sensor minimum (v0.9.0) is above every CI runner release.
func TestCIRunnerVersionPolicy_FromConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.SensorConfig.LatestVersion, cfg.SensorConfig.MinVersion = "v0.21.1", "v0.9.0"
	cfg.SensorConfig.CIRunnerLatestVersion = "0.2.0"
	cfg.SensorConfig.CIRunnerMinVersion = "latest" // not a version: ignored with a warning
	p := ciRunnerVersionPolicy(cfg, logger.NewNop())
	if p.LatestVersion != "v0.2.0" || p.MinVersion != "" {
		t.Fatalf("CI runner policy = %+v, want latest v0.2.0 and no minimum", p)
	}
	cfg.SensorConfig.CIRunnerMinVersion = "v0.3.0"
	if p := ciRunnerVersionPolicy(cfg, logger.NewNop()); p.MinVersion != "v0.3.0" {
		t.Fatalf("CI runner minimum = %q", p.MinVersion)
	}
	cfg.SensorConfig.CIRunnerLatestVersion, cfg.SensorConfig.CIRunnerMinVersion = "", ""
	if p := ciRunnerVersionPolicy(cfg, logger.NewNop()); p.LatestVersion != "" || p.MinVersion != "" {
		t.Fatalf("CI runner settings off, policy = %+v: the sensor settings leaked in", p)
	}
}
