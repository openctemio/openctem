package main

import (
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/versions"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestSensorHealthPolicy_FromConfig(t *testing.T) {
	cfg := &config.Config{}
	cfg.Worker.HeartbeatTimeout = 10 * time.Minute
	cfg.SensorConfig.HeartbeatInterval = time.Minute

	p := sensorHealthPolicy(cfg)
	if p.OfflineAfter != 10*time.Minute {
		t.Errorf("offline after = %s, want the heartbeat timeout", p.OfflineAfter)
	}
	if p.OnlineWindow != 72*time.Second {
		t.Errorf("online window = %s, want the 1m interval plus its 12s grace", p.OnlineWindow)
	}
	// Every catalog product has its own release line, from versions.yaml.
	for _, prod := range versions.Products() {
		if l, ok := p.ReleaseLineFor(prod.ID); !ok || l.Latest != prod.Latest || l.Min != prod.Min {
			t.Errorf("%s: line = %+v (known %v), want %s / %q", prod.ID, l, ok, prod.Latest, prod.Min)
		}
	}
	if p.SDKLatestVersion != versions.SDKLatest() {
		t.Errorf("sdk latest = %q", p.SDKLatestVersion)
	}
}

// The install snippets of every product pin its latest release; SENSOR_IMAGE
// replaces only the scanning sensor's repository (a mirror).
func TestSensorInstallProducts(t *testing.T) {
	sensorImage := func(image string) (scanner, others map[string]string) {
		cfg := &config.Config{}
		cfg.SensorConfig.Image = image
		others = map[string]string{}
		for _, p := range sensorInstallProducts(cfg, logger.NewNop()) {
			if p.ID == versions.DefaultProductID {
				scanner = map[string]string{"image": p.Image}
			} else {
				others[p.ID] = p.Image
			}
		}
		return scanner, others
	}
	latest := versions.SensorLatest()
	published := versions.SensorImage() + ":" + latest
	for image, want := range map[string]string{
		"":                                 published,
		versions.SensorImage():             published,
		"registry.local:5000/sec/sensor":   "registry.local:5000/sec/sensor:" + latest,
		"ghcr.io/openctemio/sensor:latest": "ghcr.io/openctemio/sensor:" + latest, // the tag is the release's
		// Not an image reference (would land in a shell line): the default.
		"evil; rm -rf /":       published,
		"ghcr.io/x@sha256:abc": published,
	} {
		scanner, others := sensorImage(image)
		if scanner["image"] != want {
			t.Errorf("SENSOR_IMAGE %q -> %q, want %q", image, scanner["image"], want)
		}
		for id, img := range others {
			p, _ := versions.LookupProduct(id)
			if img != p.ImageRef() {
				t.Errorf("SENSOR_IMAGE %q changed %s's image to %q", image, id, img)
			}
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
