package main

import (
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
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
	// Release lines and the latest SDK are resolved per request by the
	// handler (they follow the release feed), never fixed here.
	if len(p.Products) != 0 || p.SDKLatestVersion != "" {
		t.Errorf("start-up policy fixes release lines: %+v / %q", p.Products, p.SDKLatestVersion)
	}
	if len(p.SDKAdvisories) != len(versions.SDKAdvisories()) {
		t.Errorf("sdk advisories = %v", p.SDKAdvisories)
	}
}

// The install snippets of every product pin its latest release; SENSOR_IMAGE
// replaces only the scanning sensor's repository (a mirror).
func TestSensorInstallProducts(t *testing.T) {
	sensorImage := func(image string) (scanner, others map[string]string) {
		cfg := &config.Config{}
		cfg.SensorConfig.Image = image
		others = map[string]string{}
		for _, p := range sensorInstallProducts(cfg, logger.NewNop())() {
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

// A release learned from the release feed reaches the mirror's snippets too,
// by tag only (a mirrored image may have another digest); the published
// repository gets tag and digest.
func TestSensorInstallProducts_LearnedRelease(t *testing.T) {
	t.Cleanup(func() { versions.SetLearned(nil) })
	digest := "sha256:" + strings.Repeat("ef", 32)
	mirror := &config.Config{}
	mirror.SensorConfig.Image = "registry.local:5000/sec/sensor"
	mirrorSrc := sensorInstallProducts(mirror, logger.NewNop())
	publishedSrc := sensorInstallProducts(&config.Config{}, logger.NewNop())

	versions.SetLearned(map[string]versions.Learned{"sensor": {Version: "v99.3.0", Digest: digest}})
	image := func(ps []handler.SensorInstallProduct) string {
		for _, p := range ps {
			if p.ID == versions.DefaultProductID {
				return p.Image
			}
		}
		return ""
	}
	if got := image(mirrorSrc()); got != "registry.local:5000/sec/sensor:v99.3.0" {
		t.Errorf("mirror image = %q", got)
	}
	if got := image(publishedSrc()); got != versions.SensorImage()+":v99.3.0@"+digest {
		t.Errorf("published image = %q", got)
	}
}
