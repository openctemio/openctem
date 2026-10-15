package config

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/versions"
)

// The sensor products' release lines are not settings: they come from the
// version manifest built into the API. The old sensor-wide channel
// variables are refused, so an operator never believes one still applies.
func TestLoad_SensorReleaseChannelRetired(t *testing.T) {
	for _, name := range []string{"SENSOR_LATEST_VERSION", "SENSOR_MIN_VERSION", "SENSOR_SDK_LATEST_VERSION", "SENSOR_SDK_MIN_VERSION"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "v0.5.0")
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("Load with %s set: err = %v, want it refused by name", name, err)
			}
		})
	}
}

// CI runner versions keep their environment overrides; their defaults come
// from the embedded versions.yaml.
func TestLoad_CIRunnerVersionDefaultsAndOverrides(t *testing.T) {
	t.Run("defaults are versions.yaml ci.latest and ci.min", func(t *testing.T) {
		t.Setenv("CI_RUNNER_LATEST_VERSION", "")
		t.Setenv("CI_RUNNER_MIN_VERSION", "")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.SensorConfig.CIRunnerLatestVersion != versions.CIRunnerLatest() ||
			cfg.SensorConfig.CIRunnerMinVersion != versions.CIRunnerMin() {
			t.Errorf("ci latest=%q min=%q", cfg.SensorConfig.CIRunnerLatestVersion, cfg.SensorConfig.CIRunnerMinVersion)
		}
	})
	t.Run("the environment wins", func(t *testing.T) {
		t.Setenv("CI_RUNNER_LATEST_VERSION", "v9.0.0")
		t.Setenv("CI_RUNNER_MIN_VERSION", "none")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.SensorConfig.CIRunnerLatestVersion != "v9.0.0" || cfg.SensorConfig.CIRunnerMinVersion != "" {
			t.Errorf("ci latest=%q min=%q", cfg.SensorConfig.CIRunnerLatestVersion, cfg.SensorConfig.CIRunnerMinVersion)
		}
	})
	t.Run("SENSOR_IMAGE defaults to the catalog's scanning sensor image", func(t *testing.T) {
		t.Setenv("SENSOR_IMAGE", "")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.SensorConfig.Image != versions.SensorImage() {
			t.Errorf("image = %q", cfg.SensorConfig.Image)
		}
	})
}
