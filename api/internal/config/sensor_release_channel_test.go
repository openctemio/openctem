package config

import "testing"

func TestLoad_SensorReleaseChannel(t *testing.T) {
	t.Run("defaults: latest and minimum are the compiled-in versions.yaml values", func(t *testing.T) {
		t.Setenv("SENSOR_LATEST_VERSION", "")
		t.Setenv("SENSOR_MIN_VERSION", "")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.SensorConfig.LatestVersion != DefaultSensorLatestVersion || cfg.SensorConfig.MinVersion != DefaultSensorMinVersion {
			t.Errorf("latest=%q min=%q", cfg.SensorConfig.LatestVersion, cfg.SensorConfig.MinVersion)
		}
	})
	t.Run("defaults: the SDK policy comes from versions.yaml too", func(t *testing.T) {
		t.Setenv("SENSOR_SDK_LATEST_VERSION", "")
		t.Setenv("SENSOR_SDK_MIN_VERSION", "")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.SensorConfig.SDKLatestVersion != DefaultSensorSDKLatestVersion ||
			cfg.SensorConfig.SDKMinVersion != DefaultSensorSDKMinVersion {
			t.Errorf("sdk latest=%q min=%q", cfg.SensorConfig.SDKLatestVersion, cfg.SensorConfig.SDKMinVersion)
		}
	})
	t.Run("set from the environment", func(t *testing.T) {
		t.Setenv("SENSOR_LATEST_VERSION", "v0.5.0")
		t.Setenv("SENSOR_MIN_VERSION", " 0.4.0 ")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.SensorConfig.LatestVersion != "v0.5.0" || cfg.SensorConfig.MinVersion != "0.4.0" {
			t.Errorf("latest=%q min=%q", cfg.SensorConfig.LatestVersion, cfg.SensorConfig.MinVersion)
		}
	})
	t.Run("none turns the default off", func(t *testing.T) {
		t.Setenv("SENSOR_LATEST_VERSION", "none")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.SensorConfig.LatestVersion != "" {
			t.Errorf("latest=%q, want empty", cfg.SensorConfig.LatestVersion)
		}
	})
}
