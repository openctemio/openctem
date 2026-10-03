package config

import "testing"

// The legacy sensor health checker ignores the health controller's startup
// grace and convicts every sensor right after an API restart
// (internal/infra/jobs/sensor_health_checker_grace_db_test.go). It is off
// unless WORKER_HEALTH_CHECK_ENABLED turns it on.
func TestLoad_LegacySensorHealthCheckerOffByDefault(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("WORKER_HEALTH_CHECK_ENABLED", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Worker.Enabled {
		t.Fatal("WORKER_HEALTH_CHECK_ENABLED defaults to true; want false")
	}

	t.Setenv("WORKER_HEALTH_CHECK_ENABLED", "true")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Worker.Enabled {
		t.Fatal("WORKER_HEALTH_CHECK_ENABLED=true did not enable the legacy checker")
	}
}
