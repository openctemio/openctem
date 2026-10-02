package config

import (
	"os"
	"testing"
	"time"
)

// RFC-032 Phase 0: renewed sensor keys expire after 90 days by default; "0"
// keeps them non-expiring.
func TestLoad_SensorKeyTTL(t *testing.T) {
	cases := map[string]time.Duration{
		"":     90 * 24 * time.Hour,
		"720h": 30 * 24 * time.Hour,
		"0":    0,
		"oops": 90 * 24 * time.Hour, // unparseable: the default
	}
	for env, want := range cases {
		t.Setenv("SENSOR_KEY_TTL", env)
		t.Setenv("AGENT_KEY_TTL", "")
		_ = os.Unsetenv("AGENT_KEY_TTL") // restored by t.Setenv's cleanup
		cfg, err := Load()
		if err != nil {
			t.Fatalf("SENSOR_KEY_TTL=%q: Load: %v", env, err)
		}
		if cfg.SensorConfig.KeyTTL != want {
			t.Errorf("SENSOR_KEY_TTL=%q: KeyTTL = %v, want %v", env, cfg.SensorConfig.KeyTTL, want)
		}
	}
}
