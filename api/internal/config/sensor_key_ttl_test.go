package config

import (
	"os"
	"strings"
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

// An unparseable TTL ("30d" is not a Go duration) is refused at startup
// rather than silently replaced with the 90-day default.
func TestLoad_SensorKeyTTLUnparseableRefused(t *testing.T) {
	for _, bad := range []string{"oops", "30d"} {
		t.Setenv("SENSOR_KEY_TTL", bad)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SENSOR_KEY_TTL is not a duration") {
			t.Errorf("SENSOR_KEY_TTL=%q: err = %v, want a refusal naming it", bad, err)
		}
	}
}
