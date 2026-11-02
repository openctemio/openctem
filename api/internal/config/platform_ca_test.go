package config

import (
	"slices"
	"strings"
	"testing"
)

// PLATFORM_CA_CERT_FILE is the platform's CA file; the API's earlier name
// SENSOR_CA_CERT_FILE is still read when it is unset, with a warning.
func TestLoad_PlatformCACertFile(t *testing.T) {
	deprecated := func(w []string) bool {
		return slices.ContainsFunc(w, func(s string) bool { return strings.Contains(s, "SENSOR_CA_CERT_FILE is deprecated") })
	}
	cases := []struct {
		name, platform, legacy, want string
		warn                         bool
	}{
		{"unset", "", "", "", false},
		{"new name", "/ca/root.crt", "", "/ca/root.crt", false},
		{"deprecated name", "", "/ca/old.crt", "/ca/old.crt", true},
		{"new name wins", "/ca/root.crt", "/ca/old.crt", "/ca/root.crt", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			devEnv(t)
			t.Setenv("PLATFORM_CA_CERT_FILE", c.platform)
			t.Setenv("SENSOR_CA_CERT_FILE", c.legacy)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.SensorConfig.CACertFile != c.want {
				t.Errorf("CACertFile = %q, want %q", cfg.SensorConfig.CACertFile, c.want)
			}
			if deprecated(cfg.EnvWarnings) != c.warn {
				t.Errorf("warnings = %v, want deprecation warning %v", cfg.EnvWarnings, c.warn)
			}
		})
	}
}
