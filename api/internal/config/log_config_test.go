package config

import "testing"

func TestLoad_LogLevelAndFormat(t *testing.T) {
	cases := []struct {
		name, appEnv, level, format string
		wantLevel, wantFormat       string
	}{
		{"development defaults", "development", "", "", "debug", "text"},
		{"non-development defaults", "staging", "", "", "info", "json"},
		{"set in development", "development", "info", "json", "info", "json"},
		{"set in another environment", "staging", "warn", "text", "warn", "text"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("APP_ENV", tc.appEnv)
			t.Setenv("LOG_LEVEL", tc.level)
			t.Setenv("LOG_FORMAT", tc.format)
			// Outside development, Load requires a real encryption key.
			t.Setenv("APP_ENCRYPTION_KEY", "9f2c4e6a8b0d1f3e5a7c9b1d3f5e7a9c0b2d4f6e8a1c3e5b7d9f0a2c4e6b8d0f")
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Log.Level != tc.wantLevel || cfg.Log.Format != tc.wantFormat {
				t.Errorf("level=%q format=%q, want %q %q", cfg.Log.Level, cfg.Log.Format, tc.wantLevel, tc.wantFormat)
			}
		})
	}
}
