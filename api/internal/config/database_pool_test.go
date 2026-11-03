package config

import (
	"strings"
	"testing"
)

// The pool keeps as many idle connections as it may open unless told
// otherwise. With fewer idle than open, every burst of concurrent requests
// closed the extra connections and reopened them on the next burst.
func TestLoad_IdleConnectionsDefaultToOpenLimit(t *testing.T) {
	for _, tc := range []struct {
		name, open, idle   string
		wantOpen, wantIdle int
	}{
		{"defaults", "", "", 25, 25},
		{"idle follows a raised open limit", "40", "", 40, 40},
		{"explicit idle wins", "40", "3", 40, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("APP_ENV", "development")
			t.Setenv("AUTH_PROVIDER", "")
			t.Setenv("AUTH_JWT_SECRET", strings.Repeat("a", 64))
			t.Setenv("DB_MAX_OPEN_CONNS", tc.open)
			t.Setenv("DB_MAX_IDLE_CONNS", tc.idle)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Database.MaxOpenConns != tc.wantOpen || cfg.Database.MaxIdleConns != tc.wantIdle {
				t.Fatalf("open/idle = %d/%d, want %d/%d", cfg.Database.MaxOpenConns,
					cfg.Database.MaxIdleConns, tc.wantOpen, tc.wantIdle)
			}
		})
	}
}
