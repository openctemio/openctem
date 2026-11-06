package postgres

import (
	"context"
	"net/url"
	"strconv"
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/testdb"
)

// The jit=off DSN key must actually reach the server as a session setting
// (lib/pq forwards unknown keys as startup parameters).
func TestNew_DisablesJITForSessions(t *testing.T) {
	raw := testdb.URL()
	if raw == "" {
		t.Skip("DATABASE_URL not set; skipping JIT session test")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Skipf("parse DATABASE_URL: %v", err)
	}
	port, _ := strconv.Atoi(u.Port())
	pw, _ := u.User.Password()
	cfg := &config.DatabaseConfig{
		Host: u.Hostname(), Port: port, User: u.User.Username(), Password: pw,
		Name: u.Path[1:], SSLMode: u.Query().Get("sslmode"),
		MaxOpenConns: 2, MaxIdleConns: 1,
	}
	if cfg.SSLMode == "" {
		cfg.SSLMode = "disable"
	}

	// DATABASE_URL is set and reachable here (testdb guarded it), so a
	// failure is New's: skipping hid an empty password breaking the DSN.
	db, err := New(cfg)
	if err != nil {
		t.Fatalf("cannot connect through New: %v", err)
	}
	defer db.Close()

	var jit string
	if err := db.QueryRowContext(context.Background(), "SHOW jit").Scan(&jit); err != nil {
		t.Fatalf("SHOW jit: %v", err)
	}
	if jit != "off" {
		t.Fatalf("expected jit=off on API sessions, got %q", jit)
	}
}
