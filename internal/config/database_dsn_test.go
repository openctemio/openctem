package config

import (
	"strings"
	"testing"
)

func TestDatabaseDSN_JITOffByDefault(t *testing.T) {
	c := DatabaseConfig{Host: "h", Port: 5432, User: "u", Password: "p", Name: "n", SSLMode: "disable"}
	if !strings.HasSuffix(c.DSN(), " jit=off") {
		t.Fatalf("JIT must be disabled per session by default, got %q", c.DSN())
	}

	c.JITEnabled = true
	if strings.Contains(c.DSN(), "jit=") {
		t.Fatalf("DB_JIT_ENABLED=true must leave the server default, got %q", c.DSN())
	}
}
