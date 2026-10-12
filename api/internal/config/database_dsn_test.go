package config

import (
	"strings"
	"testing"

	"github.com/lib/pq"
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

// Every value must reach the driver as written. Unquoted, an empty password
// (trust or peer auth) made lib/pq read "dbname=app_test" as the password and
// connect to the default database (named after the user) instead.
func TestDatabaseDSN_ValuesSurviveParsing(t *testing.T) {
	for _, tc := range []struct{ name, password, database string }{
		{"empty password", "", "app_test"},
		{"password with a space", "pass word", "app_test"},
		{"password with quote and backslash", `it's\here`, "app_test"},
		{"password that looks like a key", "dbname=other", "app_test"},
		{"database with a space", "p", "my db"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := DatabaseConfig{
				Host: "localhost", Port: 5433, User: "openctem",
				Password: tc.password, Name: tc.database, SSLMode: "disable",
			}
			got, err := pq.NewConfig(c.DSN())
			if err != nil {
				t.Fatalf("lib/pq rejected the DSN: %v", err)
			}
			if got.Password != tc.password {
				t.Errorf("password: got %q, want %q", got.Password, tc.password)
			}
			if got.Database != tc.database {
				t.Errorf("database: got %q, want %q", got.Database, tc.database)
			}
			if got.User != "openctem" || got.Host != "localhost" || got.Port != 5433 {
				t.Errorf("user/host/port: got %q %q %d", got.User, got.Host, got.Port)
			}
			if got.Runtime["jit"] != "off" {
				t.Errorf("jit: got %q, want off", got.Runtime["jit"])
			}
		})
	}
}
