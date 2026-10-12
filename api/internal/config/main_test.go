package config

import (
	"os"
	"testing"
)

// TestMain gives the package tests a development environment with a local
// JWT secret, so a test about one setting does not have to satisfy every
// production check that an unset APP_ENV now applies. Tests about the
// defaults themselves (production_default_test.go) override both.
func TestMain(m *testing.M) {
	setDefault := func(k, v string) {
		if os.Getenv(k) == "" {
			_ = os.Setenv(k, v)
		}
	}
	setDefault("APP_ENV", envDevelopment)
	setDefault("AUTH_JWT_SECRET", "config-package-test-secret-0123456789abcdef0123456789abcdef0123")
	os.Exit(m.Run())
}
