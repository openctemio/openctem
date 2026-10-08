package config

import (
	"strings"
	"testing"
)

// An unset APP_ENV must not mean development: an image started without
// configuration has to get every production check, and refuse to start
// without real secrets, instead of running with development defaults.
func TestLoad_UnsetAppEnvIsProduction(t *testing.T) {
	t.Setenv("APP_ENV", "")
	t.Setenv("AUTH_PROVIDER", "")
	t.Setenv("AUTH_JWT_SECRET", "")
	t.Setenv("APP_ENCRYPTION_KEY", "")
	if appEnv() != EnvProduction {
		t.Fatalf("default APP_ENV = %q, want production", appEnv())
	}
	if _, err := Load(); err == nil {
		t.Fatal("Load succeeded with no secrets and APP_ENV unset; want a refusal")
	}
}

func TestLoad_DefaultAuthProviderIsLocal(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("AUTH_PROVIDER", "")
	t.Setenv("AUTH_JWT_SECRET", strings.Repeat("a", 64))
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.Provider != AuthProviderLocal {
		t.Fatalf("default AUTH_PROVIDER = %q, want local", cfg.Auth.Provider)
	}
}

func TestIsPlaceholderSecret(t *testing.T) {
	for _, v := range []string{
		"openssl rand -hex 32",
		"<CHANGE_ME_GENERATE_WITH_OPENSSL>",
		"<CHANGE_ME_MIN_32_CHARS>",
		"your-super-secret-key-at-least-64-characters-long-for-production",
		"# openssl rand -hex 24",
		"changeme",
	} {
		if !isPlaceholderSecret(v) {
			t.Errorf("isPlaceholderSecret(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"", strings.Repeat("ab", 32), "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"} {
		if isPlaceholderSecret(v) {
			t.Errorf("isPlaceholderSecret(%q) = true, want false", v)
		}
	}
}

// The example file's literal must fail with a message naming the variable and
// the fix, in every environment (development included), and never echo it.
func TestLoad_PlaceholderSecretRefusedWithClearMessage(t *testing.T) {
	for _, env := range []string{"development", "production"} {
		t.Run(env, func(t *testing.T) {
			t.Setenv("APP_ENV", env)
			t.Setenv("AUTH_PROVIDER", "local")
			t.Setenv("AUTH_JWT_SECRET", strings.Repeat("a", 64))
			t.Setenv("APP_ENCRYPTION_KEY", "openssl rand -hex 32")
			_, err := Load()
			if err == nil {
				t.Fatal("Load accepted APP_ENCRYPTION_KEY=\"openssl rand -hex 32\"")
			}
			msg := err.Error()
			if !strings.Contains(msg, "APP_ENCRYPTION_KEY") || !strings.Contains(msg, "placeholder") {
				t.Fatalf("error %q does not say which variable holds a placeholder", msg)
			}
			if strings.Contains(msg, "openssl rand -hex 32\"") {
				t.Fatalf("error echoes the value: %q", msg)
			}
		})
	}
}
