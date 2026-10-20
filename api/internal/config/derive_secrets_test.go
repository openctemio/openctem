package config

import (
	"strings"
	"testing"
)

const testEncKey = "9f2c4e6a8b0d1f3e5a7c9b1d3f5e7a9c0b2d4f6e8a1c3e5b7d9f0a2c4e6b8d0f"

// With APP_ENCRYPTION_KEY alone, production starts: the session secret and
// the OAuth state secret are derived, long enough for production, distinct
// from each other and from the key, and stable across starts.
func TestLoad_DerivesSessionAndOAuthStateSecrets(t *testing.T) {
	prodEnv(t)
	t.Setenv("AUTH_JWT_SECRET", "")
	t.Setenv("OAUTH_STATE_SECRET", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Auth.JWTSecretDerived || len(cfg.Auth.JWTSecret) < 64 {
		t.Fatalf("session secret not derived: derived=%v len=%d", cfg.Auth.JWTSecretDerived, len(cfg.Auth.JWTSecret))
	}
	if cfg.OAuth.StateSecret == "" || cfg.OAuth.StateSecret == cfg.Auth.JWTSecret ||
		strings.Contains(cfg.Auth.JWTSecret, testEncKey) || cfg.Auth.JWTSecret == testEncKey {
		t.Fatal("derived secrets must differ from each other and from the encryption key")
	}
	again, err := Load()
	if err != nil || again.Auth.JWTSecret != cfg.Auth.JWTSecret || again.OAuth.StateSecret != cfg.OAuth.StateSecret {
		t.Fatal("derivation must be stable across starts (sessions survive a restart)")
	}
}

// An explicit secret wins and is not marked derived.
func TestLoad_ExplicitSessionSecretWins(t *testing.T) {
	prodEnv(t)
	explicit := strings.Repeat("e", 64)
	t.Setenv("AUTH_JWT_SECRET", explicit)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.JWTSecret != explicit || cfg.Auth.JWTSecretDerived {
		t.Fatalf("explicit AUTH_JWT_SECRET lost")
	}
}

// Without either secret, local sign-in cannot start.
func TestLoad_NoKeyNoSessionSecretRefused(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("APP_ENCRYPTION_KEY", "")
	t.Setenv("AUTH_JWT_SECRET", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "AUTH_JWT_SECRET") {
		t.Fatalf("err = %v, want a refusal naming AUTH_JWT_SECRET", err)
	}
}

// There is no default database password outside development.
func TestLoad_DBPasswordRequiredOutsideDevelopment(t *testing.T) {
	prodEnv(t)
	t.Setenv("DB_PASSWORD", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "DB_PASSWORD is required") {
		t.Fatalf("err = %v, want DB_PASSWORD is required", err)
	}
	t.Setenv("APP_ENV", "development")
	if _, err := Load(); err != nil {
		t.Fatalf("development with no DB_PASSWORD: %v", err)
	}
}

func TestLoad_RefusesPlaintextCredentialsSwitch(t *testing.T) {
	if err := rejectRetiredEnv(fakeEnv{"APP_ALLOW_PLAINTEXT_CREDENTIALS": "true"}.lookup); err == nil {
		t.Fatal("APP_ALLOW_PLAINTEXT_CREDENTIALS must be refused")
	}
}

// prodEnv is a minimal valid production environment without AUTH_JWT_SECRET.
func prodEnv(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"APP_ENV": "production", "APP_ENCRYPTION_KEY": testEncKey, "DB_PASSWORD": "prod-db-password-0123456789",
		"DB_SSLMODE": "require", "REDIS_PASSWORD": strings.Repeat("r", 40), "REDIS_TLS_ENABLED": "true",
		"AUTH_COOKIE_SECURE": "true", "AUTH_REQUIRE_EMAIL_VERIFICATION": "true", "LOG_LEVEL": "info",
		"CORS_ALLOWED_ORIGINS": "https://ctem.example.com", "AUTH_JWT_SECRET": "", "OAUTH_STATE_SECRET": "",
		"SIGNER_SOCKET": "/run/openctem-signer/signer.sock", "SIGNER_DANGEROUS_ALLOW_UNSIGNED_JOBS": "",
	} {
		t.Setenv(k, v)
	}
}

// Production refuses to start without the job signer (research/191 A-1),
// unless the operator accepts unsigned jobs by name.
func TestLoad_ProductionRequiresTheJobSigner(t *testing.T) {
	prodEnv(t)
	t.Setenv("SIGNER_SOCKET", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SIGNER_SOCKET") {
		t.Fatalf("err = %v, want SIGNER_SOCKET required", err)
	}
	t.Setenv("SIGNER_DANGEROUS_ALLOW_UNSIGNED_JOBS", "true")
	if _, err := Load(); err != nil {
		t.Fatalf("with the explicit override: %v", err)
	}
	t.Setenv("SIGNER_DANGEROUS_ALLOW_UNSIGNED_JOBS", "")
	t.Setenv("APP_ENV", "development")
	t.Setenv("CORS_ALLOWED_ORIGINS", "")
	if _, err := Load(); err != nil && strings.Contains(err.Error(), "SIGNER_SOCKET") {
		t.Fatalf("development must not require the signer: %v", err)
	}
}
