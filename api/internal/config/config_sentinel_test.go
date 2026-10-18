package config

import (
	"strings"
	"testing"
)

// The startup sentinel in config.go refuses to boot the server with
// the docker-compose dev-default JWT secret or AES-256 encryption
// key in non-development environments. These tests pin that
// behaviour so a future config refactor can't silently demote the
// guard.
//
// The full Validate() path requires a lot of unrelated fields to be
// set (DB URL, Redis password, OAuth …) so we hit the sentinel
// helpers directly — they are small pure functions.

func TestIsDevDefaultJWTSecret_AllListedSentinelsMatch(t *testing.T) {
	for _, s := range devDefaultJWTSecrets {
		if !isDevDefaultJWTSecret(s) {
			t.Errorf("sentinel list contains %q but isDevDefaultJWTSecret returned false", s)
		}
	}
}

func TestIsDevDefaultJWTSecret_LegitSecretPasses(t *testing.T) {
	// A high-entropy hex string that happens to be 64 chars — the
	// same length as the dev default — must not be rejected.
	legit := "fffe00112233445566778899aabbccddeeff00112233445566778899aabbccdd"
	if isDevDefaultJWTSecret(legit) {
		t.Errorf("a legit 64-char hex secret was flagged as dev-default: %q", legit)
	}
}

func TestIsDevDefaultEncryptionKey_MatchesDockerComposeLiteral(t *testing.T) {
	const literal = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if !isDevDefaultEncryptionKey(literal) {
		t.Fatal("the docker-compose dev AES key literal must be rejected by the sentinel")
	}
}

func TestIsDevDefaultEncryptionKey_LegitKeyPasses(t *testing.T) {
	legit := "ffffeeeeeeeedddddddddcccccccccbbbbbbbbbaaaaaaaaa99999999988888888"
	if isDevDefaultEncryptionKey(legit) {
		t.Errorf("a legit 64-char hex key was flagged as dev-default: %q", legit)
	}
	// Shorter-than-64 string that starts identically must not match
	// — the sentinel is an exact-string compare, not a prefix match.
	prefix := "0123456789abcdef0123456789abcdef"
	if isDevDefaultEncryptionKey(prefix) {
		t.Errorf("prefix-only match is wrong; got match for %q", prefix)
	}
}

// Validate() happy path for the sentinel branch: dev env with the
// dev-default secret MUST pass (otherwise `docker compose up` breaks
// for every new contributor). We stub the rest of the config to
// minimum-valid.
func TestValidate_DevEnv_AcceptsDevDefaultJWT(t *testing.T) {
	c := minimalValidConfig()
	c.App.Env = "development"
	c.Auth.JWTSecret = devDefaultJWTSecrets[0]

	if err := c.Validate(); err != nil {
		t.Fatalf("dev env must accept the dev-default JWT secret; got %v", err)
	}
}

// Validate() NEGATIVE: production with dev-default JWT must refuse.
func TestValidate_ProdEnv_RefusesDevDefaultJWT(t *testing.T) {
	c := minimalValidConfig()
	c.App.Env = EnvProduction
	c.Auth.JWTSecret = devDefaultJWTSecrets[0] // 64+ chars so it passes the length check first

	err := c.Validate()
	if err == nil {
		t.Fatal("prod env MUST refuse the dev-default JWT secret")
	}
	// Error message must name AUTH_JWT_SECRET so the operator can
	// locate the misconfiguration quickly.
	if !strings.Contains(err.Error(), "AUTH_JWT_SECRET") {
		t.Errorf("error should mention AUTH_JWT_SECRET; got %q", err.Error())
	}
}

// Validate() NEGATIVE: production with dev-default encryption key
// must refuse. Only fires when the key is actually SET (empty key is
// handled by a separate "required in production" branch).
func TestValidate_ProdEnv_RefusesDevDefaultEncryptionKey(t *testing.T) {
	c := minimalValidConfig()
	c.App.Env = EnvProduction
	c.Auth.JWTSecret = strongHexSecret // passes JWT checks
	c.Encryption.Key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	err := c.Validate()
	if err == nil {
		t.Fatal("prod env MUST refuse the dev-default AES-256 key")
	}
	if !strings.Contains(err.Error(), "APP_ENCRYPTION_KEY") {
		t.Errorf("error should mention APP_ENCRYPTION_KEY; got %q", err.Error())
	}
}

// ---------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------

// strongHexSecret is a 64-char hex string that is NOT in
// devDefaultJWTSecrets — suitable as a "real" production secret in
// tests.
const strongHexSecret = "ff00112233445566778899aabbccddeeff00112233445566778899aabbccddee"

// minimalValidConfig returns a Config where every field Validate()
// inspects is set to a sane production-ish value EXCEPT the fields
// we want the specific test to exercise. Tests set env + the field
// under test before calling Validate.
func minimalValidConfig() *Config {
	return &Config{
		App: AppConfig{
			Name: "openctem",
			Env:  "development",
		},
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
		},
		Auth: AuthConfig{
			Provider:                 AuthProviderLocal,
			JWTSecret:                strongHexSecret,
			PasswordMinLength:        10,
			MaxLoginAttempts:         5,
			MaxActiveSessions:        10,
			AccessTokenDuration:      15 * 60 * 1_000_000_000, // 15m in ns
			RefreshTokenDuration:     60 * 60 * 1_000_000_000, // 1h
			SessionDuration:          24 * 60 * 60 * 1_000_000_000,
			RequireEmailVerification: true,
			CookieSecure:             true,
		},
		CORS:       CORSConfig{AllowedOrigins: []string{"https://app.example.com"}},
		Database:   DatabaseConfig{Host: "localhost", SSLMode: "require"},
		Redis:      RedisConfig{Password: "redispass"},
		RateLimit:  RateLimitConfig{Enabled: true},
		Log:        LogConfig{Level: "info"},
		Encryption: EncryptionConfig{Key: "", KeyFormat: ""},
	}
}

func TestValidate_SignupMode(t *testing.T) {
	cfg := minimalValidConfig()
	cfg.Auth.SignupMode = ""
	if err := cfg.Validate(); err != nil {
		t.Fatalf("empty mode must default, got %v", err)
	}
	if cfg.Auth.SignupMode != SignupModeDisabled {
		t.Fatalf("empty mode defaulted to %q, want disabled", cfg.Auth.SignupMode)
	}
	for _, ok := range []string{SignupModeDomain, SignupModeOpen} {
		cfg.Auth.SignupMode = ok
		if err := cfg.Validate(); err != nil {
			t.Fatalf("%s must be valid, got %v", ok, err)
		}
	}
	// The old TENANT_CREATION_MODE values and typos are refused, never read
	// as "open".
	for _, bad := range []string{"self_service", "admin_only", "opne", "true"} {
		cfg.Auth.SignupMode = bad
		if err := cfg.Validate(); err == nil {
			t.Fatalf("SIGNUP_MODE=%q must fail validation", bad)
		}
	}
	cfg.Auth.SignupMode = SignupModeOpen
	cfg.Auth.SignupCaptcha = "off"
	if err := cfg.Validate(); err == nil {
		t.Fatal("SIGNUP_CAPTCHA accepts only the explicit acceptance value")
	}
	cfg.Auth.SignupCaptcha = ""
	cfg.Auth.Provider = AuthProviderOIDC
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "SIGNUP_MODE") {
		t.Fatalf("public sign-up without local accounts must fail, got %v", err)
	}
}

// Public sign-up is closed unless the operator opts in (SIGNUP_MODE, the
// deployment ceiling); the old variable stops start-up with the way to move.
func TestLoad_SignupModeDefaultsToDisabled(t *testing.T) {
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Auth.SignupMode != SignupModeDisabled || cfg.Auth.SignupOpen() || cfg.Auth.PublicSignup() {
		t.Fatalf("unset SIGNUP_MODE loaded as %q, want disabled", cfg.Auth.SignupMode)
	}
	t.Setenv("SIGNUP_MODE", "Open")
	if cfg, err = Load(); err != nil || !cfg.Auth.SignupOpen() || !cfg.Auth.PublicSignup() {
		t.Fatalf("explicit open must load: %v", err)
	}
	t.Setenv("SIGNUP_MODE", SignupModeDomain)
	if cfg, err = Load(); err != nil || cfg.Auth.SignupOpen() || !cfg.Auth.PublicSignup() {
		t.Fatalf("domain allows public sign-up but no organization self-service: %v", err)
	}
	t.Setenv("SIGNUP_MODE", "")
	t.Setenv("TENANT_CREATION_MODE", "self_service")
	if _, err = Load(); err == nil || !strings.Contains(err.Error(), "SIGNUP_MODE=open") {
		t.Fatalf("TENANT_CREATION_MODE must stop start-up and name SIGNUP_MODE, got %v", err)
	}
}

// SIGNUP_MODE=open in production starts without CAPTCHA keys in the
// environment: the keys may be set in the console, and open sign-up stays
// closed at runtime until they are (signup.Service.SetCaptchaReady).
func TestValidateProduction_OpenSignupStartsWithoutEnvCaptcha(t *testing.T) {
	cfg := minimalValidConfig()
	cfg.Auth.CookieSameSite = "lax"
	cfg.Auth.SignupMode = SignupModeOpen
	if err := cfg.validateProductionAuth(); err != nil {
		t.Fatalf("open without environment CAPTCHA keys must start (the console may set them): %v", err)
	}
}

// APP_ENCRYPTION_KEY_PREVIOUS entries must be valid keys and differ from the
// current key; the error never echoes the key.
func TestValidate_PreviousEncryptionKeys(t *testing.T) {
	const current = "ab00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
	const previous = "cd00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
	for name, tc := range map[string]struct {
		prev    []string
		wantErr bool
	}{
		"valid previous":   {[]string{previous}, false},
		"malformed":        {[]string{"not-a-key-value"}, true},
		"equal to current": {[]string{current}, true},
	} {
		c := minimalValidConfig()
		c.Encryption.Key = current
		c.Encryption.PreviousKeys = tc.prev
		err := c.Validate()
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", name, err, tc.wantErr)
		}
		if err != nil && strings.Contains(err.Error(), tc.prev[0]) {
			t.Errorf("%s: the error must not echo the key", name)
		}
	}
}
