package config

import (
	"strings"
	"testing"
)

// The secret-finding fingerprint has its own key: required outside
// development, long enough, never printed, and independent of
// APP_ENCRYPTION_KEY so rotating the encryption key keeps secret identities.

func TestLoad_FingerprintKeyRequiredInProduction(t *testing.T) {
	prodEnv(t)
	t.Setenv("FINGERPRINT_KEY", "")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "FINGERPRINT_KEY is required") {
		t.Fatalf("production without FINGERPRINT_KEY: %v", err)
	}
}

func TestLoad_FingerprintKeyTooShortIsRefusedWithoutEchoingIt(t *testing.T) {
	prodEnv(t)
	const short = "short-secret-value"
	t.Setenv("FINGERPRINT_KEY", short)
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "FINGERPRINT_KEY must be at least 32") {
		t.Fatalf("short key: %v", err)
	}
	if strings.Contains(err.Error(), short) {
		t.Fatal("the error printed the key")
	}
}

func TestFingerprintSecret_DevelopmentFallsBackToTheEncryptionKeyOnly(t *testing.T) {
	dev := &Config{}
	dev.App.Env = envDevelopment
	dev.Encryption.Key = "enc-key"
	if got := dev.FingerprintSecret(); got != "enc-key" {
		t.Fatalf("dev fallback = %q", got)
	}
	dev.Encryption.FingerprintKey = "fp-key"
	if got := dev.FingerprintSecret(); got != "fp-key" {
		t.Fatalf("dedicated key ignored: %q", got)
	}
	prod := &Config{}
	prod.App.Env = "production"
	prod.Encryption.Key = "enc-key"
	if got := prod.FingerprintSecret(); got != "" {
		t.Fatalf("production fell back to the encryption key: %q", got)
	}
}
