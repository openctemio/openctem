package integration

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/scm"
	"github.com/openctemio/openctem/api/pkg/crypto"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	testKeyCurrent = "ab00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
	testKeyOther   = "cd00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
)

func mustCipher(t *testing.T, key string) *crypto.Cipher {
	t.Helper()
	c, err := crypto.NewCipherFromKey(key, "hex")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// A stored credential that does not decrypt under the configured key (a key
// mismatch, a corrupt value, a legacy plaintext row) is never used as is:
// it would send ciphertext or an unencrypted secret upstream (RFC-049 F-8).
func TestDecryptCredentials_FailsClosed(t *testing.T) {
	s := &IntegrationService{encryptor: mustCipher(t, testKeyCurrent), logger: logger.NewNop()}
	underOther, err := mustCipher(t, testKeyOther).EncryptString("https://hooks.slack.example/T000/B000/secret")
	if err != nil {
		t.Fatal(err)
	}

	for name, stored := range map[string]string{
		"legacy plaintext": "https://hooks.slack.example/T000/B000/secret",
		"other key":        underOther,
	} {
		intg := integrationdom.NewIntegration(shared.NewID(), shared.NewID(), "slack",
			integrationdom.CategoryNotification, integrationdom.ProviderSlack, integrationdom.AuthTypeToken)
		intg.SetCredentials(stored)

		got, err := s.decryptCredentials(intg)
		if !errors.Is(err, ErrCredentialsUnreadable) || !errors.Is(err, scm.ErrAuthFailed) || got != "" {
			t.Fatalf("%s: decryptCredentials = %q, %v; want \"\", ErrCredentialsUnreadable", name, got, err)
		}
		cfg, err := s.buildNotificationConfig(intg, nil)
		if !errors.Is(err, ErrCredentialsUnreadable) || cfg.WebhookURL != "" {
			t.Fatalf("%s: buildNotificationConfig = %+v, %v; want no webhook URL and an error", name, cfg, err)
		}
	}

	good, err := mustCipher(t, testKeyCurrent).EncryptString("tok")
	if err != nil {
		t.Fatal(err)
	}
	intg := integrationdom.NewIntegration(shared.NewID(), shared.NewID(), "gh",
		integrationdom.CategorySCM, integrationdom.ProviderGitHub, integrationdom.AuthTypeToken)
	intg.SetCredentials(good)
	if got, err := s.decryptCredentials(intg); err != nil || got != "tok" {
		t.Fatalf("current key: %q, %v", got, err)
	}
}

// With APP_ALLOW_PLAINTEXT_CREDENTIALS (development) the encryptor is a no-op
// and stored values are used as written.
func TestDecryptCredentials_DevelopmentPlaintext(t *testing.T) {
	s := &IntegrationService{encryptor: crypto.NewNoOpEncryptor(), logger: logger.NewNop()}
	intg := integrationdom.NewIntegration(shared.NewID(), shared.NewID(), "gh",
		integrationdom.CategorySCM, integrationdom.ProviderGitHub, integrationdom.AuthTypeToken)
	intg.SetCredentials("tok")
	if got, err := s.decryptCredentials(intg); err != nil || got != "tok" {
		t.Fatalf("no-op encryptor: %q, %v", got, err)
	}
}

// An undecryptable Jira/GitHub webhook secret verifies nothing (it is never
// used as an HMAC key as is).
func TestSecretFromIntegration_FailsClosed(t *testing.T) {
	s := &IntegrationService{encryptor: mustCipher(t, testKeyCurrent), logger: logger.NewNop()}
	intg := integrationdom.NewIntegration(shared.NewID(), shared.NewID(), "jira",
		integrationdom.CategoryTicketing, integrationdom.ProviderJira, integrationdom.AuthTypeToken)
	intg.SetMetadata(map[string]any{jiraWebhookSecretMetaKey: "plaintext-secret"})
	if got := s.secretFromIntegration(intg); got != "" {
		t.Fatalf("undecryptable secret returned %q", got)
	}
}
