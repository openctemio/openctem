package jira

import (
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A stored Jira credential that does not decrypt under the configured key is
// an error, never sent to Jira as is (RFC-049 F-8).
func TestResolveCredentials_UndecryptableFailsClosed(t *testing.T) {
	cipher, err := crypto.NewCipherFromKey("ab00112233445566778899aabbccddeeff00112233445566778899aabbccddee", "hex")
	if err != nil {
		t.Fatal(err)
	}
	other, err := crypto.NewCipherFromKey("cd00112233445566778899aabbccddeeff00112233445566778899aabbccddee", "hex")
	if err != nil {
		t.Fatal(err)
	}
	underOtherKey, err := other.EncryptString(`{"email":"a@example.com","api_token":"tok"}`)
	if err != nil {
		t.Fatal(err)
	}
	r := NewIntegrationClientResolver(&stubIntegrationRepo{}, cipher, logger.NewNop())

	for name, stored := range map[string]string{
		"legacy plaintext": "a@example.com:tok",
		"other key":        underOtherKey,
	} {
		intg := newJiraIntegration(t, integration.StatusConnected, "https://jira.example.com", stored, nil)
		email, token, err := r.resolveCredentials(intg)
		if err == nil || !strings.Contains(err.Error(), "cannot be decrypted") {
			t.Fatalf("%s: err = %v, want a decrypt error", name, err)
		}
		if email != "" || token != "" {
			t.Fatalf("%s: credential leaked: %q %q", name, email, token)
		}
	}

	good, err := cipher.EncryptString(`{"email":"a@example.com","api_token":"tok"}`)
	if err != nil {
		t.Fatal(err)
	}
	intg := newJiraIntegration(t, integration.StatusConnected, "https://jira.example.com", good, nil)
	if email, token, err := r.resolveCredentials(intg); err != nil || email != "a@example.com" || token != "tok" {
		t.Fatalf("current key: %q %q %v", email, token, err)
	}
}
