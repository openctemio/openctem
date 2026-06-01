package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	integrationdom "github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
)

// jiraWebhookSecretMetaKey is the integration-metadata key under which the
// (encrypted) per-tenant Jira inbound-webhook HMAC secret is stored.
const jiraWebhookSecretMetaKey = "webhook_secret_encrypted"

// jiraWebhookSecretBytes is the entropy of a generated webhook secret.
const jiraWebhookSecretBytes = 32

// ErrNoJiraIntegration is returned when a tenant has no Jira integration to
// anchor a webhook secret to.
var ErrNoJiraIntegration = fmt.Errorf("%w: no Jira integration configured for this tenant", shared.ErrNotFound)

// generateWebhookSecret returns a fresh random hex secret.
func generateWebhookSecret() (string, error) {
	buf := make([]byte, jiraWebhookSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate webhook secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// secretFromIntegration decrypts the webhook secret stored on an integration's
// metadata, or returns "" if none is set.
func (s *IntegrationService) secretFromIntegration(intg *integrationdom.Integration) string {
	enc, _ := intg.Metadata()[jiraWebhookSecretMetaKey].(string)
	if enc == "" {
		return ""
	}
	plain, err := s.encryptor.DecryptString(enc)
	if err != nil {
		// Backward-compat: treat an undecryptable value as plaintext (mirrors
		// decryptCredentials). A genuinely corrupt value just fails to match.
		return enc
	}
	return plain
}

// storeSecretOnIntegration encrypts secret and persists it onto the
// integration's metadata.
func (s *IntegrationService) storeSecretOnIntegration(ctx context.Context, intg *integrationdom.Integration, secret string) error {
	enc, err := s.encryptor.EncryptString(secret)
	if err != nil {
		return fmt.Errorf("encrypt webhook secret: %w", err)
	}
	meta := intg.Metadata()
	if meta == nil {
		meta = make(map[string]any)
	}
	meta[jiraWebhookSecretMetaKey] = enc
	intg.SetMetadata(meta)
	if err := s.repo.Update(ctx, intg); err != nil {
		return fmt.Errorf("persist webhook secret: %w", err)
	}
	return nil
}

// primaryJiraIntegration returns the tenant's most-recently-created Jira
// integration (ListByProvider orders by created_at DESC). Returns
// ErrNoJiraIntegration if the tenant has none.
func (s *IntegrationService) primaryJiraIntegration(ctx context.Context, tenantID shared.ID) (*integrationdom.Integration, error) {
	intgs, err := s.repo.ListByProvider(ctx, tenantID, integrationdom.ProviderJira)
	if err != nil {
		return nil, fmt.Errorf("list jira integrations: %w", err)
	}
	if len(intgs) == 0 {
		return nil, ErrNoJiraIntegration
	}
	return intgs[0], nil
}

// EnsureJiraWebhookSecret returns the tenant's Jira inbound-webhook secret,
// lazily generating and persisting one on the tenant's primary Jira integration
// if none exists. The plaintext secret is returned so the caller can show it to
// the tenant admin to configure in Jira. Requires a Jira integration to exist.
func (s *IntegrationService) EnsureJiraWebhookSecret(ctx context.Context, tenantID shared.ID) (string, error) {
	intg, err := s.primaryJiraIntegration(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if existing := s.secretFromIntegration(intg); existing != "" {
		return existing, nil
	}
	secret, err := generateWebhookSecret()
	if err != nil {
		return "", err
	}
	if err := s.storeSecretOnIntegration(ctx, intg, secret); err != nil {
		return "", err
	}
	s.logger.Info("generated Jira webhook secret", "tenant_id", tenantID.String(), "integration_id", intg.ID().String())
	return secret, nil
}

// RotateJiraWebhookSecret generates a new secret on the tenant's primary Jira
// integration and returns it. The previous secret stops verifying immediately.
func (s *IntegrationService) RotateJiraWebhookSecret(ctx context.Context, tenantID shared.ID) (string, error) {
	intg, err := s.primaryJiraIntegration(ctx, tenantID)
	if err != nil {
		return "", err
	}
	secret, err := generateWebhookSecret()
	if err != nil {
		return "", err
	}
	if err := s.storeSecretOnIntegration(ctx, intg, secret); err != nil {
		return "", err
	}
	s.logger.Info("rotated Jira webhook secret", "tenant_id", tenantID.String(), "integration_id", intg.ID().String())
	return secret, nil
}

// ListJiraWebhookSecrets returns the decrypted webhook secrets configured on all
// of the tenant's Jira integrations (excluding disabled ones). These are the
// candidate secrets used to verify an inbound Jira webhook for that tenant. The
// result is tenant-scoped, so a secret from one tenant can never verify
// another tenant's webhook.
func (s *IntegrationService) ListJiraWebhookSecrets(ctx context.Context, tenantID shared.ID) ([]string, error) {
	intgs, err := s.repo.ListByProvider(ctx, tenantID, integrationdom.ProviderJira)
	if err != nil {
		return nil, fmt.Errorf("list jira integrations: %w", err)
	}
	secrets := make([]string, 0, len(intgs))
	for _, intg := range intgs {
		if intg.Status() == integrationdom.StatusDisabled {
			continue
		}
		if secret := s.secretFromIntegration(intg); secret != "" {
			secrets = append(secrets, secret)
		}
	}
	return secrets, nil
}
