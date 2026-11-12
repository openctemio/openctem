package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
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
// metadata, or returns "" if none is set or it does not decrypt (fail closed:
// the integration then verifies no inbound webhook until the secret is
// rotated).
func (s *IntegrationService) secretFromIntegration(intg *integrationdom.Integration) string {
	enc, _ := intg.Metadata()[jiraWebhookSecretMetaKey].(string)
	if enc == "" {
		return ""
	}
	plain, err := s.encryptor.DecryptString(enc)
	if err != nil {
		s.logger.Warn("webhook secret cannot be decrypted; rotate it",
			"tenant_id", intg.TenantID().String(),
			"integration_id", intg.ID().String())
		return ""
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

// MinJiraWebhookSecretLen and MaxJiraWebhookSecretLen bound a secret an
// administrator types in (one Jira generated or chose). A shorter one is too
// easy to guess; a generated one is 64 hex characters.
const (
	MinJiraWebhookSecretLen = 16
	MaxJiraWebhookSecretLen = 256
)

// ErrJiraWebhookUnauthorized refuses an inbound delivery. One error for every
// cause (unknown integration, another provider, disabled, no secret, a bad or
// missing signature), so a caller cannot probe which integrations exist.
var ErrJiraWebhookUnauthorized = fmt.Errorf("%w: invalid webhook signature", shared.ErrUnauthorized)

// ErrInvalidJiraWebhookSecret refuses a secret outside the allowed shape.
var ErrInvalidJiraWebhookSecret = fmt.Errorf("%w: the webhook secret must be %d to %d printable characters without spaces",
	shared.ErrValidation, MinJiraWebhookSecretLen, MaxJiraWebhookSecretLen)

// jiraIntegrationOf returns the tenant's Jira integration with this id, or
// not found (another tenant's integration, or a non-Jira one, is not found).
func (s *IntegrationService) jiraIntegrationOf(ctx context.Context, tenantID, integrationID shared.ID) (*integrationdom.Integration, error) {
	intg, err := s.repo.GetByTenantAndID(ctx, tenantID, integrationID)
	if err != nil {
		return nil, err
	}
	if intg.Provider() != integrationdom.ProviderJira {
		return nil, ErrNoJiraIntegration
	}
	return intg, nil
}

// JiraWebhookHasSecret reports whether the tenant's Jira integration has an
// inbound webhook secret. The secret itself is never returned after it is
// set: it is shown once, on rotation.
func (s *IntegrationService) JiraWebhookHasSecret(ctx context.Context, tenantID, integrationID shared.ID) (bool, error) {
	intg, err := s.jiraIntegrationOf(ctx, tenantID, integrationID)
	if err != nil {
		return false, err
	}
	return s.secretFromIntegration(intg) != "", nil
}

// RotateJiraWebhookSecret generates a new inbound webhook secret for one of
// the tenant's Jira integrations and returns it, the only time it is shown.
// The previous secret stops verifying immediately.
func (s *IntegrationService) RotateJiraWebhookSecret(ctx context.Context, tenantID, integrationID shared.ID) (string, error) {
	intg, err := s.jiraIntegrationOf(ctx, tenantID, integrationID)
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

// ReplaceJiraWebhookSecret stores a secret the administrator chose (for example
// the one Jira generated in its webhook form). Stored encrypted; never
// returned.
func (s *IntegrationService) ReplaceJiraWebhookSecret(ctx context.Context, tenantID, integrationID shared.ID, secret string) error {
	if !validJiraWebhookSecret(secret) {
		return ErrInvalidJiraWebhookSecret
	}
	intg, err := s.jiraIntegrationOf(ctx, tenantID, integrationID)
	if err != nil {
		return err
	}
	if err := s.storeSecretOnIntegration(ctx, intg, secret); err != nil {
		return err
	}
	s.logger.Info("set Jira webhook secret", "tenant_id", tenantID.String(), "integration_id", intg.ID().String())
	return nil
}

func validJiraWebhookSecret(secret string) bool {
	if len(secret) < MinJiraWebhookSecretLen || len(secret) > MaxJiraWebhookSecretLen {
		return false
	}
	for _, r := range secret {
		if r <= ' ' || r > '~' {
			return false
		}
	}
	return true
}

// VerifyJiraDelivery authenticates an inbound Jira webhook delivered to the
// per-integration URL. The integration id in the URL names exactly one
// integration and so one tenant; the delivery must carry
// X-Hub-Signature: sha256=<hex HMAC-SHA256 of the raw body> under that
// integration's own secret. It returns the integration's tenant. Every
// failure is ErrJiraWebhookUnauthorized.
func (s *IntegrationService) VerifyJiraDelivery(ctx context.Context, integrationID shared.ID, body []byte, signature string) (shared.ID, error) {
	// Unscoped by design: the URL is the only identity an unauthenticated
	// sender has, and the secret of that one integration is the proof.
	intg, err := s.repo.GetByID(ctx, integrationID)
	if err != nil || intg == nil ||
		intg.Provider() != integrationdom.ProviderJira ||
		intg.Status() == integrationdom.StatusDisabled {
		return shared.ID{}, ErrJiraWebhookUnauthorized
	}
	secret := s.secretFromIntegration(intg)
	if secret == "" || !VerifyHubSignature(body, signature, secret) {
		return shared.ID{}, ErrJiraWebhookUnauthorized
	}
	return intg.TenantID(), nil
}
