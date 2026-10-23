package integration

import (
	"context"
	"fmt"
	"maps"
	"time"

	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/webhooksig"
)

// Signing secret of a generic webhook integration
// (docs/rfcs/RFC-124-outbound-webhooks.md, pkg/webhooksig).

// ErrNoWebhookIntegration: the tenant has no generic webhook integration with
// this id (another tenant's, or another provider's, is not found either).
var ErrNoWebhookIntegration = fmt.Errorf("%w: no webhook integration with this id", shared.ErrNotFound)

// RotatedSigningSecret is the result of a rotation: the new secret, shown
// only here, and until when the replaced one still signs.
type RotatedSigningSecret struct {
	Secret             string     `json:"secret"`
	RotatedAt          time.Time  `json:"rotated_at"`
	PreviousValidUntil *time.Time `json:"previous_valid_until,omitempty"`
}

func (s *IntegrationService) webhookIntegrationOf(ctx context.Context, tenantID, integrationID shared.ID) (*integrationdom.Integration, error) {
	intg, err := s.repo.GetByTenantAndID(ctx, tenantID, integrationID)
	if err != nil {
		return nil, err
	}
	if intg.Provider() != integrationdom.ProviderWebhook {
		return nil, ErrNoWebhookIntegration
	}
	return intg, nil
}

// WebhookSigningStatus reports whether the integration has a signing secret
// and its rotation times. The secret itself is never returned after a
// rotation.
func (s *IntegrationService) WebhookSigningStatus(ctx context.Context, tenantID, integrationID shared.ID) (integrationdom.SigningSecretStatus, error) {
	intg, err := s.webhookIntegrationOf(ctx, tenantID, integrationID)
	if err != nil {
		return integrationdom.SigningSecretStatus{}, err
	}
	return integrationdom.SigningSecretStatusOf(intg.Metadata(), time.Now()), nil
}

// RotateWebhookSigningSecret generates a new signing secret and returns it,
// the only time it is shown. The replaced secret keeps signing for
// SigningSecretOverlap (deliveries carry both signatures), so the receiver
// can switch without dropping any. The first rotation creates the secret;
// until then deliveries are unsigned. A secret replaced while still in an
// earlier overlap is dropped at once: at most two secrets ever sign.
func (s *IntegrationService) RotateWebhookSigningSecret(ctx context.Context, tenantID, integrationID shared.ID) (*RotatedSigningSecret, error) {
	intg, err := s.webhookIntegrationOf(ctx, tenantID, integrationID)
	if err != nil {
		return nil, err
	}
	secret, err := webhooksig.GenerateSecret()
	if err != nil {
		return nil, err
	}
	enc, err := s.encryptor.EncryptString(secret)
	if err != nil {
		return nil, fmt.Errorf("encrypt signing secret: %w", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	meta := make(map[string]any, len(intg.Metadata())+4)
	maps.Copy(meta, intg.Metadata())
	out := &RotatedSigningSecret{Secret: secret, RotatedAt: now}
	delete(meta, integrationdom.MetaSigningSecretPrevious)
	delete(meta, integrationdom.MetaSigningSecretPreviousUntil)
	if cur, _ := meta[integrationdom.MetaSigningSecret].(string); cur != "" {
		until := now.Add(integrationdom.SigningSecretOverlap)
		meta[integrationdom.MetaSigningSecretPrevious] = cur
		meta[integrationdom.MetaSigningSecretPreviousUntil] = until.Format(time.RFC3339)
		out.PreviousValidUntil = &until
	}
	meta[integrationdom.MetaSigningSecret] = enc
	meta[integrationdom.MetaSigningSecretRotatedAt] = now.Format(time.RFC3339)
	intg.SetMetadata(meta)
	if err := s.repo.Update(ctx, intg); err != nil {
		return nil, fmt.Errorf("persist signing secret: %w", err)
	}
	s.logger.Info("rotated webhook signing secret", "tenant_id", tenantID.String(), "integration_id", intg.ID().String())
	return out, nil
}
