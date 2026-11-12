package tenant

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Evidence secret retention bounds (docs/architecture/finding-evidence.md).
const (
	DefaultEvidenceSecretRetentionDays = 30
	MinEvidenceSecretRetentionDays     = 1
	MaxEvidenceSecretRetentionDays     = 365
)

// EvidenceSettings controls finding evidence for a tenant. The masked
// evidence is kept for the platform retention; the encrypted secret values
// masked out of it (tokens, cookies, credentials of the scanned target) are
// deleted sooner, after SecretRetentionDays. After that the evidence stays
// readable but its masked values can no longer be revealed.
type EvidenceSettings struct {
	// SecretRetentionDays: 0 = DefaultEvidenceSecretRetentionDays.
	SecretRetentionDays int `json:"secret_retention_days,omitempty"`
}

// Validate checks the bounds. Zero means "use the default".
func (s EvidenceSettings) Validate() error {
	if s.SecretRetentionDays != 0 && (s.SecretRetentionDays < MinEvidenceSecretRetentionDays || s.SecretRetentionDays > MaxEvidenceSecretRetentionDays) {
		return fmt.Errorf("%w: secret_retention_days must be between %d and %d", shared.ErrValidation,
			MinEvidenceSecretRetentionDays, MaxEvidenceSecretRetentionDays)
	}
	return nil
}

// EffectiveSecretRetentionDays returns the retention, falling back to the default.
func (s EvidenceSettings) EffectiveSecretRetentionDays() int {
	if s.SecretRetentionDays <= 0 {
		return DefaultEvidenceSecretRetentionDays
	}
	return s.SecretRetentionDays
}

// UpdateEvidenceSettings updates only the evidence settings.
func (t *Tenant) UpdateEvidenceSettings(es EvidenceSettings) error {
	if err := es.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.Evidence = es
	return t.UpdateSettings(settings)
}
