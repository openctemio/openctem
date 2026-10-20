package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// TenantAISettingsRepository implements tenant.AISettingsRepository on the
// tenant_ai_settings table (one row per organization). Every query is scoped
// by tenant_id. The key column holds ciphertext only.
type TenantAISettingsRepository struct {
	db *DB
}

// NewTenantAISettingsRepository creates the repository.
func NewTenantAISettingsRepository(db *DB) *TenantAISettingsRepository {
	return &TenantAISettingsRepository{db: db}
}

var _ tenant.AISettingsRepository = (*TenantAISettingsRepository)(nil)

// aiPolicyJSON is the auto-triage policy. A missing key means "not set": the
// platform default applies.
type aiPolicyJSON struct {
	AutoTriageEnabled      *bool    `json:"auto_triage_enabled,omitempty"`
	AutoTriageSeverities   []string `json:"auto_triage_severities,omitempty"`
	AutoTriageDelaySeconds *int     `json:"auto_triage_delay_seconds,omitempty"`
}

func sourceToMode(src string) tenant.AIMode {
	switch src {
	case "own":
		return tenant.AIModeBYOK
	case "off":
		return tenant.AIModeDisabled
	default:
		return tenant.AIModePlatform
	}
}

func modeToSource(m tenant.AIMode) string {
	switch m {
	case tenant.AIModeBYOK:
		return "own"
	case tenant.AIModeDisabled:
		return "off"
	default:
		return "platform"
	}
}

// Get returns the organization's settings, defaults for an organization
// without a row.
func (r *TenantAISettingsRepository) Get(ctx context.Context, tenantID shared.ID, defaults tenant.AISettings) (tenant.AISettings, error) {
	const q = `
		SELECT source, provider, base_url, model, key_enc, key_last4, key_updated_at, key_updated_by::text,
		       enabled_at, enabled_by, policy, updated_at, updated_by::text
		  FROM tenant_ai_settings WHERE tenant_id = $1`
	var (
		source, provider, baseURL, model, last4, enabledBy string
		keyEnc, keyBy, updBy                               sql.NullString
		keyAt, enabledAt                                   sql.NullTime
		updAt                                              time.Time
		policyRaw                                          []byte
	)
	err := r.db.QueryRowContext(ctx, q, tenantID.String()).Scan(&source, &provider, &baseURL, &model, &keyEnc, &last4,
		&keyAt, &keyBy, &enabledAt, &enabledBy, &policyRaw, &updAt, &updBy)
	if errors.Is(err, sql.ErrNoRows) {
		return defaults, nil
	}
	if err != nil {
		return tenant.AISettings{}, fmt.Errorf("read AI settings: %w", err)
	}
	out := defaults
	out.Mode = sourceToMode(source)
	out.Provider, out.BaseURL, out.ModelOverride = tenant.LLMProvider(provider), baseURL, model
	out.APIKey, out.KeyLast4 = keyEnc.String, last4
	if keyAt.Valid {
		t := keyAt.Time.UTC()
		out.KeyUpdatedAt = &t
	}
	out.KeyUpdatedBy = keyBy.String
	if enabledAt.Valid {
		t := enabledAt.Time.UTC()
		out.EnabledAt = &t
	}
	out.EnabledBy = enabledBy
	u := updAt.UTC()
	out.UpdatedAt, out.UpdatedBy = &u, updBy.String
	var pol aiPolicyJSON
	if err := json.Unmarshal(policyRaw, &pol); err != nil {
		return tenant.AISettings{}, fmt.Errorf("decode AI policy: %w", err)
	}
	if pol.AutoTriageEnabled != nil {
		out.AutoTriageEnabled = *pol.AutoTriageEnabled
	}
	if pol.AutoTriageSeverities != nil {
		out.AutoTriageSeverities = pol.AutoTriageSeverities
	}
	if pol.AutoTriageDelaySeconds != nil {
		out.AutoTriageDelaySeconds = *pol.AutoTriageDelaySeconds
	}
	return out, nil
}

// Save upserts the source, own provider, key and consent. The policy column
// is left as it is.
func (r *TenantAISettingsRepository) Save(ctx context.Context, tenantID shared.ID, s tenant.AISettings) error {
	const q = `
		INSERT INTO tenant_ai_settings (tenant_id, source, provider, base_url, model, key_enc, key_last4,
		                                key_updated_at, key_updated_by, enabled_at, enabled_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, '')::uuid, $10, $11, NULLIF($12, '')::uuid)
		ON CONFLICT (tenant_id) DO UPDATE SET
		       source = EXCLUDED.source, provider = EXCLUDED.provider, base_url = EXCLUDED.base_url,
		       model = EXCLUDED.model, key_enc = EXCLUDED.key_enc, key_last4 = EXCLUDED.key_last4,
		       key_updated_at = EXCLUDED.key_updated_at, key_updated_by = EXCLUDED.key_updated_by,
		       enabled_at = EXCLUDED.enabled_at, enabled_by = EXCLUDED.enabled_by,
		       updated_by = EXCLUDED.updated_by, updated_at = now()`
	var key sql.NullString
	if s.APIKey != "" {
		key = sql.NullString{String: s.APIKey, Valid: true}
	}
	_, err := r.db.ExecContext(ctx, q, tenantID.String(), modeToSource(s.Mode), string(s.Provider), s.BaseURL, s.ModelOverride,
		key, s.KeyLast4, s.KeyUpdatedAt, s.KeyUpdatedBy, s.EnabledAt, s.EnabledBy, s.UpdatedBy)
	if err != nil {
		return fmt.Errorf("save AI settings: %w", err)
	}
	return nil
}
