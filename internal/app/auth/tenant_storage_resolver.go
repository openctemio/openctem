package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/openctemio/api/pkg/crypto"
	"github.com/openctemio/api/pkg/domain/attachment"
	"github.com/openctemio/api/pkg/logger"
)

// SettingsStorageResolver resolves per-tenant storage config from the settings table.
type SettingsStorageResolver struct {
	db        *sql.DB
	encryptor crypto.Encryptor // encrypts S3 credentials at rest
	logger    *logger.Logger
}

// NewSettingsStorageResolver creates a new resolver.
func NewSettingsStorageResolver(db *sql.DB, enc crypto.Encryptor, log *logger.Logger) *SettingsStorageResolver {
	return &SettingsStorageResolver{db: db, encryptor: enc, logger: log}
}

// GetTenantStorageConfig reads the storage_config setting for a tenant.
// Returns nil if not configured (tenant uses default provider).
func (r *SettingsStorageResolver) GetTenantStorageConfig(ctx context.Context, tenantID string) (*attachment.StorageConfig, error) {
	query := `SELECT value_json FROM settings
		WHERE tenant_id = $1 AND key = 'storage_config' AND value_json IS NOT NULL
		LIMIT 1`

	var raw json.RawMessage
	err := r.db.QueryRowContext(ctx, query, tenantID).Scan(&raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No config → use default
		}
		return nil, err
	}

	var cfg attachment.StorageConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		r.logger.Warn("invalid tenant storage config", "tenant_id", tenantID, "error", err)
		return nil, nil
	}
	if cfg.Provider == "" {
		return nil, nil
	}

	// Decrypt credentials
	if r.encryptor != nil && cfg.AccessKey != "" {
		if dec, err := r.encryptor.DecryptString(cfg.AccessKey); err == nil {
			cfg.AccessKey = dec
		}
	}
	if r.encryptor != nil && cfg.SecretKey != "" {
		if dec, err := r.encryptor.DecryptString(cfg.SecretKey); err == nil {
			cfg.SecretKey = dec
		}
	}

	return &cfg, nil
}

// SaveTenantStorageConfig upserts the storage config for a tenant.
func (r *SettingsStorageResolver) SaveTenantStorageConfig(ctx context.Context, tenantID string, cfg attachment.StorageConfig) error {
	// Encrypt credentials before persisting
	if r.encryptor != nil && cfg.AccessKey != "" {
		if enc, err := r.encryptor.EncryptString(cfg.AccessKey); err == nil {
			cfg.AccessKey = enc
		}
	}
	if r.encryptor != nil && cfg.SecretKey != "" {
		if enc, err := r.encryptor.EncryptString(cfg.SecretKey); err == nil {
			cfg.SecretKey = enc
		}
	}

	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	query := `INSERT INTO settings (id, tenant_id, key, category, value_type, value_json, description)
		VALUES (gen_random_uuid(), $1, 'storage_config', 'storage', 'json', $2, 'File storage provider configuration')
		ON CONFLICT ON CONSTRAINT unique_setting_key
		DO UPDATE SET value_json = $2, updated_at = NOW()`

	_, err = r.db.ExecContext(ctx, query, tenantID, cfgJSON)
	return err
}
