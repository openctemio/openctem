package postgres

// The platform policy for scan approval (RFC-072 §5): the
// platform default in platform_settings, the per-organization override in
// tenants.scan_approval_policy. Written only by the admin console service.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScanPolicyRepository implements scanpolicy.Repository.
type ScanPolicyRepository struct{ db *DB }

// NewScanPolicyRepository creates the repository.
func NewScanPolicyRepository(db *DB) *ScanPolicyRepository { return &ScanPolicyRepository{db: db} }

var _ scanpolicy.Repository = (*ScanPolicyRepository)(nil)

type scanPolicyValue struct {
	Mode scangov.PlatformPolicy `json:"mode"`
}

// GetDefault returns the stored platform default, or scanpolicy.ErrNotFound.
func (r *ScanPolicyRepository) GetDefault(ctx context.Context) (scangov.PlatformPolicy, int, error) {
	var raw []byte
	var version int
	err := r.db.QueryRowContext(ctx, `SELECT value, version FROM platform_settings WHERE key = $1`,
		scangov.PlatformPolicyKey).Scan(&raw, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, scanpolicy.ErrNotFound
	}
	if err != nil {
		return "", 0, fmt.Errorf("get scan approval policy: %w", err)
	}
	var v scanPolicyValue
	if err := json.Unmarshal(raw, &v); err != nil || !v.Mode.Valid() {
		return "", 0, fmt.Errorf("decode scan approval policy: invalid value")
	}
	return v.Mode, version, nil
}

// SetDefault stores the platform default when the stored version is
// expectedVersion (0: nothing stored yet), and returns the new version.
func (r *ScanPolicyRepository) SetDefault(ctx context.Context, mode scangov.PlatformPolicy, expectedVersion int, by shared.ID, at time.Time) (int, error) {
	raw, err := json.Marshal(scanPolicyValue{Mode: mode})
	if err != nil {
		return 0, err
	}
	var version int
	if expectedVersion == 0 {
		err = r.db.QueryRowContext(ctx, `
			INSERT INTO platform_settings (key, value, version, source, updated_by, updated_at)
			VALUES ($1, $2, 1, 'console', $3, $4)
			ON CONFLICT (key) DO NOTHING
			RETURNING version`, scangov.PlatformPolicyKey, raw, by.String(), at).Scan(&version)
	} else {
		err = r.db.QueryRowContext(ctx, `
			UPDATE platform_settings
			   SET value = $2, version = version + 1, source = 'console', updated_by = $3, updated_at = $4
			 WHERE key = $1 AND version = $5
			RETURNING version`, scangov.PlatformPolicyKey, raw, by.String(), at, expectedVersion).Scan(&version)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 0, scanpolicy.ErrVersionConflict
	}
	if err != nil {
		return 0, fmt.Errorf("set scan approval policy: %w", err)
	}
	return version, nil
}

// GetOverride returns an organization's override (nil: none).
func (r *ScanPolicyRepository) GetOverride(ctx context.Context, tenantID shared.ID) (*scangov.PlatformPolicy, error) {
	var v sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT scan_approval_policy FROM tenants WHERE id = $1`, tenantID.String()).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get organization scan approval policy: %w", err)
	}
	if !v.Valid {
		return nil, nil
	}
	m := scangov.PlatformPolicy(v.String)
	return &m, nil
}

// SetOverride sets (nil: removes) an organization's override.
func (r *ScanPolicyRepository) SetOverride(ctx context.Context, tenantID shared.ID, mode *scangov.PlatformPolicy) error {
	var v any
	if mode != nil {
		v = string(*mode)
	}
	res, err := r.db.ExecContext(ctx, `UPDATE tenants SET scan_approval_policy = $2, updated_at = now() WHERE id = $1`,
		tenantID.String(), v)
	if err != nil {
		return fmt.Errorf("set organization scan approval policy: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}
