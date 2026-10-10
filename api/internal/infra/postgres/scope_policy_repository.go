package postgres

// The platform policy for scope-widening approvals (RFC-054 §12.6): the
// platform default in platform_settings, the per-organization override in
// tenants.scope_approval_policy. Written only by the admin console service.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scopepolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// ScopePolicyRepository implements scopepolicy.Repository.
type ScopePolicyRepository struct{ db *DB }

// NewScopePolicyRepository creates the repository.
func NewScopePolicyRepository(db *DB) *ScopePolicyRepository { return &ScopePolicyRepository{db: db} }

var _ scopepolicy.Repository = (*ScopePolicyRepository)(nil)

type scopePolicyValue struct {
	Mode tenant.ScopeApprovalMode `json:"mode"`
}

// GetDefault returns the stored platform default, or scopepolicy.ErrNotFound.
func (r *ScopePolicyRepository) GetDefault(ctx context.Context) (tenant.ScopeApprovalMode, int, error) {
	var raw []byte
	var version int
	err := r.db.QueryRowContext(ctx, `SELECT value, version FROM platform_settings WHERE key = $1`,
		tenant.ScopeApprovalPolicyKey).Scan(&raw, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, scopepolicy.ErrNotFound
	}
	if err != nil {
		return "", 0, fmt.Errorf("get scope approval policy: %w", err)
	}
	var v scopePolicyValue
	if err := json.Unmarshal(raw, &v); err != nil || !v.Mode.Valid() {
		return "", 0, fmt.Errorf("decode scope approval policy: invalid value")
	}
	return v.Mode, version, nil
}

// SetDefault stores the platform default when the stored version is
// expectedVersion (0: nothing stored yet), and returns the new version.
func (r *ScopePolicyRepository) SetDefault(ctx context.Context, mode tenant.ScopeApprovalMode, expectedVersion int, by shared.ID, at time.Time) (int, error) {
	raw, err := json.Marshal(scopePolicyValue{Mode: mode})
	if err != nil {
		return 0, err
	}
	var version int
	if expectedVersion == 0 {
		err = r.db.QueryRowContext(ctx, `
			INSERT INTO platform_settings (key, value, version, source, updated_by, updated_at)
			VALUES ($1, $2, 1, 'console', $3, $4)
			ON CONFLICT (key) DO NOTHING
			RETURNING version`, tenant.ScopeApprovalPolicyKey, raw, by.String(), at).Scan(&version)
	} else {
		err = r.db.QueryRowContext(ctx, `
			UPDATE platform_settings
			   SET value = $2, version = version + 1, source = 'console', updated_by = $3, updated_at = $4
			 WHERE key = $1 AND version = $5
			RETURNING version`, tenant.ScopeApprovalPolicyKey, raw, by.String(), at, expectedVersion).Scan(&version)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 0, scopepolicy.ErrVersionConflict
	}
	if err != nil {
		return 0, fmt.Errorf("set scope approval policy: %w", err)
	}
	return version, nil
}

// GetOverride returns an organization's override (nil: none).
func (r *ScopePolicyRepository) GetOverride(ctx context.Context, tenantID shared.ID) (*tenant.ScopeApprovalMode, error) {
	var v sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT scope_approval_policy FROM tenants WHERE id = $1`, tenantID.String()).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get organization scope approval policy: %w", err)
	}
	if !v.Valid {
		return nil, nil
	}
	m := tenant.ScopeApprovalMode(v.String)
	return &m, nil
}

// SetOverride sets (nil: removes) an organization's override.
func (r *ScopePolicyRepository) SetOverride(ctx context.Context, tenantID shared.ID, mode *tenant.ScopeApprovalMode) error {
	var v any
	if mode != nil {
		v = string(*mode)
	}
	res, err := r.db.ExecContext(ctx, `UPDATE tenants SET scope_approval_policy = $2, updated_at = now() WHERE id = $1`,
		tenantID.String(), v)
	if err != nil {
		return fmt.Errorf("set organization scope approval policy: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}
