package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SensorIdentityPolicyRepository reads and writes
// tenants.sensor_bearer_keys_allowed (RFC-052 D-4).
type SensorIdentityPolicyRepository struct {
	db *DB
}

// NewSensorIdentityPolicyRepository creates the repository.
func NewSensorIdentityPolicyRepository(db *DB) *SensorIdentityPolicyRepository {
	return &SensorIdentityPolicyRepository{db: db}
}

var _ sensordom.IdentityPolicyRepository = (*SensorIdentityPolicyRepository)(nil)

// BearerKeysAllowed reports whether the tenant may create bearer-key sensors.
func (r *SensorIdentityPolicyRepository) BearerKeysAllowed(ctx context.Context, tenantID shared.ID) (bool, error) {
	var allowed bool
	err := r.db.QueryRowContext(ctx, `SELECT sensor_bearer_keys_allowed FROM tenants WHERE id = $1`, tenantID.String()).Scan(&allowed)
	if errors.Is(err, sql.ErrNoRows) {
		return false, shared.ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("read sensor identity policy: %w", err)
	}
	return allowed, nil
}

// SetBearerKeysAllowed changes the policy; changed is false when it already
// had that value.
func (r *SensorIdentityPolicyRepository) SetBearerKeysAllowed(ctx context.Context, tenantID shared.ID, allowed bool) (bool, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE tenants SET sensor_bearer_keys_allowed = $2, updated_at = NOW()
		WHERE id = $1 AND sensor_bearer_keys_allowed IS DISTINCT FROM $2`, tenantID.String(), allowed)
	if err != nil {
		return false, fmt.Errorf("write sensor identity policy: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// KeyBindRequiresApproval reports whether the tenant's bearer-key sensors
// must be re-paired instead of binding their own key.
func (r *SensorIdentityPolicyRepository) KeyBindRequiresApproval(ctx context.Context, tenantID shared.ID) (bool, error) {
	var required bool
	err := r.db.QueryRowContext(ctx, `SELECT sensor_key_bind_requires_approval FROM tenants WHERE id = $1`, tenantID.String()).Scan(&required)
	if errors.Is(err, sql.ErrNoRows) {
		return false, shared.ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("read sensor key bind policy: %w", err)
	}
	return required, nil
}

// SetKeyBindRequiresApproval changes the key bind policy; changed is false
// when it already had that value.
func (r *SensorIdentityPolicyRepository) SetKeyBindRequiresApproval(ctx context.Context, tenantID shared.ID, required bool) (bool, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE tenants SET sensor_key_bind_requires_approval = $2, updated_at = NOW()
		WHERE id = $1 AND sensor_key_bind_requires_approval IS DISTINCT FROM $2`, tenantID.String(), required)
	if err != nil {
		return false, fmt.Errorf("write sensor key bind policy: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}
