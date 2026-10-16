package postgres

// The platform policy for scan approval (RFC-073 §5): the
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

// ListFollowingDefault lists the organizations with no override (they
// follow the platform default).
func (r *ScanPolicyRepository) ListFollowingDefault(ctx context.Context) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id FROM tenants WHERE scan_approval_policy IS NULL ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("list organizations following the scan approval default: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("list organizations following the scan approval default: %w", err)
		}
		id, err := shared.IDFromString(raw)
		if err != nil {
			return nil, fmt.Errorf("list organizations following the scan approval default: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
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

var _ scanpolicy.ProofStore = (*ScanPolicyRepository)(nil)

type proofValue struct {
	Required *bool `json:"required"`
}

// GetProofRequired returns whether platform sensors need a verified domain,
// or scanpolicy.ErrNotFound when nothing is stored.
func (r *ScanPolicyRepository) GetProofRequired(ctx context.Context) (bool, int, error) {
	var raw []byte
	var version int
	err := r.db.QueryRowContext(ctx, `SELECT value, version FROM platform_settings WHERE key = $1`,
		scanpolicy.ProofSettingKey).Scan(&raw, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return false, 0, scanpolicy.ErrNotFound
	}
	if err != nil {
		return false, 0, fmt.Errorf("get platform sensor proof setting: %w", err)
	}
	var v proofValue
	if err := json.Unmarshal(raw, &v); err != nil || v.Required == nil {
		return false, 0, fmt.Errorf("decode platform sensor proof setting: invalid value")
	}
	return *v.Required, version, nil
}

// SetProofRequired stores the setting when the stored version is
// expectedVersion (0: nothing stored yet), and returns the new version.
func (r *ScanPolicyRepository) SetProofRequired(ctx context.Context, required bool, expectedVersion int, by string, at time.Time) (int, error) {
	raw, err := json.Marshal(proofValue{Required: &required})
	if err != nil {
		return 0, err
	}
	var version int
	if expectedVersion == 0 {
		err = r.db.QueryRowContext(ctx, `
			INSERT INTO platform_settings (key, value, version, source, updated_by, updated_at)
			VALUES ($1, $2, 1, 'console', $3, $4)
			ON CONFLICT (key) DO NOTHING
			RETURNING version`, scanpolicy.ProofSettingKey, raw, by, at).Scan(&version)
	} else {
		err = r.db.QueryRowContext(ctx, `
			UPDATE platform_settings
			   SET value = $2, version = version + 1, source = 'console', updated_by = $3, updated_at = $4
			 WHERE key = $1 AND version = $5
			RETURNING version`, scanpolicy.ProofSettingKey, raw, by, at, expectedVersion).Scan(&version)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 0, scanpolicy.ErrVersionConflict
	}
	if err != nil {
		return 0, fmt.Errorf("set platform sensor proof setting: %w", err)
	}
	return version, nil
}

var _ scanpolicy.SharedSensorsStore = (*ScanPolicyRepository)(nil)

// GetSharedSensors returns the instance shared sensor setting, or
// scanpolicy.ErrNotFound when nothing is stored.
func (r *ScanPolicyRepository) GetSharedSensors(ctx context.Context) (scanpolicy.SharedSensorsSetting, int, error) {
	var raw []byte
	var version int
	err := r.db.QueryRowContext(ctx, `SELECT value, version FROM platform_settings WHERE key = $1`,
		scanpolicy.SharedSensorsSettingKey).Scan(&raw, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return scanpolicy.SharedSensorsSetting{}, 0, scanpolicy.ErrNotFound
	}
	if err != nil {
		return scanpolicy.SharedSensorsSetting{}, 0, fmt.Errorf("get shared sensor setting: %w", err)
	}
	var v struct {
		Enabled *bool `json:"enabled"`
		NewOrgs *bool `json:"new_orgs"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || v.Enabled == nil {
		return scanpolicy.SharedSensorsSetting{}, 0, fmt.Errorf("decode shared sensor setting: invalid value")
	}
	return scanpolicy.SharedSensorsSetting{Enabled: *v.Enabled, NewOrgs: v.NewOrgs}, version, nil
}

// SetSharedSensors stores the setting when the stored version is
// expectedVersion (0: nothing stored yet), and returns the new version.
func (r *ScanPolicyRepository) SetSharedSensors(ctx context.Context, v scanpolicy.SharedSensorsSetting, expectedVersion int, by string, at time.Time) (int, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return 0, err
	}
	var version int
	if expectedVersion == 0 {
		err = r.db.QueryRowContext(ctx, `
			INSERT INTO platform_settings (key, value, version, source, updated_by, updated_at)
			VALUES ($1, $2, 1, 'console', $3, $4)
			ON CONFLICT (key) DO NOTHING
			RETURNING version`, scanpolicy.SharedSensorsSettingKey, raw, by, at).Scan(&version)
	} else {
		err = r.db.QueryRowContext(ctx, `
			UPDATE platform_settings
			   SET value = $2, version = version + 1, source = 'console', updated_by = $3, updated_at = $4
			 WHERE key = $1 AND version = $5
			RETURNING version`, scanpolicy.SharedSensorsSettingKey, raw, by, at, expectedVersion).Scan(&version)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 0, scanpolicy.ErrVersionConflict
	}
	if err != nil {
		return 0, fmt.Errorf("set shared sensor setting: %w", err)
	}
	return version, nil
}

// GetSharedSensorsAccess returns the instance administrator's decision for
// the organization ("" when none).
func (r *ScanPolicyRepository) GetSharedSensorsAccess(ctx context.Context, tenantID shared.ID) (string, error) {
	var v sql.NullString
	err := r.db.QueryRowContext(ctx, `SELECT shared_sensors_access FROM tenants WHERE id = $1`, tenantID.String()).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", shared.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("get organization shared sensor access: %w", err)
	}
	return v.String, nil
}

// SetSharedSensorsAccess sets ("" removes) the decision for the organization.
func (r *ScanPolicyRepository) SetSharedSensorsAccess(ctx context.Context, tenantID shared.ID, decision string) error {
	var v any
	if decision != "" {
		v = decision
	}
	res, err := r.db.ExecContext(ctx, `UPDATE tenants SET shared_sensors_access = $2, updated_at = now() WHERE id = $1`,
		tenantID.String(), v)
	if err != nil {
		return fmt.Errorf("set organization shared sensor access: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// getPlatformSetting decodes the stored value of key into dst and returns
// its version, or scanpolicy.ErrNotFound when nothing is stored.
func (r *ScanPolicyRepository) getPlatformSetting(ctx context.Context, key string, dst any) (int, error) {
	var raw []byte
	var version int
	err := r.db.QueryRowContext(ctx, `SELECT value, version FROM platform_settings WHERE key = $1`, key).Scan(&raw, &version)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, scanpolicy.ErrNotFound
	}
	if err != nil {
		return 0, fmt.Errorf("get platform setting %s: %w", key, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return 0, fmt.Errorf("decode platform setting %s: invalid value", key)
	}
	return version, nil
}

// putPlatformSetting stores value under key when the stored version is
// expectedVersion (0: nothing stored yet), and returns the new version.
func (r *ScanPolicyRepository) putPlatformSetting(ctx context.Context, key string, value any, expectedVersion int, by string, at time.Time) (int, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return 0, err
	}
	var version int
	if expectedVersion == 0 {
		err = r.db.QueryRowContext(ctx, `
			INSERT INTO platform_settings (key, value, version, source, updated_by, updated_at)
			VALUES ($1, $2, 1, 'console', $3, $4)
			ON CONFLICT (key) DO NOTHING
			RETURNING version`, key, raw, by, at).Scan(&version)
	} else {
		err = r.db.QueryRowContext(ctx, `
			UPDATE platform_settings
			   SET value = $2, version = version + 1, source = 'console', updated_by = $3, updated_at = $4
			 WHERE key = $1 AND version = $5
			RETURNING version`, key, raw, by, at, expectedVersion).Scan(&version)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return 0, scanpolicy.ErrVersionConflict
	}
	if err != nil {
		return 0, fmt.Errorf("set platform setting %s: %w", key, err)
	}
	return version, nil
}

var _ scanpolicy.InternalZonesStore = (*ScanPolicyRepository)(nil)

type internalZonesValue struct {
	Allowed *bool `json:"allowed"`
}

// GetInternalZones returns whether shared sensors may scan internal zones,
// or scanpolicy.ErrNotFound when nothing is stored.
func (r *ScanPolicyRepository) GetInternalZones(ctx context.Context) (bool, int, error) {
	var v internalZonesValue
	version, err := r.getPlatformSetting(ctx, scanpolicy.InternalZonesSettingKey, &v)
	if err != nil {
		return false, 0, err
	}
	if v.Allowed == nil {
		return false, 0, fmt.Errorf("decode shared sensor internal zones setting: invalid value")
	}
	return *v.Allowed, version, nil
}

// SetInternalZones stores the setting (optimistic concurrency).
func (r *ScanPolicyRepository) SetInternalZones(ctx context.Context, allowed bool, expectedVersion int, by string, at time.Time) (int, error) {
	return r.putPlatformSetting(ctx, scanpolicy.InternalZonesSettingKey, internalZonesValue{Allowed: &allowed}, expectedVersion, by, at)
}

var _ scanpolicy.AnomalyThresholdsStore = (*ScanPolicyRepository)(nil)

// GetAnomalyThresholds returns the shared sensor anomaly thresholds, or
// scanpolicy.ErrNotFound when nothing is stored.
func (r *ScanPolicyRepository) GetAnomalyThresholds(ctx context.Context) (scanpolicy.AnomalyThresholds, int, error) {
	var v scanpolicy.AnomalyThresholds
	version, err := r.getPlatformSetting(ctx, scanpolicy.AnomalyThresholdsSettingKey, &v)
	if err != nil {
		return scanpolicy.AnomalyThresholds{}, 0, err
	}
	if err := v.Validate(); err != nil {
		return scanpolicy.AnomalyThresholds{}, 0, fmt.Errorf("decode shared sensor anomaly thresholds: invalid value")
	}
	return v, version, nil
}

// SetAnomalyThresholds stores the thresholds (optimistic concurrency).
func (r *ScanPolicyRepository) SetAnomalyThresholds(ctx context.Context, t scanpolicy.AnomalyThresholds, expectedVersion int, by string, at time.Time) (int, error) {
	return r.putPlatformSetting(ctx, scanpolicy.AnomalyThresholdsSettingKey, t, expectedVersion, by, at)
}
