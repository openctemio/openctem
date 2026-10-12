package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"time"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SensorSigningKeyRepository persists the public keys of key-bound sensors
// (sensor_keys, RFC-052). Writes that create keys run inside the pairing
// transaction (sensor_pairing_repository.go); this type reads, stamps use
// and revokes.
type SensorSigningKeyRepository struct {
	db *DB
}

// NewSensorSigningKeyRepository creates a SensorSigningKeyRepository.
func NewSensorSigningKeyRepository(db *DB) *SensorSigningKeyRepository {
	return &SensorSigningKeyRepository{db: db}
}

var _ sensordom.SigningKeyRepository = (*SensorSigningKeyRepository)(nil)

const sensorSigningKeyColumns = `id, tenant_id, sensor_id, thumbprint, public_key, status,
	created_at, activated_at, revoked_at, COALESCE(revoked_reason, ''), last_used_at, host(last_used_ip)`

func scanSigningKey(row interface{ Scan(...any) error }) (*sensordom.SigningKey, error) {
	var (
		k                        sensordom.SigningKey
		id, tenantID, sensorID   string
		status                   string
		activated, revoked, used sql.NullTime
		lastIP                   sql.NullString
	)
	if err := row.Scan(&id, &tenantID, &sensorID, &k.Thumbprint, &k.PublicKey, &status,
		&k.CreatedAt, &activated, &revoked, &k.RevokedReason, &used, &lastIP); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("scan sensor key: %w", err)
	}
	var err error
	if k.ID, err = shared.IDFromString(id); err != nil {
		return nil, err
	}
	if k.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, err
	}
	if k.SensorID, err = shared.IDFromString(sensorID); err != nil {
		return nil, err
	}
	k.Status = sensordom.SigningKeyStatus(status)
	k.ActivatedAt, k.RevokedAt, k.LastUsedAt = nullTimeValue(activated), nullTimeValue(revoked), nullTimeValue(used)
	if lastIP.Valid {
		k.LastUsedIP = net.ParseIP(lastIP.String)
	}
	return &k, nil
}

// GetActiveByThumbprint returns the active key with this thumbprint.
func (r *SensorSigningKeyRepository) GetActiveByThumbprint(ctx context.Context, thumbprint string) (*sensordom.SigningKey, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+sensorSigningKeyColumns+`
		FROM sensor_keys WHERE thumbprint = $1 AND status = 'active'`, thumbprint)
	return scanSigningKey(row)
}

// ListBySensor returns every key of a sensor, newest first.
func (r *SensorSigningKeyRepository) ListBySensor(ctx context.Context, tenantID, sensorID shared.ID) ([]*sensordom.SigningKey, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+sensorSigningKeyColumns+`
		FROM sensor_keys WHERE tenant_id = $1 AND sensor_id = $2
		ORDER BY created_at DESC LIMIT 100`, tenantID.String(), sensorID.String())
	if err != nil {
		return nil, fmt.Errorf("list sensor keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*sensordom.SigningKey
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RecordUse stamps the key's last use (best effort; a revoked key is not
// touched).
func (r *SensorSigningKeyRepository) RecordUse(ctx context.Context, thumbprint string, ip net.IP, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `UPDATE sensor_keys
		SET last_used_at = $2, last_used_ip = COALESCE($3::inet, last_used_ip)
		WHERE thumbprint = $1 AND status = 'active'`, thumbprint, at, heartbeatIP(ip))
	if err != nil {
		return fmt.Errorf("record sensor key use: %w", err)
	}
	return nil
}

// Revoke revokes one pending or active key of a sensor in the tenant.
func (r *SensorSigningKeyRepository) Revoke(ctx context.Context, tenantID, sensorID, keyID shared.ID, reason string, at time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE sensor_keys
		SET status = 'revoked', revoked_at = $5, revoked_reason = $4
		WHERE tenant_id = $1 AND sensor_id = $2 AND id = $3 AND status IN ('pending', 'active')`,
		tenantID.String(), sensorID.String(), keyID.String(), reason, at)
	if err != nil {
		return false, fmt.Errorf("revoke sensor key: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// RevokeAllForSensor revokes every pending or active key of a sensor
// (sensor revoked, deleted or re-paired).
func (r *SensorSigningKeyRepository) RevokeAllForSensor(ctx context.Context, tenantID, sensorID shared.ID, reason string, at time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE sensor_keys
		SET status = 'revoked', revoked_at = $4, revoked_reason = $3
		WHERE tenant_id = $1 AND sensor_id = $2 AND status IN ('pending', 'active')`,
		tenantID.String(), sensorID.String(), reason, at)
	if err != nil {
		return 0, fmt.Errorf("revoke sensor keys: %w", err)
	}
	return res.RowsAffected()
}

// BindToBearerSensor makes an active bearer-key sensor key-bound: the row
// changes kind first (the compare-and-set that lets exactly one of two
// concurrent binds win), the key is inserted active, and every API key of
// the sensor is retired. All or nothing.
func (r *SensorSigningKeyRepository) BindToBearerSensor(ctx context.Context, key *sensordom.SigningKey, at time.Time) (int64, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin key bind: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE sensors
		SET auth_kind = 'key_bound', api_key_hash = $3, api_key_prefix = '', key_expires_at = NULL, updated_at = $4
		WHERE tenant_id = $1 AND id = $2 AND status = 'active' AND NOT is_platform_sensor
		  AND auth_kind IS DISTINCT FROM 'key_bound'`,
		key.TenantID.String(), key.SensorID.String(), sensordom.KeyBoundHashPlaceholder(), at)
	if err != nil {
		return 0, fmt.Errorf("bind sensor: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return 0, sensordom.ErrKeyBindConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sensor_keys
		(id, tenant_id, sensor_id, thumbprint, public_key, status, created_at, activated_at)
		VALUES ($1, $2, $3, $4, $5, 'active', $6, $6)`,
		key.ID.String(), key.TenantID.String(), key.SensorID.String(), key.Thumbprint, key.PublicKey, at); err != nil {
		if isUniqueViolation(err) {
			return 0, sensordom.ErrKeyBindConflict
		}
		return 0, fmt.Errorf("register bound key: %w", err)
	}
	retired, err := execCount(ctx, tx, `UPDATE sensor_api_keys
		SET is_active = FALSE, revoked_at = $2, revoked_reason = $3
		WHERE sensor_id = $1 AND is_active`, key.SensorID.String(), at, sensordom.KeyRevokedBound)
	if err != nil {
		return 0, fmt.Errorf("retire API keys: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit key bind: %w", err)
	}
	return int64(retired), nil
}
