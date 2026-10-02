package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SensorAPIKeyRepository persists per-sensor API keys in the sensor_api_keys table.
// This is the multi-key model behind rotation overlap (RFC-014 Phase 3): an
// sensor can hold several keys at once so a renewed key (N+1) coexists with the
// key it replaces (N) during a grace window, and each key carries its own
// expiry, scopes, and usage audit. It is separate from api_keys (tenant/user
// keys) — a different table and concept.
type SensorAPIKeyRepository struct {
	db *DB
	tokenPepper
}

// NewSensorAPIKeyRepository creates a SensorAPIKeyRepository.
func NewSensorAPIKeyRepository(db *DB) *SensorAPIKeyRepository {
	return &SensorAPIKeyRepository{db: db}
}

var _ sensordom.APIKeyRepository = (*SensorAPIKeyRepository)(nil)

const sensorAPIKeyColumns = `
	id, sensor_id, name, key_hash, key_prefix, scopes,
	expires_at, last_used_at, host(last_used_ip), use_count,
	is_active, revoked_at, revoked_reason, created_at`

// Create inserts a new API key.
func (r *SensorAPIKeyRepository) Create(ctx context.Context, key *sensordom.APIKey) error {
	query := `
		INSERT INTO sensor_api_keys (
			id, sensor_id, name, key_hash, key_prefix, scopes,
			expires_at, last_used_at, last_used_ip, use_count,
			is_active, revoked_at, revoked_reason, created_at, key_pepper_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`

	_, err := r.db.ExecContext(ctx, query,
		key.ID.String(),
		key.SensorID.String(),
		key.Name,
		key.KeyHash,
		key.KeyPrefix,
		pq.Array(key.Scopes),
		nullTime(key.ExpiresAt),
		nullTime(key.LastUsedAt),
		nullInet(key.LastUsedIP),
		key.UseCount,
		key.IsActive,
		nullTime(key.RevokedAt),
		nullString(key.RevokedReason),
		key.CreatedAt,
		r.value(),
	)
	if err != nil {
		return fmt.Errorf("create sensor api key: %w", err)
	}
	return nil
}

// GetByID retrieves a key by ID.
func (r *SensorAPIKeyRepository) GetByID(ctx context.Context, id shared.ID) (*sensordom.APIKey, error) {
	query := "SELECT" + sensorAPIKeyColumns + " FROM sensor_api_keys WHERE id = $1"
	return r.scanOne(r.db.QueryRowContext(ctx, query, id.String()))
}

// GetByHash retrieves an ACTIVE key by hash. Revoked/inactive keys are excluded
// so the auth path never resurrects a killed credential. Expiry is enforced by
// the caller via APIKey.IsValid so an expired-but-active key still resolves (and
// is then rejected) rather than silently 404ing.
func (r *SensorAPIKeyRepository) GetByHash(ctx context.Context, hash string) (*sensordom.APIKey, error) {
	query := "SELECT" + sensorAPIKeyColumns + " FROM sensor_api_keys WHERE key_hash = $1 AND is_active = TRUE"
	return r.scanOne(r.db.QueryRowContext(ctx, query, hash))
}

// GetBySensorID retrieves all keys for a sensor, newest first.
func (r *SensorAPIKeyRepository) GetBySensorID(ctx context.Context, sensorID shared.ID) ([]*sensordom.APIKey, error) {
	query := "SELECT" + sensorAPIKeyColumns + " FROM sensor_api_keys WHERE sensor_id = $1 " + orderByCreatedAtDesc
	rows, err := r.db.QueryContext(ctx, query, sensorID.String())
	if err != nil {
		return nil, fmt.Errorf("get keys by sensor: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return r.scanMany(rows)
}

// List lists keys with optional filters.
func (r *SensorAPIKeyRepository) List(ctx context.Context, filter sensordom.APIKeyFilter) ([]*sensordom.APIKey, error) {
	query := "SELECT" + sensorAPIKeyColumns + " FROM sensor_api_keys WHERE 1=1"
	args := []any{}
	i := 1
	if filter.SensorID != nil {
		query += fmt.Sprintf(" AND sensor_id = $%d", i)
		args = append(args, filter.SensorID.String())
		i++
	}
	if filter.IsActive != nil {
		query += fmt.Sprintf(" AND is_active = $%d", i)
		args = append(args, *filter.IsActive)
	}
	query += " " + orderByCreatedAtDesc

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list sensor api keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return r.scanMany(rows)
}

// Update updates a key's mutable fields.
func (r *SensorAPIKeyRepository) Update(ctx context.Context, key *sensordom.APIKey) error {
	query := `
		UPDATE sensor_api_keys
		SET name = $2, scopes = $3, expires_at = $4, last_used_at = $5,
		    last_used_ip = $6, use_count = $7, is_active = $8,
		    revoked_at = $9, revoked_reason = $10
		WHERE id = $1`
	res, err := r.db.ExecContext(ctx, query,
		key.ID.String(),
		key.Name,
		pq.Array(key.Scopes),
		nullTime(key.ExpiresAt),
		nullTime(key.LastUsedAt),
		nullInet(key.LastUsedIP),
		key.UseCount,
		key.IsActive,
		nullTime(key.RevokedAt),
		nullString(key.RevokedReason),
	)
	if err != nil {
		return fmt.Errorf("update sensor api key: %w", err)
	}
	return oneRowAffected(res, sensordom.ErrSensorNotFound)
}

// Delete removes a key.
func (r *SensorAPIKeyRepository) Delete(ctx context.Context, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, "DELETE FROM sensor_api_keys WHERE id = $1", id.String())
	if err != nil {
		return fmt.Errorf("delete sensor api key: %w", err)
	}
	return oneRowAffected(res, sensordom.ErrSensorNotFound)
}

// RecordUsage bumps use_count and last-used fields. Best-effort: a missing row
// is not an error (the key may have been revoked between auth and this async
// update).
func (r *SensorAPIKeyRepository) RecordUsage(ctx context.Context, id shared.ID, ip string) error {
	query := `
		UPDATE sensor_api_keys
		SET use_count = use_count + 1, last_used_at = NOW(), last_used_ip = $2
		WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id.String(), nullInet(ip))
	if err != nil {
		return fmt.Errorf("record sensor api key usage: %w", err)
	}
	return nil
}

// Revoke deactivates a key with a reason.
func (r *SensorAPIKeyRepository) Revoke(ctx context.Context, id shared.ID, reason string) error {
	query := `
		UPDATE sensor_api_keys
		SET is_active = FALSE, revoked_at = NOW(), revoked_reason = $2
		WHERE id = $1 AND is_active = TRUE`
	res, err := r.db.ExecContext(ctx, query, id.String(), nullString(reason))
	if err != nil {
		return fmt.Errorf("revoke sensor api key: %w", err)
	}
	return oneRowAffected(res, sensordom.ErrSensorNotFound)
}

// CountActiveBySensorID counts active keys for a sensor.
func (r *SensorAPIKeyRepository) CountActiveBySensorID(ctx context.Context, sensorID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM sensor_api_keys WHERE sensor_id = $1 AND is_active = TRUE",
		sensorID.String()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count active sensor api keys: %w", err)
	}
	return n, nil
}

// RetireKeys brings the expiry of the sensor's active, non-revoked keys
// forward to at — never later than an expiry they already have. With newest
// set, only keys created before that key are touched, compared on
// (created_at, id) as stored, so of two concurrent renewals the newer key is
// never retired by the older one. It writes expires_at alone, so a
// concurrent revoke is not undone.
func (r *SensorAPIKeyRepository) RetireKeys(ctx context.Context, sensorID shared.ID, newest *shared.ID, at time.Time) (int64, error) {
	var (
		res sql.Result
		err error
	)
	if newest != nil {
		res, err = r.db.ExecContext(ctx, `
			UPDATE sensor_api_keys k
			SET expires_at = $3
			FROM sensor_api_keys n
			WHERE n.id = $2 AND n.sensor_id = $1
			  AND k.sensor_id = $1
			  AND k.is_active AND k.revoked_at IS NULL
			  AND (k.created_at, k.id) < (n.created_at, n.id)
			  AND (k.expires_at IS NULL OR k.expires_at > $3)`,
			sensorID.String(), newest.String(), at)
	} else {
		res, err = r.db.ExecContext(ctx, `
			UPDATE sensor_api_keys
			SET expires_at = $2
			WHERE sensor_id = $1
			  AND is_active AND revoked_at IS NULL
			  AND (expires_at IS NULL OR expires_at > $2)`,
			sensorID.String(), at)
	}
	if err != nil {
		return 0, fmt.Errorf("retire sensor api keys: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func (r *SensorAPIKeyRepository) scanOne(row *sql.Row) (*sensordom.APIKey, error) {
	k, err := r.scan(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sensordom.ErrSensorNotFound
	}
	return k, err
}

func (r *SensorAPIKeyRepository) scanMany(rows *sql.Rows) ([]*sensordom.APIKey, error) {
	keys := make([]*sensordom.APIKey, 0)
	for rows.Next() {
		k, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (r *SensorAPIKeyRepository) scan(s rowScanner) (*sensordom.APIKey, error) {
	var (
		k          sensordom.APIKey
		id         string
		sensorID   string
		scopes     pq.StringArray
		expiresAt  sql.NullTime
		lastUsedAt sql.NullTime
		lastUsedIP sql.NullString
		revokedAt  sql.NullTime
		revoked    sql.NullString
	)
	if err := s.Scan(
		&id, &sensorID, &k.Name, &k.KeyHash, &k.KeyPrefix, &scopes,
		&expiresAt, &lastUsedAt, &lastUsedIP, &k.UseCount,
		&k.IsActive, &revokedAt, &revoked, &k.CreatedAt,
	); err != nil {
		return nil, err
	}
	k.ID, _ = shared.IDFromString(id)
	k.SensorID, _ = shared.IDFromString(sensorID)
	k.Scopes = scopes
	k.ExpiresAt = nullTimeValue(expiresAt)
	k.LastUsedAt = nullTimeValue(lastUsedAt)
	k.LastUsedIP = nullStringValue(lastUsedIP)
	k.RevokedAt = nullTimeValue(revokedAt)
	k.RevokedReason = nullStringValue(revoked)
	return &k, nil
}

// nullInet maps an IP string to a NULL-able INET value; empty → NULL.
func nullInet(ip string) any {
	if ip == "" {
		return nil
	}
	return ip
}

// oneRowAffected maps a zero-row result to notFound.
func oneRowAffected(res sql.Result, notFound error) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return notFound
	}
	return nil
}

// RehashKey replaces the stored hash of a renewed sensor key row made with an earlier pepper
// by its hash under the current pepper, only while the stored hash is still
// oldHash. Reports whether the row changed.
func (r *SensorAPIKeyRepository) RehashKey(ctx context.Context, id shared.ID, oldHash, newHash string) (bool, error) {
	return r.rehash(ctx, r.db, sensorRowTokens, id, oldHash, newHash)
}

// CountKeysNotUnderPepper counts active tokens not hashed with the current
// pepper (they still need APP_ENCRYPTION_KEY_PREVIOUS).
func (r *SensorAPIKeyRepository) CountKeysNotUnderPepper(ctx context.Context) (int, error) {
	return r.countNotCurrent(ctx, r.db, sensorRowTokens)
}
