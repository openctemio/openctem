package postgres

// Instance enrollment tokens and the pairing requests they start
// (docs/rfcs/RFC-100-shared-sensors.md §7). Nothing here has a tenant: a
// shared sensor belongs to the instance. Only the pairing service calls the
// Unscoped methods.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const instanceTokenColumns = `id, token_hash, name, reason, created_by, created_by_email, created_at, expires_at,
	used_at, host(used_from)`

func scanInstanceToken(row interface{ Scan(...any) error }) (*sensordom.InstanceEnrollmentToken, error) {
	var (
		t             sensordom.InstanceEnrollmentToken
		id            string
		createdBy, ip sql.NullString
		usedAt        sql.NullTime
	)
	if err := row.Scan(&id, &t.TokenHash, &t.Name, &t.Reason, &createdBy, &t.CreatedByEmail, &t.CreatedAt, &t.ExpiresAt,
		&usedAt, &ip); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sensordom.ErrPairingNotFound
		}
		return nil, fmt.Errorf("scan instance enrollment token: %w", err)
	}
	var err error
	if t.ID, err = shared.IDFromString(id); err != nil {
		return nil, err
	}
	t.CreatedBy, t.UsedAt = optionalID(createdBy), nullTimeValue(usedAt)
	if ip.Valid {
		t.UsedFrom = net.ParseIP(ip.String)
	}
	return &t, nil
}

// CreateInstanceToken stores a new token (its hash only).
func (r *SensorPairingRepository) CreateInstanceToken(ctx context.Context, t *sensordom.InstanceEnrollmentToken) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO instance_enrollment_tokens
		(id, token_hash, name, reason, created_by, created_by_email, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		t.ID.String(), t.TokenHash, t.Name, t.Reason, idOrNull(t.CreatedBy), t.CreatedByEmail, t.CreatedAt, t.ExpiresAt)
	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("CONFLICT", "enrollment token already exists", shared.ErrConflict)
		}
		return fmt.Errorf("create instance enrollment token: %w", err)
	}
	return nil
}

// GetInstanceTokenUnscoped returns a token by id.
func (r *SensorPairingRepository) GetInstanceTokenUnscoped(ctx context.Context, id shared.ID) (*sensordom.InstanceEnrollmentToken, error) {
	return scanInstanceToken(r.db.QueryRowContext(ctx, `SELECT `+instanceTokenColumns+`
		FROM instance_enrollment_tokens WHERE id = $1`, id.String()))
}

// StartWithInstanceTokenUnscoped spends the token and inserts the pairing
// request bound to it, in one transaction. The first request that presents
// a token wins it; any later one (and an unknown or expired token) gets
// false with nothing written.
func (r *SensorPairingRepository) StartWithInstanceTokenUnscoped(ctx context.Context, tokenHash string, p *sensordom.Pairing, now time.Time) (*sensordom.InstanceEnrollmentToken, bool, error) {
	facts, err := json.Marshal(p.HostFacts)
	if err != nil {
		return nil, false, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, false, fmt.Errorf("begin instance enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	t, err := scanInstanceToken(tx.QueryRowContext(ctx, `UPDATE instance_enrollment_tokens
		SET used_at = $2, used_from = $3::inet
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2
		RETURNING `+instanceTokenColumns, tokenHash, now, heartbeatIP(p.SourceIP)))
	if errors.Is(err, sensordom.ErrPairingNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sensor_pairings
		(id, mode, status, public_key, thumbprint, commitment, platform_nonce, host_facts, source_ip,
		 requested_name, instance_token_id, created_at, expires_at)
		VALUES ($1, 'forward', 'pending', $2, $3, $4, $5, $6, $7::inet, $8, $9, $10, $11)`,
		p.ID.String(), p.PublicKey, p.Thumbprint, p.Commitment, p.PlatformNonce, facts, heartbeatIP(p.SourceIP),
		nullString(t.Name), t.ID.String(), p.CreatedAt, p.ExpiresAt); err != nil {
		if isUniqueViolation(err) {
			// The key has another open request: the token stays unspent.
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("create instance pairing: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, false, fmt.Errorf("commit instance enrollment: %w", err)
	}
	tid := t.ID
	p.InstanceTokenID, p.RequestedName = &tid, t.Name
	return t, true, nil
}

// ApproveInstanceUnscoped approves a revealed request bound to an instance
// token: it creates the shared sensor (scope instance, no tenant; the insert
// trigger sets trust level trusted and the least-privilege grant) and its
// pending key, and marks the request approved. A request that is not open,
// not revealed or not token-bound is ErrPairingNotFound.
func (r *SensorPairingRepository) ApproveInstanceUnscoped(ctx context.Context, a sensordom.InstanceApproval) (*sensordom.PairingApprovalResult, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin instance approve: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	p, err := scanPairing(tx.QueryRowContext(ctx, `SELECT `+sensorPairingColumns+`
		FROM sensor_pairings
		WHERE id = $1 AND status = 'pending' AND sensor_nonce IS NOT NULL AND expires_at > $2
		  AND instance_token_id IS NOT NULL AND tenant_id IS NULL
		FOR UPDATE`, a.PairingID.String(), a.Now))
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sensors
		(id, tenant_id, scope, name, type, description, capabilities, execution_mode, status, health,
		 api_key_hash, api_key_prefix, hostname, version, reported_os, reported_arch,
		 max_concurrent_jobs, auth_kind, created_at, updated_at)
		VALUES ($1, NULL, 'instance', $2, $3, '', '{}', 'daemon', 'active', 'unknown',
		        $4, '', $5, $6, $7, $8, 5, 'key_bound', $9, $9)`,
		a.SensorID.String(), a.Name, string(a.Type), sensordom.KeyBoundHashPlaceholder(),
		nullString(a.Hostname), nullString(a.Version), nullString(a.OS), nullString(a.Arch), a.Now); err != nil {
		return nil, fmt.Errorf("create shared sensor: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sensor_keys
		(id, tenant_id, sensor_id, thumbprint, public_key, status, created_at)
		VALUES ($1, NULL, $2, $3, $4, 'pending', $5)`,
		a.KeyID.String(), a.SensorID.String(), p.Thumbprint, p.PublicKey, a.Now); err != nil {
		if isUniqueViolation(err) {
			return nil, sensordom.ErrPairingNotFound
		}
		return nil, fmt.Errorf("register shared sensor key: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sensor_pairings
		SET status = 'approved', sensor_id = $2, approved_at = $3, expires_at = $4, requested_name = $5
		WHERE id = $1`, a.PairingID.String(), a.SensorID.String(), a.Now, a.ConfirmBy, a.Name); err != nil {
		return nil, fmt.Errorf("mark instance pairing approved: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit instance approve: %w", err)
	}
	sid, at := a.SensorID, a.Now
	p.Status, p.SensorID, p.ApprovedAt, p.ExpiresAt, p.RequestedName = sensordom.PairingApproved, &sid, &at, a.ConfirmBy, a.Name
	return &sensordom.PairingApprovalResult{Pairing: p, SensorID: sid}, nil
}
