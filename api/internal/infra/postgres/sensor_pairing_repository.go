package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SensorPairingRepository persists pairing requests (sensor_pairings,
// RFC-052 §4). A default-mode request has no tenant until it is approved;
// the methods that read such rows end in Unscoped and are called only by the
// pairing service (tools/lint/tenantsql).
type SensorPairingRepository struct {
	db          *DB
	limitChecks // sensors: approving a pairing that creates a new sensor
}

// NewSensorPairingRepository creates a SensorPairingRepository.
func NewSensorPairingRepository(db *DB) *SensorPairingRepository {
	return &SensorPairingRepository{db: db}
}

var _ sensordom.PairingRepository = (*SensorPairingRepository)(nil)

const sensorPairingColumns = `id, mode, status, tenant_id, COALESCE(code_hash, ''),
	public_key, COALESCE(thumbprint, ''), commitment, sensor_nonce, platform_nonce, COALESCE(sas, ''),
	host_facts, host(source_ip), repair_sensor_id, sensor_id,
	COALESCE(requested_name, ''), requested_zone_ids, COALESCE(requested_profile, ''),
	created_by, approved_by, approved_at, denied_by, denied_at, confirmed_at, created_at, expires_at,
	instance_token_id, enrollment_token_id, COALESCE(repair_reason, ''), last_refusal, last_refusal_at, last_refusal_details`

func scanPairing(row interface{ Scan(...any) error }) (*sensordom.Pairing, error) {
	var (
		p                                 sensordom.Pairing
		id, mode, status                  string
		tenantID, repairID, sensorID      sql.NullString
		createdBy, approvedBy, deniedBy   sql.NullString
		approvedAt, deniedAt, confirmedAt sql.NullTime
		hostFacts                         []byte
		sourceIP, instanceToken           sql.NullString
		enrollmentToken                   sql.NullString
		zones                             pq.StringArray
		refusal                           sql.NullString
		refusalAt                         sql.NullTime
		refusalDetails                    []byte
	)
	if err := row.Scan(&id, &mode, &status, &tenantID, &p.CodeHash,
		&p.PublicKey, &p.Thumbprint, &p.Commitment, &p.SensorNonce, &p.PlatformNonce, &p.SAS,
		&hostFacts, &sourceIP, &repairID, &sensorID,
		&p.RequestedName, &zones, &p.RequestedProfile,
		&createdBy, &approvedBy, &approvedAt, &deniedBy, &deniedAt, &confirmedAt, &p.CreatedAt, &p.ExpiresAt,
		&instanceToken, &enrollmentToken, &p.RepairReason, &refusal, &refusalAt, &refusalDetails); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sensordom.ErrPairingNotFound
		}
		return nil, fmt.Errorf("scan sensor pairing: %w", err)
	}
	var err error
	if p.ID, err = shared.IDFromString(id); err != nil {
		return nil, err
	}
	p.Mode, p.Status = sensordom.PairingMode(mode), sensordom.PairingStatus(status)
	p.TenantID, p.RepairSensorID, p.SensorID = optionalID(tenantID), optionalID(repairID), optionalID(sensorID)
	p.CreatedBy, p.ApprovedBy, p.DeniedBy = optionalID(createdBy), optionalID(approvedBy), optionalID(deniedBy)
	p.ApprovedAt, p.DeniedAt, p.ConfirmedAt = nullTimeValue(approvedAt), nullTimeValue(deniedAt), nullTimeValue(confirmedAt)
	p.InstanceTokenID, p.EnrollmentTokenID = optionalID(instanceToken), optionalID(enrollmentToken)
	if len(hostFacts) > 0 {
		_ = json.Unmarshal(hostFacts, &p.HostFacts)
	}
	if sourceIP.Valid {
		p.SourceIP = net.ParseIP(sourceIP.String)
	}
	if refusal.Valid && refusalAt.Valid {
		p.LastRefusal = &sensordom.PairingRefusal{Reason: refusal.String, At: refusalAt.Time}
		_ = json.Unmarshal(refusalDetails, &p.LastRefusal.Details)
	}
	for _, z := range zones {
		if zid, err := shared.IDFromString(z); err == nil {
			p.RequestedZoneIDs = append(p.RequestedZoneIDs, zid)
		}
	}
	return &p, nil
}

func idOrNull(id *shared.ID) sql.NullString {
	if id == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: id.String(), Valid: true}
}

func pairingIDStrings(ids []shared.ID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}

// CountOpenUnscoped counts open default-mode requests platform-wide (the
// cap of RFC-052 §4.4).
func (r *SensorPairingRepository) CountOpenUnscoped(ctx context.Context, now time.Time) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sensor_pairings
		WHERE status = 'pending' AND tenant_id IS NULL AND expires_at > $1`, now).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count open pairings: %w", err)
	}
	return n, nil
}

// CreateForward inserts a default-mode request (no tenant).
func (r *SensorPairingRepository) CreateForward(ctx context.Context, p *sensordom.Pairing) error {
	facts, err := json.Marshal(p.HostFacts)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO sensor_pairings
		(id, mode, status, code_hash, public_key, thumbprint, commitment, platform_nonce,
		 host_facts, source_ip, repair_sensor_id, created_at, expires_at)
		VALUES ($1, 'forward', 'pending', $2, $3, $4, $5, $6, $7, $8::inet, $9, $10, $11)`,
		p.ID.String(), nullString(p.CodeHash), p.PublicKey, p.Thumbprint, p.Commitment, p.PlatformNonce,
		facts, heartbeatIP(p.SourceIP), idOrNull(p.RepairSensorID), p.CreatedAt, p.ExpiresAt)
	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("CONFLICT", "pairing code or key already in use", shared.ErrConflict)
		}
		return fmt.Errorf("create pairing: %w", err)
	}
	return nil
}

// AttachToExpectationUnscoped fills the open expectation with this code.
// The expectation keeps its id, tenant, requested settings and re-pair
// target: an ordinary code never becomes a re-pair because the sensor says
// so, and a re-pair code never loses its target. The same key starting again
// with the same code (a restarted sensor) re-arms its own request with the
// new nonces; a code another key already holds matches nothing.
func (r *SensorPairingRepository) AttachToExpectationUnscoped(ctx context.Context, codeHash string, p *sensordom.Pairing, now time.Time) (bool, error) {
	facts, err := json.Marshal(p.HostFacts)
	if err != nil {
		return false, err
	}
	var id string
	var tenant, repair sql.NullString
	err = r.db.QueryRowContext(ctx, `UPDATE sensor_pairings
		SET status = 'pending', public_key = $2, thumbprint = $3, commitment = $4, platform_nonce = $5,
		    host_facts = $6, source_ip = $7::inet,
		    sensor_nonce = NULL, sas = NULL
		WHERE code_hash = $1 AND mode = 'reverse' AND expires_at > $8
		  AND (status = 'expecting' OR (status = 'pending' AND thumbprint = $3))
		RETURNING id, tenant_id, repair_sensor_id`,
		codeHash, p.PublicKey, p.Thumbprint, p.Commitment, p.PlatformNonce, facts, heartbeatIP(p.SourceIP),
		now).Scan(&id, &tenant, &repair)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		if isUniqueViolation(err) {
			return false, nil
		}
		return false, fmt.Errorf("attach to expectation: %w", err)
	}
	if p.ID, err = shared.IDFromString(id); err != nil {
		return false, err
	}
	// The expectation's re-pair target is the console's decision; whatever
	// sensor id the sensor named is not used (RFC-052 §4.6).
	p.Mode, p.Status, p.TenantID, p.RepairSensorID = sensordom.PairingReverse, sensordom.PairingPending, optionalID(tenant), optionalID(repair)
	return true, nil
}

// KeyRegisteredUnscoped reports whether a key with this thumbprint was ever
// registered to a sensor (an approval inserts it; a thumbprint is never
// reused, whatever the key's status or tenant).
func (r *SensorPairingRepository) KeyRegisteredUnscoped(ctx context.Context, thumbprint string) (bool, error) {
	var ok bool
	if err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM sensor_keys WHERE thumbprint = $1)`,
		thumbprint).Scan(&ok); err != nil {
		return false, fmt.Errorf("check sensor key: %w", err)
	}
	return ok, nil
}

// SupersedeForKeyUnscoped closes the open, unapproved requests of the key
// with thumbprint (status pending, whatever their deadline) so the key can
// start a new one, and returns them. The key's own reverse-mode request
// under keepCodeHash that is still within its deadline is kept: the start
// re-arms it. Approved and finished requests are never touched.
func (r *SensorPairingRepository) SupersedeForKeyUnscoped(ctx context.Context, thumbprint, keepCodeHash string, now time.Time) ([]*sensordom.Pairing, error) {
	rows, err := r.db.QueryContext(ctx, `UPDATE sensor_pairings
		SET status = 'expired', expires_at = LEAST(expires_at, $3)
		WHERE thumbprint = $1 AND status = 'pending'
		  AND NOT ($2 <> '' AND mode = 'reverse' AND code_hash = $2 AND expires_at > $3)
		RETURNING `+sensorPairingColumns, thumbprint, keepCodeHash, now)
	if err != nil {
		return nil, fmt.Errorf("supersede pairings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*sensordom.Pairing
	for rows.Next() {
		p, err := scanPairing(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("supersede pairings: %w", err)
	}
	return out, nil
}

// GetForKeyUnscoped returns the request id bound to the key with
// thumbprint; any mismatch is ErrPairingNotFound.
func (r *SensorPairingRepository) GetForKeyUnscoped(ctx context.Context, id shared.ID, thumbprint string) (*sensordom.Pairing, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+sensorPairingColumns+`
		FROM sensor_pairings WHERE id = $1 AND thumbprint = $2`, id.String(), thumbprint)
	return scanPairing(row)
}

// RevealUnscoped stores the sensor nonce and the SAS, once.
func (r *SensorPairingRepository) RevealUnscoped(ctx context.Context, id shared.ID, thumbprint string, sensorNonce []byte, sas string, now time.Time) (bool, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE sensor_pairings SET sensor_nonce = $3, sas = $4
		WHERE id = $1 AND thumbprint = $2 AND status = 'pending' AND sensor_nonce IS NULL AND expires_at > $5`,
		id.String(), thumbprint, sensorNonce, sas, now)
	if err != nil {
		return false, fmt.Errorf("reveal pairing: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// FindOpenByCodeHash returns the open, revealed default-mode request with
// this code.
func (r *SensorPairingRepository) FindOpenByCodeHash(ctx context.Context, codeHash string, now time.Time) (*sensordom.Pairing, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+sensorPairingColumns+`
		FROM sensor_pairings
		WHERE code_hash = $1 AND mode = 'forward' AND status = 'pending' AND tenant_id IS NULL
		  AND sensor_nonce IS NOT NULL AND expires_at > $2`, codeHash, now)
	return scanPairing(row)
}

// CreateExpectation inserts a reverse-mode request for the tenant.
func (r *SensorPairingRepository) CreateExpectation(ctx context.Context, p *sensordom.Pairing) error {
	if p.TenantID == nil {
		return fmt.Errorf("%w: expectation without tenant", shared.ErrValidation)
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO sensor_pairings
		(id, mode, status, tenant_id, code_hash, repair_sensor_id, requested_name, requested_zone_ids,
		 requested_profile, created_by, created_at, expires_at, repair_reason)
		VALUES ($1, 'reverse', 'expecting', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		p.ID.String(), p.TenantID.String(), p.CodeHash, idOrNull(p.RepairSensorID), nullString(p.RequestedName),
		pq.Array(pairingIDStrings(p.RequestedZoneIDs)), nullString(p.RequestedProfile), idOrNull(p.CreatedBy), p.CreatedAt, p.ExpiresAt,
		nullString(p.RepairReason))
	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("CONFLICT", "pairing code already in use", shared.ErrConflict)
		}
		return fmt.Errorf("create expectation: %w", err)
	}
	return nil
}

// CloseOpenRepairs closes the tenant's open (expecting or pending, not yet
// approved) re-pair requests for sensorID: a new re-pair code supersedes
// the earlier ones.
func (r *SensorPairingRepository) CloseOpenRepairs(ctx context.Context, tenantID, sensorID shared.ID, now time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `UPDATE sensor_pairings SET status = 'expired', expires_at = LEAST(expires_at, $3)
		WHERE tenant_id = $1 AND repair_sensor_id = $2 AND status IN ('expecting', 'pending')`,
		tenantID.String(), sensorID.String(), now)
	if err != nil {
		return 0, fmt.Errorf("close open re-pairs: %w", err)
	}
	return res.RowsAffected()
}

// GetForTenant returns a request of the tenant (expectations, and requests
// it approved or denied).
func (r *SensorPairingRepository) GetForTenant(ctx context.Context, tenantID, id shared.ID) (*sensordom.Pairing, error) {
	row := r.db.QueryRowContext(ctx, `SELECT `+sensorPairingColumns+`
		FROM sensor_pairings WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String())
	return scanPairing(row)
}

// Approve binds an open, revealed request to the approver's tenant in one
// transaction: the sensor (new, or the re-paired one with every earlier
// credential revoked), its pending key, its zones, the hook (grant), and the
// request's state. A request another approver won, that expired or that
// belongs to another tenant is ErrPairingNotFound.
func (r *SensorPairingRepository) Approve(ctx context.Context, a sensordom.PairingApproval, repair *shared.ID) (*sensordom.PairingApprovalResult, error) {
	// A re-pair replaces an existing sensor; only a new one counts.
	if repair == nil {
		if err := r.checkLimit(ctx, a.TenantID, limits.Sensors, 1); err != nil {
			return nil, err
		}
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin approve: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	p, err := scanPairing(tx.QueryRowContext(ctx, `SELECT `+sensorPairingColumns+`
		FROM sensor_pairings
		WHERE id = $1 AND status = 'pending' AND sensor_nonce IS NOT NULL AND expires_at > $2
		  AND (tenant_id = $3 OR (tenant_id IS NULL AND code_hash = $4)) AND instance_token_id IS NULL
		FOR UPDATE`, a.PairingID.String(), a.Now, a.TenantID.String(), a.CodeHash))
	if err != nil {
		return nil, err
	}
	target := repair
	if target == nil {
		target = p.RepairSensorID
	}
	out := &sensordom.PairingApprovalResult{Pairing: p}
	if target != nil {
		out.SensorID, out.Repair = *target, true
		res, err := tx.ExecContext(ctx, `UPDATE sensors
			SET auth_kind = 'key_bound', api_key_hash = $3, api_key_prefix = '', key_expires_at = NULL,
			    identity_cloned_at = NULL, updated_at = $4
			WHERE tenant_id = $1 AND id = $2 AND status <> 'revoked' AND scope = 'organization'`,
			a.TenantID.String(), target.String(), sensordom.KeyBoundHashPlaceholder(), a.Now)
		if err != nil {
			return nil, fmt.Errorf("re-pair sensor: %w", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return nil, sensordom.ErrPairingNotFound
		}
		revoked, err := execCount(ctx, tx, `UPDATE sensor_keys
			SET status = 'revoked', revoked_at = $3, revoked_reason = $4
			WHERE tenant_id = $1 AND sensor_id = $2 AND status IN ('pending', 'active')`,
			a.TenantID.String(), target.String(), a.Now, sensordom.KeyRevokedRepaired)
		if err != nil {
			return nil, fmt.Errorf("revoke earlier keys: %w", err)
		}
		out.RevokedKeys = int64(revoked)
		if _, err := tx.ExecContext(ctx, `UPDATE sensor_api_keys
			SET is_active = FALSE, revoked_at = $2, revoked_reason = $3
			WHERE sensor_id = $1 AND is_active`, target.String(), a.Now, sensordom.KeyRevokedRepaired); err != nil {
			return nil, fmt.Errorf("revoke bearer keys: %w", err)
		}
	} else {
		out.SensorID = a.SensorID
		hostname := a.Hostname
		if _, err := tx.ExecContext(ctx, `INSERT INTO sensors
			(id, tenant_id, name, type, description, capabilities, execution_mode, status, health,
			 api_key_hash, api_key_prefix, hostname, version, reported_os, reported_arch,
			 max_concurrent_jobs, auth_kind, created_at, updated_at)
			VALUES ($1, $2, $3, $4, '', '{}', 'daemon', 'active', 'unknown',
			        $5, '', $6, $7, $8, $9, 5, 'key_bound', $10, $10)`,
			a.SensorID.String(), a.TenantID.String(), a.Name, string(a.Type), sensordom.KeyBoundHashPlaceholder(),
			nullString(hostname), nullString(a.Version), nullString(a.OS), nullString(a.Arch), a.Now); err != nil {
			return nil, fmt.Errorf("create paired sensor: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sensor_keys
		(id, tenant_id, sensor_id, thumbprint, public_key, status, created_at)
		VALUES ($1, $2, $3, $4, $5, 'pending', $6)`,
		a.KeyID.String(), a.TenantID.String(), out.SensorID.String(), p.Thumbprint, p.PublicKey, a.Now); err != nil {
		if isUniqueViolation(err) {
			// The key was registered before (a thumbprint is never reused).
			return nil, sensordom.ErrPairingNotFound
		}
		return nil, fmt.Errorf("register sensor key: %w", err)
	}
	for _, z := range a.ZoneIDs {
		res, err := tx.ExecContext(ctx, `INSERT INTO scan_zone_sensors (tenant_id, zone_id, sensor_id, created_by)
			SELECT $1, z.id, $3, $4 FROM scan_zones z WHERE z.tenant_id = $1 AND z.id = $2
			ON CONFLICT DO NOTHING`, a.TenantID.String(), z.String(), out.SensorID.String(), a.ApprovedBy.String())
		if err != nil {
			return nil, fmt.Errorf("assign zone: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			var exists bool
			_ = tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM scan_zones WHERE tenant_id = $1 AND id = $2)`,
				a.TenantID.String(), z.String()).Scan(&exists)
			if !exists {
				return nil, shared.NewDomainError("VALIDATION", "unknown scan zone", shared.ErrValidation)
			}
		}
	}
	if a.OnApproved != nil {
		if err := a.OnApproved(ctx, tx, out.SensorID, out.Repair); err != nil {
			return nil, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sensor_pairings
		SET status = 'approved', tenant_id = $2, sensor_id = $3, approved_by = $4, approved_at = $5, expires_at = $6,
		    requested_name = $7
		WHERE id = $1`, a.PairingID.String(), a.TenantID.String(), out.SensorID.String(), a.ApprovedBy.String(), a.Now, a.ConfirmBy,
		a.Name); err != nil {
		return nil, fmt.Errorf("mark pairing approved: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit approve: %w", err)
	}
	tid, sid, by, at := a.TenantID, out.SensorID, a.ApprovedBy, a.Now
	p.Status, p.TenantID, p.SensorID, p.ApprovedBy, p.ApprovedAt, p.ExpiresAt = sensordom.PairingApproved, &tid, &sid, &by, &at, a.ConfirmBy
	p.RequestedName = a.Name
	return out, nil
}

// Deny refuses an open request (an expectation of the tenant, or a
// default-mode request nobody claimed yet).
func (r *SensorPairingRepository) Deny(ctx context.Context, tenantID, id, actor shared.ID, codeHash string, now time.Time) (*sensordom.Pairing, error) {
	// A tenantless request is refused only with its code, like an approval.
	row := r.db.QueryRowContext(ctx, `UPDATE sensor_pairings
		SET status = 'denied', denied_by = $3, denied_at = $4, tenant_id = COALESCE(tenant_id, $1)
		WHERE id = $2 AND status IN ('expecting', 'pending') AND expires_at > $4
		  AND (tenant_id = $1 OR (tenant_id IS NULL AND $5 <> '' AND code_hash = $5))
		  AND instance_token_id IS NULL
		RETURNING `+sensorPairingColumns, tenantID.String(), id.String(), actor.String(), now, codeHash)
	return scanPairing(row)
}

// ConfirmUnscoped completes an approved request for the key with thumbprint and
// activates its key. Confirming an already completed request again (a
// retried call) returns it unchanged.
func (r *SensorPairingRepository) ConfirmUnscoped(ctx context.Context, id shared.ID, thumbprint string, now time.Time) (*sensordom.Pairing, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin confirm: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	p, err := scanPairing(tx.QueryRowContext(ctx, `SELECT `+sensorPairingColumns+`
		FROM sensor_pairings WHERE id = $1 AND thumbprint = $2 FOR UPDATE`, id.String(), thumbprint))
	if err != nil {
		return nil, err
	}
	switch {
	case p.Status == sensordom.PairingCompleted:
		return p, nil
	case p.Status != sensordom.PairingApproved || !now.Before(p.ExpiresAt) || p.SensorID == nil ||
		(p.TenantID == nil) != p.IsInstance():
		return nil, sensordom.ErrPairingNotFound
	}
	// A shared sensor's key has no tenant (its pairing has none either).
	res, err := tx.ExecContext(ctx, `UPDATE sensor_keys SET status = 'active', activated_at = $4
		WHERE tenant_id IS NOT DISTINCT FROM $1::uuid AND sensor_id = $2 AND thumbprint = $3 AND status = 'pending'`,
		idOrNull(p.TenantID), p.SensorID.String(), thumbprint, now)
	if err != nil {
		return nil, fmt.Errorf("activate sensor key: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return nil, sensordom.ErrPairingNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sensor_pairings SET status = 'completed', confirmed_at = $2 WHERE id = $1`,
		id.String(), now); err != nil {
		return nil, fmt.Errorf("complete pairing: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit confirm: %w", err)
	}
	at := now
	p.Status, p.ConfirmedAt = sensordom.PairingCompleted, &at
	return p, nil
}

// refusalThrottle is the least time between two refusals noted on one
// expectation: a sensor in a retry loop writes at most this often.
const refusalThrottle = 5 * time.Second

// RecordRefusalUnscoped notes a refused attempt on the open expectation with
// this code hash. It runs only for a start whose signature verified; a code
// that matches no open expectation writes nothing (the sensor's answer does
// not depend on it either).
func (r *SensorPairingRepository) RecordRefusalUnscoped(ctx context.Context, codeHash, thumbprint, reason string, details map[string]any, now time.Time) error {
	if codeHash == "" {
		return nil
	}
	raw, err := json.Marshal(details)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `UPDATE sensor_pairings
		SET last_refusal = CASE WHEN $3 = 'code_taken' AND (status = 'expecting' OR thumbprint = $2) THEN 'key_busy' ELSE $3 END,
		    last_refusal_at = $5, last_refusal_details = $4
		WHERE code_hash = $1 AND mode = 'reverse' AND status IN ('expecting', 'pending') AND expires_at > $5
		  AND (last_refusal_at IS NULL OR last_refusal_at <= $6)`,
		codeHash, thumbprint, reason, raw, now, now.Add(-refusalThrottle))
	if err != nil {
		return fmt.Errorf("record pairing refusal: %w", err)
	}
	return nil
}

// RemoveUnconfirmedSensors deletes the sensors created by an approval whose
// pairing expired before the sensor confirmed it (the sweep revoked its only
// key): such a sensor never had a working key, never called in and holds no
// command. A re-pair's registration is never removed.
func (r *SensorPairingRepository) RemoveUnconfirmedSensors(ctx context.Context) ([]sensordom.RemovedSensor, error) {
	rows, err := r.db.QueryContext(ctx, `DELETE FROM sensors s
		USING sensor_pairings p
		WHERE p.status = 'expired' AND p.approved_at IS NOT NULL AND p.confirmed_at IS NULL
		  AND p.repair_sensor_id IS NULL AND p.instance_token_id IS NULL
		  AND p.tenant_id = s.tenant_id AND p.sensor_id = s.id
		  AND s.last_seen_at IS NULL AND s.scope = 'organization'
		  AND NOT EXISTS (SELECT 1 FROM sensor_keys k WHERE k.tenant_id = s.tenant_id AND k.sensor_id = s.id
		                  AND NOT (k.status = 'revoked' AND k.revoked_reason = $1))
		  AND NOT EXISTS (SELECT 1 FROM sensor_api_keys a WHERE a.sensor_id = s.id)
		  AND NOT EXISTS (SELECT 1 FROM commands c WHERE c.tenant_id = s.tenant_id AND c.sensor_id = s.id)
		RETURNING s.tenant_id, s.id, s.name`, sensordom.KeyRevokedUnconfirmed)
	if err != nil {
		return nil, fmt.Errorf("remove unconfirmed sensors: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []sensordom.RemovedSensor
	for rows.Next() {
		var tid, id, name string
		if err := rows.Scan(&tid, &id, &name); err != nil {
			return nil, fmt.Errorf("remove unconfirmed sensors: %w", err)
		}
		t, err1 := shared.IDFromString(tid)
		s, err2 := shared.IDFromString(id)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, sensordom.RemovedSensor{TenantID: t, ID: s, Name: name})
	}
	return out, rows.Err()
}

// ExpireForPlatform expires requests past their deadline, revokes the
// pending key of approvals never confirmed, and purges old rows.
func (r *SensorPairingRepository) ExpireForPlatform(ctx context.Context, now, purgeBefore time.Time) (int64, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin expire: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE sensor_keys k
		SET status = 'revoked', revoked_at = $1, revoked_reason = $2
		FROM sensor_pairings p
		WHERE p.status = 'approved' AND p.expires_at <= $1
		  AND k.tenant_id IS NOT DISTINCT FROM p.tenant_id AND k.sensor_id = p.sensor_id AND k.thumbprint = p.thumbprint
		  AND k.status = 'pending'`, now, sensordom.KeyRevokedUnconfirmed); err != nil {
		return 0, fmt.Errorf("revoke unconfirmed keys: %w", err)
	}
	n, err := execCount(ctx, tx, `UPDATE sensor_pairings SET status = 'expired'
		WHERE status IN ('expecting', 'pending', 'approved') AND expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sensor_pairings
		WHERE created_at < $1 AND status IN ('completed', 'denied', 'expired')`, purgeBefore); err != nil {
		return 0, fmt.Errorf("purge pairings: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit expire: %w", err)
	}
	return int64(n), nil
}
