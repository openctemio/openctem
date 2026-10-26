package postgres

// Organization enrollment tokens and the pairing requests they start
// (docs/architecture/sensor-pairing.md, "Enrollment tokens"). Every
// user-plane query is scoped by tenant; only the pairing service calls the
// Unscoped methods, from a sensor's signed start request, and the tenant of
// the request then comes from the token row, never from the sensor.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/lib/pq"

	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ sensordom.EnrollmentTokenRepository = (*SensorPairingRepository)(nil)

const enrollmentTokenColumns = `id, tenant_id, name, token_hash, token_hint, max_uses, use_count, require_approval,
	sensor_type, grant_profile, zone_ids, labels, allowed_cidrs::text[], created_by, created_at, expires_at,
	last_used_at, host(last_used_from), revoked_at, revoked_by`

func scanEnrollmentToken(row interface{ Scan(...any) error }) (*sensordom.EnrollmentToken, error) {
	var (
		t                                sensordom.EnrollmentToken
		id, tenantID, sensorType         string
		zones, cidrs                     pq.StringArray
		labels                           []byte
		createdBy, revokedBy, lastUsedIP sql.NullString
		lastUsedAt, revokedAt            sql.NullTime
	)
	if err := row.Scan(&id, &tenantID, &t.Name, &t.TokenHash, &t.TokenHint, &t.MaxUses, &t.UseCount,
		&t.RequireApproval, &sensorType, &t.GrantProfile, &zones, &labels, &cidrs, &createdBy, &t.CreatedAt,
		&t.ExpiresAt, &lastUsedAt, &lastUsedIP, &revokedAt, &revokedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sensordom.ErrPairingNotFound
		}
		return nil, fmt.Errorf("scan enrollment token: %w", err)
	}
	var err error
	if t.ID, err = shared.IDFromString(id); err != nil {
		return nil, err
	}
	if t.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, err
	}
	t.SensorType = sensordom.SensorType(sensorType)
	for _, z := range zones {
		if zid, err := shared.IDFromString(z); err == nil {
			t.ZoneIDs = append(t.ZoneIDs, zid)
		}
	}
	for _, c := range cidrs {
		if p, err := netip.ParsePrefix(c); err == nil {
			t.AllowedCIDRs = append(t.AllowedCIDRs, p)
		}
	}
	if len(labels) > 0 {
		_ = json.Unmarshal(labels, &t.Labels)
	}
	t.CreatedBy, t.RevokedBy = optionalID(createdBy), optionalID(revokedBy)
	t.LastUsedAt, t.RevokedAt = nullTimeValue(lastUsedAt), nullTimeValue(revokedAt)
	if lastUsedIP.Valid {
		t.LastUsedFrom = net.ParseIP(lastUsedIP.String)
	}
	return &t, nil
}

func cidrStrings(ps []netip.Prefix) pq.StringArray {
	out := make(pq.StringArray, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Masked().String())
	}
	return out
}

// CreateEnrollmentToken stores a new token (its hash only).
func (r *SensorPairingRepository) CreateEnrollmentToken(ctx context.Context, t *sensordom.EnrollmentToken) error {
	labels, err := json.Marshal(t.Labels)
	if err != nil {
		return err
	}
	if t.Labels == nil {
		labels = []byte("{}")
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO sensor_enrollment_tokens
		(id, tenant_id, name, token_hash, token_hint, max_uses, require_approval, sensor_type, grant_profile,
		 zone_ids, labels, allowed_cidrs, created_by, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::uuid[], $11, $12::cidr[], $13, $14, $15)`,
		t.ID.String(), t.TenantID.String(), t.Name, t.TokenHash, t.TokenHint, t.MaxUses, t.RequireApproval,
		string(t.SensorType), t.GrantProfile, pq.Array(uuidStrings(t.ZoneIDs)), labels, cidrStrings(t.AllowedCIDRs),
		idOrNull(t.CreatedBy), t.CreatedAt, t.ExpiresAt)
	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("CONFLICT", "enrollment token already exists", shared.ErrConflict)
		}
		return fmt.Errorf("create enrollment token: %w", err)
	}
	return nil
}

// ListEnrollmentTokens returns the tenant's tokens, newest first.
func (r *SensorPairingRepository) ListEnrollmentTokens(ctx context.Context, tenantID shared.ID, limit int) ([]*sensordom.EnrollmentToken, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+enrollmentTokenColumns+`
		FROM sensor_enrollment_tokens WHERE tenant_id = $1
		ORDER BY created_at DESC, id DESC LIMIT $2`, tenantID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list enrollment tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*sensordom.EnrollmentToken, 0)
	for rows.Next() {
		t, err := scanEnrollmentToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeEnrollmentToken revokes an unrevoked token of the tenant.
func (r *SensorPairingRepository) RevokeEnrollmentToken(ctx context.Context, tenantID, id, by shared.ID, now time.Time) (*sensordom.EnrollmentToken, error) {
	return scanEnrollmentToken(r.db.QueryRowContext(ctx, `UPDATE sensor_enrollment_tokens
		SET revoked_at = $3, revoked_by = $4
		WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL
		RETURNING `+enrollmentTokenColumns, tenantID.String(), id.String(), now, by.String()))
}

// ZonesInTenant reports whether every id is a scan zone of the tenant.
func (r *SensorPairingRepository) ZonesInTenant(ctx context.Context, tenantID shared.ID, ids []shared.ID) (bool, error) {
	if len(ids) == 0 {
		return true, nil
	}
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(DISTINCT id) FROM scan_zones
		WHERE tenant_id = $1 AND id = ANY($2::uuid[])`, tenantID.String(), pq.Array(uuidStrings(ids))).Scan(&n); err != nil {
		return false, fmt.Errorf("check scan zones: %w", err)
	}
	seen := map[shared.ID]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	return n == len(seen), nil
}

// GetEnrollmentTokenUnscoped returns a token by id.
func (r *SensorPairingRepository) GetEnrollmentTokenUnscoped(ctx context.Context, id shared.ID) (*sensordom.EnrollmentToken, error) {
	return scanEnrollmentToken(r.db.QueryRowContext(ctx, `SELECT `+enrollmentTokenColumns+`
		FROM sensor_enrollment_tokens WHERE id = $1`, id.String()))
}

// StartWithEnrollmentTokenUnscoped checks and spends the token and inserts
// the request bound to its tenant, in one transaction (the token row is
// locked, so concurrent starts cannot spend more uses than it has). A use
// is a sensor key: the same key starting again (its earlier request
// expired while waiting for approval) spends nothing.
func (r *SensorPairingRepository) StartWithEnrollmentTokenUnscoped(ctx context.Context, tokenHash string, p *sensordom.Pairing, now time.Time) (*sensordom.EnrollmentToken, sensordom.EnrollmentRefusal, error) {
	facts, err := json.Marshal(p.HostFacts)
	if err != nil {
		return nil, sensordom.EnrollmentUnknown, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, sensordom.EnrollmentUnknown, fmt.Errorf("begin enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	t, err := scanEnrollmentToken(tx.QueryRowContext(ctx, `SELECT `+enrollmentTokenColumns+`
		FROM sensor_enrollment_tokens WHERE token_hash = $1 FOR UPDATE`, tokenHash))
	if errors.Is(err, sensordom.ErrPairingNotFound) {
		return nil, sensordom.EnrollmentUnknown, nil
	}
	if err != nil {
		return nil, sensordom.EnrollmentUnknown, err
	}
	var seenKey, creatorActive bool
	if err := tx.QueryRowContext(ctx, `SELECT
		EXISTS (SELECT 1 FROM sensor_pairings WHERE enrollment_token_id = $1 AND thumbprint = $2),
		EXISTS (SELECT 1 FROM tenant_members m WHERE m.tenant_id = $3 AND m.user_id = $4 AND m.status = 'active')`,
		t.ID.String(), p.Thumbprint, t.TenantID.String(), idOrNull(t.CreatedBy)).Scan(&seenKey, &creatorActive); err != nil {
		return t, sensordom.EnrollmentUnknown, fmt.Errorf("check enrollment token: %w", err)
	}
	switch {
	case t.RevokedAt != nil:
		return t, sensordom.EnrollmentRevoked, nil
	case !now.Before(t.ExpiresAt):
		return t, sensordom.EnrollmentExpired, nil
	case !seenKey && t.UseCount >= t.MaxUses:
		return t, sensordom.EnrollmentExhausted, nil
	case !t.AllowsSource(p.SourceIP):
		return t, sensordom.EnrollmentSourceRefused, nil
	case t.CreatedBy == nil || !creatorActive:
		return t, sensordom.EnrollmentCreatorGone, nil
	}
	spend := 0
	if !seenKey {
		spend = 1
	}
	if _, err := tx.ExecContext(ctx, `UPDATE sensor_enrollment_tokens
		SET use_count = use_count + $2, last_used_at = $3, last_used_from = $4::inet
		WHERE id = $1`, t.ID.String(), spend, now, heartbeatIP(p.SourceIP)); err != nil {
		return t, sensordom.EnrollmentUnknown, fmt.Errorf("spend enrollment token: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO sensor_pairings
		(id, mode, status, tenant_id, public_key, thumbprint, commitment, platform_nonce, host_facts, source_ip,
		 requested_name, requested_zone_ids, requested_profile, created_by, enrollment_token_id, created_at, expires_at)
		VALUES ($1, 'forward', 'pending', $2, $3, $4, $5, $6, $7, $8::inet, $9, $10::uuid[], $11, $12, $13, $14, $15)`,
		p.ID.String(), t.TenantID.String(), p.PublicKey, p.Thumbprint, p.Commitment, p.PlatformNonce, facts,
		heartbeatIP(p.SourceIP), nullString(p.RequestedName), pq.Array(uuidStrings(t.ZoneIDs)), nullString(t.GrantProfile),
		idOrNull(t.CreatedBy), t.ID.String(), p.CreatedAt, p.ExpiresAt); err != nil {
		if isUniqueViolation(err) {
			// The key has another open request: nothing is spent.
			return t, sensordom.EnrollmentKeyBusy, nil
		}
		return t, sensordom.EnrollmentUnknown, fmt.Errorf("create enrollment pairing: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return t, sensordom.EnrollmentUnknown, fmt.Errorf("commit enrollment: %w", err)
	}
	t.UseCount += spend
	tid, eid := t.TenantID, t.ID
	p.TenantID, p.EnrollmentTokenID = &tid, &eid
	p.RequestedZoneIDs, p.RequestedProfile, p.CreatedBy = t.ZoneIDs, t.GrantProfile, t.CreatedBy
	return t, sensordom.EnrollmentOK, nil
}

// ListPendingForTenant returns the tenant's open, revealed requests that
// wait for an administrator.
func (r *SensorPairingRepository) ListPendingForTenant(ctx context.Context, tenantID shared.ID, now time.Time, limit int) ([]*sensordom.Pairing, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+sensorPairingColumns+`
		FROM sensor_pairings
		WHERE tenant_id = $1 AND status = 'pending' AND sensor_nonce IS NOT NULL AND expires_at > $2
		ORDER BY created_at DESC LIMIT $3`, tenantID.String(), now, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending pairings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*sensordom.Pairing, 0)
	for rows.Next() {
		p, err := scanPairing(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
