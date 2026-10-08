package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/orgtrust"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// OrgTrustRepository stores trusts between organizations (tenant_trusts).
// Every query names the asking organization as host or home.
type OrgTrustRepository struct {
	db *DB
}

// NewOrgTrustRepository creates an OrgTrustRepository.
func NewOrgTrustRepository(db *DB) *OrgTrustRepository { return &OrgTrustRepository{db: db} }

var _ orgtrust.Repository = (*OrgTrustRepository)(nil)

const orgTrustColumns = `id, host_tenant_id, home_tenant_id, status, max_role, accept_home_sso,
	require_mfa_evidence, home_attests_mfa, allow_api_keys, default_expiry_days,
	requested_by, accepted_by, created_at, updated_at, accepted_at`

// Create inserts a trust; ErrExists for a pair that already has one.
func (r *OrgTrustRepository) Create(ctx context.Context, t *orgtrust.Trust) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO tenant_trusts (`+orgTrustColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		t.ID.String(), t.HostTenantID.String(), t.HomeTenantID.String(), string(t.Status),
		string(t.Settings.MaxRole), t.Settings.AcceptHomeSSO, t.Settings.RequireMFAEvidence,
		t.HomeAttestsMFA, t.Settings.AllowAPIKeys, nullIntPtr(t.Settings.DefaultExpiryDays),
		nullID(t.RequestedBy), nullID(t.AcceptedBy), t.CreatedAt, t.UpdatedAt, nullTime(t.AcceptedAt))
	if isUniqueViolation(err) {
		return orgtrust.ErrExists
	}
	if err != nil {
		return fmt.Errorf("create trust: %w", err)
	}
	return nil
}

// Update writes the mutable fields of a trust, scoped to its host and home.
func (r *OrgTrustRepository) Update(ctx context.Context, t *orgtrust.Trust) error {
	res, err := r.db.ExecContext(ctx, `
		UPDATE tenant_trusts
		SET status = $4, max_role = $5, accept_home_sso = $6, require_mfa_evidence = $7,
		    home_attests_mfa = $8, allow_api_keys = $9, default_expiry_days = $10,
		    accepted_by = $11, accepted_at = $12, updated_at = $13
		WHERE id = $1 AND host_tenant_id = $2 AND home_tenant_id = $3`,
		t.ID.String(), t.HostTenantID.String(), t.HomeTenantID.String(), string(t.Status),
		string(t.Settings.MaxRole), t.Settings.AcceptHomeSSO, t.Settings.RequireMFAEvidence,
		t.HomeAttestsMFA, t.Settings.AllowAPIKeys, nullIntPtr(t.Settings.DefaultExpiryDays),
		nullID(t.AcceptedBy), nullTime(t.AcceptedAt), t.UpdatedAt)
	if err != nil {
		return fmt.Errorf("update trust: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return orgtrust.ErrNotFound
	}
	return nil
}

// GetForTenant returns the trust when tenantID is its host or home.
func (r *OrgTrustRepository) GetForTenant(ctx context.Context, tenantID, id shared.ID) (*orgtrust.Trust, error) {
	return r.one(ctx, `SELECT `+orgTrustColumns+` FROM tenant_trusts
		WHERE id = $1 AND (host_tenant_id = $2 OR home_tenant_id = $2)`, id.String(), tenantID.String())
}

// GetPair returns host → home.
func (r *OrgTrustRepository) GetPair(ctx context.Context, host, home shared.ID) (*orgtrust.Trust, error) {
	return r.one(ctx, `SELECT `+orgTrustColumns+` FROM tenant_trusts
		WHERE host_tenant_id = $1 AND home_tenant_id = $2`, host.String(), home.String())
}

// ListForTenant returns the trusts tenantID is host or home of.
func (r *OrgTrustRepository) ListForTenant(ctx context.Context, tenantID shared.ID) ([]*orgtrust.Trust, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+orgTrustColumns+` FROM tenant_trusts
		WHERE host_tenant_id = $1 OR home_tenant_id = $1
		ORDER BY created_at DESC
		LIMIT 500`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list trusts: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*orgtrust.Trust
	for rows.Next() {
		t, err := scanOrgTrust(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Delete removes the trust when tenantID is its host or home.
func (r *OrgTrustRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM tenant_trusts
		WHERE id = $1 AND (host_tenant_id = $2 OR home_tenant_id = $2)`, id.String(), tenantID.String())
	if err != nil {
		return fmt.Errorf("delete trust: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return orgtrust.ErrNotFound
	}
	return nil
}

func (r *OrgTrustRepository) one(ctx context.Context, q string, args ...any) (*orgtrust.Trust, error) {
	t, err := scanOrgTrust(r.db.QueryRowContext(ctx, q, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, orgtrust.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get trust: %w", err)
	}
	return t, nil
}

func scanOrgTrust(s interface{ Scan(dest ...any) error }) (*orgtrust.Trust, error) {
	var (
		id, host, home, status, maxRole string
		acceptSSO, requireMFA, attests  bool
		allowKeys                       bool
		expiryDays                      sql.NullInt64
		requestedBy, acceptedBy         sql.NullString
		createdAt, updatedAt            time.Time
		acceptedAt                      sql.NullTime
	)
	if err := s.Scan(&id, &host, &home, &status, &maxRole, &acceptSSO, &requireMFA, &attests, &allowKeys,
		&expiryDays, &requestedBy, &acceptedBy, &createdAt, &updatedAt, &acceptedAt); err != nil {
		return nil, err
	}
	t := &orgtrust.Trust{
		ID: shared.MustIDFromString(id), HostTenantID: shared.MustIDFromString(host), HomeTenantID: shared.MustIDFromString(home),
		Status: orgtrust.Status(status),
		Settings: orgtrust.Settings{MaxRole: orgtrust.MaxRole(maxRole), AcceptHomeSSO: acceptSSO,
			RequireMFAEvidence: requireMFA, AllowAPIKeys: allowKeys},
		HomeAttestsMFA: attests, CreatedAt: createdAt, UpdatedAt: updatedAt, AcceptedAt: nullTimeValue(acceptedAt),
	}
	if expiryDays.Valid {
		d := int(expiryDays.Int64)
		t.Settings.DefaultExpiryDays = &d
	}
	if requestedBy.Valid {
		v := shared.MustIDFromString(requestedBy.String)
		t.RequestedBy = &v
	}
	if acceptedBy.Valid {
		v := shared.MustIDFromString(acceptedBy.String)
		t.AcceptedBy = &v
	}
	return t, nil
}
