package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/app/scopenames"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScopeNameExceptionRepository stores the platform's exceptions to the
// government and military scope rule (scope_name_exceptions). Platform data:
// only console routes reach it.
type ScopeNameExceptionRepository struct {
	db *DB
}

// NewScopeNameExceptionRepository creates the repository.
func NewScopeNameExceptionRepository(db *DB) *ScopeNameExceptionRepository {
	return &ScopeNameExceptionRepository{db: db}
}

var _ scopenames.Repository = (*ScopeNameExceptionRepository)(nil)

const scopeNameExceptionCols = `e.id, e.tenant_id, COALESCE(t.name, ''), e.name, e.include_subdomains, e.reason,
	e.authorization_ref, e.granted_by, e.granted_by_email, e.granted_at, e.expires_at, e.revoked_at,
	COALESCE(e.revoked_by_email, ''), COALESCE(e.revoke_reason, ''), e.updated_at`

func scanScopeNameException(row interface{ Scan(...any) error }) (scopenames.Exception, error) {
	var (
		e         scopenames.Exception
		id, tid   string
		grantedBy sql.NullString
		revokedAt sql.NullTime
	)
	if err := row.Scan(&id, &tid, &e.TenantName, &e.Name, &e.Subdomains, &e.Reason, &e.AuthorizationRef,
		&grantedBy, &e.GrantedByEmail, &e.GrantedAt, &e.ExpiresAt, &revokedAt, &e.RevokedByEmail,
		&e.RevokeReason, &e.UpdatedAt); err != nil {
		return e, err
	}
	var err error
	if e.ID, err = shared.IDFromString(id); err != nil {
		return e, err
	}
	if e.TenantID, err = shared.IDFromString(tid); err != nil {
		return e, err
	}
	if grantedBy.Valid {
		if g, perr := shared.IDFromString(grantedBy.String); perr == nil {
			e.GrantedBy = &g
		}
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		e.RevokedAt = &t
	}
	return e, nil
}

// List returns every exception, newest first (at most 1000).
func (r *ScopeNameExceptionRepository) List(ctx context.Context) ([]scopenames.Exception, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+scopeNameExceptionCols+`
		FROM scope_name_exceptions e LEFT JOIN tenants t ON t.id = e.tenant_id
		ORDER BY e.granted_at DESC, e.id LIMIT 1000`)
	if err != nil {
		return nil, fmt.Errorf("list scope name exceptions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []scopenames.Exception{}
	for rows.Next() {
		e, err := scanScopeNameException(rows)
		if err != nil {
			return nil, fmt.Errorf("scan scope name exception: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListLive returns the exceptions in force at now.
func (r *ScopeNameExceptionRepository) ListLive(ctx context.Context, now time.Time) ([]scopedom.NameException, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT tenant_id, name, include_subdomains, expires_at
		FROM scope_name_exceptions WHERE revoked_at IS NULL AND expires_at > $1`, now)
	if err != nil {
		return nil, fmt.Errorf("list live scope name exceptions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []scopedom.NameException{}
	for rows.Next() {
		var (
			e   scopedom.NameException
			tid string
		)
		if err := rows.Scan(&tid, &e.Name, &e.Subdomains, &e.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan live scope name exception: %w", err)
		}
		if e.TenantID, err = shared.IDFromString(tid); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Get returns one exception.
func (r *ScopeNameExceptionRepository) Get(ctx context.Context, id shared.ID) (scopenames.Exception, error) {
	e, err := scanScopeNameException(r.db.QueryRowContext(ctx, `SELECT `+scopeNameExceptionCols+`
		FROM scope_name_exceptions e LEFT JOIN tenants t ON t.id = e.tenant_id WHERE e.id = $1`, id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return e, scopenames.ErrNotFound
	}
	if err != nil {
		return e, fmt.Errorf("get scope name exception: %w", err)
	}
	return e, nil
}

// Create stores a new exception.
func (r *ScopeNameExceptionRepository) Create(ctx context.Context, e scopenames.Exception) error {
	var by any
	if e.GrantedBy != nil {
		by = e.GrantedBy.String()
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO scope_name_exceptions
		(id, tenant_id, name, include_subdomains, reason, authorization_ref, granted_by, granted_by_email,
		 granted_at, expires_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $9)`,
		e.ID.String(), e.TenantID.String(), e.Name, e.Subdomains, e.Reason, e.AuthorizationRef, by,
		e.GrantedByEmail, e.GrantedAt, e.ExpiresAt)
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return scopenames.ErrDuplicate
	}
	if err != nil {
		return fmt.Errorf("create scope name exception: %w", err)
	}
	return nil
}

// Extend sets the expiry of an exception that is not revoked.
func (r *ScopeNameExceptionRepository) Extend(ctx context.Context, id shared.ID, expiresAt, at time.Time) error {
	res, err := r.db.ExecContext(ctx, `UPDATE scope_name_exceptions SET expires_at = $2, updated_at = $3
		WHERE id = $1 AND revoked_at IS NULL`, id.String(), expiresAt, at)
	if err != nil {
		return fmt.Errorf("extend scope name exception: %w", err)
	}
	return oneRowAffected(res, scopenames.ErrRevoked)
}

// Revoke revokes an exception that is not revoked.
func (r *ScopeNameExceptionRepository) Revoke(ctx context.Context, id shared.ID, byEmail, reason string, at time.Time) error {
	res, err := r.db.ExecContext(ctx, `UPDATE scope_name_exceptions
		SET revoked_at = $2, revoked_by_email = $3, revoke_reason = $4, updated_at = $2
		WHERE id = $1 AND revoked_at IS NULL`, id.String(), at, byEmail, reason)
	if err != nil {
		return fmt.Errorf("revoke scope name exception: %w", err)
	}
	return oneRowAffected(res, scopenames.ErrRevoked)
}
