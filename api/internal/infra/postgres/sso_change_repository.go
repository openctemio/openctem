package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ssochange"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// SSOChangeRepository persists organization SSO changes that wait for an
// owner's approval (see pkg/domain/ssochange).
type SSOChangeRepository struct {
	db *DB
}

// NewSSOChangeRepository creates the repository.
func NewSSOChangeRepository(db *DB) *SSOChangeRepository {
	return &SSOChangeRepository{db: db}
}

var _ ssochange.Repository = (*SSOChangeRepository)(nil)

const ssoChangeColumns = `
	id, tenant_id, kind, target_id, payload, COALESCE(secret_encrypted, ''), status,
	requested_by_admin, requested_by_email, created_at, expires_at, decided_at, decided_by
`

// Create stores c and supersedes any earlier pending change for the same
// organization, kind and target, so an owner never approves a stale proposal
// that a later one replaced.
func (r *SSOChangeRepository) Create(ctx context.Context, c *ssochange.Change) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			UPDATE sso_pending_changes
			   SET status = 'superseded', decided_at = NOW(), secret_encrypted = NULL
			 WHERE tenant_id = $1 AND kind = $2
			   AND COALESCE(target_id::text, '') = $3
			   AND status = 'pending'`,
			c.TenantID.String(), string(c.Kind), c.TargetID,
		); err != nil {
			return fmt.Errorf("supersede pending sso changes: %w", err)
		}

		var requestedBy, target, secret any
		if c.RequestedByAdmin != nil {
			requestedBy = c.RequestedByAdmin.String()
		}
		if c.TargetID != "" {
			target = c.TargetID
		}
		if c.SecretEncrypted != "" {
			secret = c.SecretEncrypted
		}
		payload := []byte(c.Payload)
		if len(payload) == 0 {
			payload = []byte("{}")
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sso_pending_changes
			    (id, tenant_id, kind, target_id, payload, secret_encrypted, status,
			     requested_by_admin, requested_by_email, created_at, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, $8, $9, $10)`,
			c.ID.String(), c.TenantID.String(), string(c.Kind), target, payload, secret,
			requestedBy, c.RequestedByEmail, c.CreatedAt, c.ExpiresAt,
		); err != nil {
			return fmt.Errorf("insert sso change: %w", err)
		}
		return nil
	})
}

// Get returns one change of the organization.
func (r *SSOChangeRepository) Get(ctx context.Context, tenantID, id shared.ID) (*ssochange.Change, error) {
	row := r.db.QueryRowContext(ctx,
		`SELECT `+ssoChangeColumns+` FROM sso_pending_changes WHERE id = $1 AND tenant_id = $2`,
		id.String(), tenantID.String())
	c, err := scanSSOChange(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ssochange.ErrNotFound
	}
	return c, err
}

// List returns the organization's changes, newest first.
func (r *SSOChangeRepository) List(ctx context.Context, tenantID shared.ID, pendingOnly bool, limit int) ([]*ssochange.Change, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := `SELECT ` + ssoChangeColumns + ` FROM sso_pending_changes WHERE tenant_id = $1`
	if pendingOnly {
		q += ` AND status = 'pending' AND expires_at > NOW()`
	}
	q += ` ORDER BY created_at DESC LIMIT $2`
	rows, err := r.db.QueryContext(ctx, q, tenantID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("list sso changes: %w", err)
	}
	defer rows.Close()
	var out []*ssochange.Change
	for rows.Next() {
		c, err := scanSSOChange(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Approve claims the change and writes the live config in one transaction:
// either both happen or neither does, and two owners approving at once cannot
// both apply it (the claim is a conditional UPDATE on status = 'pending').
func (r *SSOChangeRepository) Approve(ctx context.Context, tenantID, id, decidedBy shared.ID, write ssochange.LiveWrite) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if err := decideSSOChange(ctx, tx, tenantID, id, decidedBy, ssochange.StatusApproved); err != nil {
			return err
		}
		switch {
		case write.SAML != nil:
			if write.SAML.TenantID() != tenantID {
				return fmt.Errorf("%w: saml config belongs to another organization", shared.ErrValidation)
			}
			return upsertSAMLProvider(ctx, tx, write.SAML)
		case write.IdPCreate != nil:
			if write.IdPCreate.TenantID() != tenantID.String() {
				return fmt.Errorf("%w: identity provider belongs to another organization", shared.ErrValidation)
			}
			return createIdentityProvider(ctx, tx, write.IdPCreate)
		case write.IdPUpdate != nil:
			if write.IdPUpdate.TenantID() != tenantID.String() {
				return fmt.Errorf("%w: identity provider belongs to another organization", shared.ErrValidation)
			}
			return updateIdentityProvider(ctx, tx, write.IdPUpdate)
		case write.DomainJIT != nil:
			if write.DomainJIT.TenantID() != tenantID {
				return fmt.Errorf("%w: domain belongs to another organization", shared.ErrValidation)
			}
			on, role := write.DomainJIT.JIT()
			res, err := tx.ExecContext(ctx,
				`UPDATE verified_domains SET jit_enabled = $3, jit_role = $4, updated_at = NOW() WHERE id = $1 AND tenant_id = $2`,
				write.DomainJIT.ID().String(), tenantID.String(), on, nullString(role))
			if err != nil {
				return fmt.Errorf("apply domain jit: %w", err)
			}
			if n, _ := res.RowsAffected(); n != 1 {
				return verifieddomain.ErrNotFound
			}
			return nil
		}
		return fmt.Errorf("%w: approval has nothing to apply", shared.ErrValidation)
	})
}

// Reject marks the change rejected and drops its secret.
func (r *SSOChangeRepository) Reject(ctx context.Context, tenantID, id, decidedBy shared.ID) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		return decideSSOChange(ctx, tx, tenantID, id, decidedBy, ssochange.StatusRejected)
	})
}

// decideSSOChange moves a pending, unexpired change to status. When no row
// qualifies it reports why: not found, expired, or already
// decided.
func decideSSOChange(ctx context.Context, tx *sql.Tx, tenantID, id, decidedBy shared.ID, status ssochange.Status) error {
	res, err := tx.ExecContext(ctx, `
		UPDATE sso_pending_changes
		   SET status = $4, decided_at = NOW(), decided_by = $3, secret_encrypted = NULL
		 WHERE id = $1 AND tenant_id = $2 AND status = 'pending' AND expires_at > NOW()`,
		id.String(), tenantID.String(), decidedBy.String(), string(status))
	if err != nil {
		return fmt.Errorf("decide sso change: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("decide sso change: %w", err)
	} else if n == 1 {
		return nil
	}

	var current string
	var expiresAt time.Time
	err = tx.QueryRowContext(ctx,
		`SELECT status, expires_at FROM sso_pending_changes WHERE id = $1 AND tenant_id = $2`,
		id.String(), tenantID.String()).Scan(&current, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ssochange.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("read sso change: %w", err)
	}
	if ssochange.Status(current) == ssochange.StatusPending || ssochange.Status(current) == ssochange.StatusExpired {
		return ssochange.ErrExpired
	}
	return ssochange.ErrNotPending
}

type ssoChangeScanner interface {
	Scan(dest ...any) error
}

func scanSSOChange(s ssoChangeScanner) (*ssochange.Change, error) {
	var (
		idStr, tenantStr, kind, status, email, secret string
		target, requestedBy, decidedBy                sql.NullString
		payload                                       []byte
		createdAt, expiresAt                          time.Time
		decidedAt                                     sql.NullTime
	)
	if err := s.Scan(&idStr, &tenantStr, &kind, &target, &payload, &secret, &status,
		&requestedBy, &email, &createdAt, &expiresAt, &decidedAt, &decidedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("scan sso change: %w", err)
	}
	id, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse sso change id: %w", err)
	}
	tenantID, err := shared.IDFromString(tenantStr)
	if err != nil {
		return nil, fmt.Errorf("parse sso change tenant: %w", err)
	}
	c := &ssochange.Change{
		ID:               id,
		TenantID:         tenantID,
		Kind:             ssochange.Kind(kind),
		TargetID:         target.String,
		Payload:          payload,
		SecretEncrypted:  secret,
		Status:           ssochange.Status(status),
		RequestedByEmail: email,
		CreatedAt:        createdAt,
		ExpiresAt:        expiresAt,
	}
	if requestedBy.Valid {
		if aid, err := shared.IDFromString(requestedBy.String); err == nil {
			c.RequestedByAdmin = &aid
		}
	}
	if decidedAt.Valid {
		t := decidedAt.Time
		c.DecidedAt = &t
	}
	if decidedBy.Valid {
		if uid, err := shared.IDFromString(decidedBy.String); err == nil {
			c.DecidedBy = &uid
		}
	}
	return c, nil
}
