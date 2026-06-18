package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/scimtoken"
	"github.com/openctemio/api/pkg/domain/shared"
)

// ScimTokenRepository persists SCIM provisioning bearer tokens.
type ScimTokenRepository struct {
	db *DB
}

// NewScimTokenRepository creates the repository.
func NewScimTokenRepository(db *DB) *ScimTokenRepository {
	return &ScimTokenRepository{db: db}
}

func (r *ScimTokenRepository) Create(ctx context.Context, t *scimtoken.ScimToken) error {
	const q = `
		INSERT INTO scim_tokens (id, tenant_id, name, token_hash, token_prefix, status, created_by, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := r.db.ExecContext(ctx, q,
		t.ID().String(),
		t.TenantID().String(),
		t.Name(),
		t.TokenHash(),
		t.Prefix(),
		string(t.Status()),
		nullableID(t.CreatedBy()),
		t.CreatedAt(),
		t.LastUsedAt(),
	)
	if err != nil {
		return fmt.Errorf("insert scim token: %w", err)
	}
	return nil
}

func (r *ScimTokenRepository) GetByHash(ctx context.Context, tokenHash string) (*scimtoken.ScimToken, error) {
	const q = `
		SELECT id, tenant_id, name, token_hash, token_prefix, status, created_by, created_at, last_used_at
		  FROM scim_tokens WHERE token_hash = $1
	`
	return r.scanOne(r.db.QueryRowContext(ctx, q, tokenHash))
}

func (r *ScimTokenRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*scimtoken.ScimToken, error) {
	const q = `
		SELECT id, tenant_id, name, token_hash, token_prefix, status, created_by, created_at, last_used_at
		  FROM scim_tokens WHERE tenant_id = $1 AND id = $2
	`
	return r.scanOne(r.db.QueryRowContext(ctx, q, tenantID.String(), id.String()))
}

func (r *ScimTokenRepository) ListByTenant(ctx context.Context, tenantID shared.ID) ([]*scimtoken.ScimToken, error) {
	const q = `
		SELECT id, tenant_id, name, token_hash, token_prefix, status, created_by, created_at, last_used_at
		  FROM scim_tokens WHERE tenant_id = $1 ORDER BY created_at DESC
	`
	rows, err := r.db.QueryContext(ctx, q, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("query scim tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*scimtoken.ScimToken
	for rows.Next() {
		t, err := r.scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scim tokens: %w", err)
	}
	return out, nil
}

func (r *ScimTokenRepository) Update(ctx context.Context, t *scimtoken.ScimToken) error {
	const q = `UPDATE scim_tokens SET status = $1, last_used_at = $2 WHERE id = $3`
	_, err := r.db.ExecContext(ctx, q, string(t.Status()), t.LastUsedAt(), t.ID().String())
	if err != nil {
		return fmt.Errorf("update scim token: %w", err)
	}
	return nil
}

// TouchLastUsed updates only last_used_at, and only while the token is still
// active — so it can never overwrite a concurrent revoke.
func (r *ScimTokenRepository) TouchLastUsed(ctx context.Context, id shared.ID, at time.Time) error {
	const q = `UPDATE scim_tokens SET last_used_at = $1 WHERE id = $2 AND status = 'active'`
	_, err := r.db.ExecContext(ctx, q, at, id.String())
	if err != nil {
		return fmt.Errorf("touch scim token: %w", err)
	}
	return nil
}

type scimRowScanner interface {
	Scan(dest ...any) error
}

func (r *ScimTokenRepository) scanOne(row *sql.Row) (*scimtoken.ScimToken, error) {
	t, err := r.scanRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, scimtoken.ErrNotFound
	}
	return t, err
}

func (r *ScimTokenRepository) scanRow(s scimRowScanner) (*scimtoken.ScimToken, error) {
	var (
		idStr, tenantStr, name, hash, prefix, status string
		createdBy                                    sql.NullString
		createdAt                                    sql.NullTime
		lastUsedAt                                   sql.NullTime
	)
	if err := s.Scan(&idStr, &tenantStr, &name, &hash, &prefix, &status, &createdBy, &createdAt, &lastUsedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		return nil, fmt.Errorf("scan scim token: %w", err)
	}

	id, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("parse scim token id: %w", err)
	}
	tenantID, err := shared.IDFromString(tenantStr)
	if err != nil {
		return nil, fmt.Errorf("parse scim token tenant id: %w", err)
	}
	var createdByPtr *shared.ID
	if createdBy.Valid {
		cb, perr := shared.IDFromString(createdBy.String)
		if perr == nil {
			createdByPtr = &cb
		}
	}
	var lastUsed *time.Time
	if lastUsedAt.Valid {
		lu := lastUsedAt.Time
		lastUsed = &lu
	}
	var created time.Time
	if createdAt.Valid {
		created = createdAt.Time
	}
	return scimtoken.Reconstruct(id, tenantID, name, hash, prefix, scimtoken.Status(status), createdByPtr, created, lastUsed), nil
}
