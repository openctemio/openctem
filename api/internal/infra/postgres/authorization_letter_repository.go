package postgres

// Authorization letters (RFC-065 §13). Every statement carries the tenant.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AuthorizationLetterRepository implements scope.LetterRepository.
type AuthorizationLetterRepository struct{ db *DB }

var _ scope.LetterRepository = (*AuthorizationLetterRepository)(nil)

// NewAuthorizationLetterRepository creates the repository.
func NewAuthorizationLetterRepository(db *DB) *AuthorizationLetterRepository {
	return &AuthorizationLetterRepository{db: db}
}

const letterColumns = `id, tenant_id, title, issuer, reference, valid_from, valid_until, attachment_id,
	file_sha256, uploaded_by, created_at, revoked_at, revoked_by`

// Create stores a letter.
func (r *AuthorizationLetterRepository) Create(ctx context.Context, l *scope.Letter) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO authorization_letters (`+letterColumns+`)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		l.ID.String(), l.TenantID.String(), l.Title, l.Issuer, l.Reference, l.ValidFrom, l.ValidUntil,
		l.AttachmentID.String(), l.FileSHA256, nullIDPtr(l.UploadedBy), l.CreatedAt, l.RevokedAt, nullIDPtr(l.RevokedBy))
	if err != nil {
		return fmt.Errorf("create authorization letter: %w", err)
	}
	return nil
}

func scanLetter(row interface{ Scan(...any) error }) (*scope.Letter, error) {
	var (
		l                     scope.Letter
		id, tid, attachment   string
		uploadedBy, revokedBy sql.NullString
		revokedAt             sql.NullTime
	)
	if err := row.Scan(&id, &tid, &l.Title, &l.Issuer, &l.Reference, &l.ValidFrom, &l.ValidUntil, &attachment,
		&l.FileSHA256, &uploadedBy, &l.CreatedAt, &revokedAt, &revokedBy); err != nil {
		return nil, err
	}
	l.ID, _ = shared.IDFromString(id)
	l.TenantID, _ = shared.IDFromString(tid)
	l.AttachmentID, _ = shared.IDFromString(attachment)
	l.UploadedBy, l.RevokedBy = idPtr(uploadedBy), idPtr(revokedBy)
	if revokedAt.Valid {
		t := revokedAt.Time
		l.RevokedAt = &t
	}
	return &l, nil
}

// GetByID returns one letter of the tenant.
func (r *AuthorizationLetterRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*scope.Letter, error) {
	l, err := scanLetter(r.db.QueryRowContext(ctx, `SELECT `+letterColumns+` FROM authorization_letters
		WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, scope.ErrLetterNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get authorization letter: %w", err)
	}
	return l, nil
}

// List lists the tenant's letters, newest first.
func (r *AuthorizationLetterRepository) List(ctx context.Context, tenantID shared.ID) ([]*scope.Letter, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+letterColumns+` FROM authorization_letters
		WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT 500`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list authorization letters: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*scope.Letter
	for rows.Next() {
		l, err := scanLetter(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// Revoke marks a letter revoked once.
func (r *AuthorizationLetterRepository) Revoke(ctx context.Context, tenantID, id, by shared.ID, at time.Time) error {
	res, err := r.db.ExecContext(ctx, `UPDATE authorization_letters SET revoked_at = $3, revoked_by = $4
		WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`, tenantID.String(), id.String(), at, by.String())
	if err != nil {
		return fmt.Errorf("revoke authorization letter: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil
	}
	if _, err := r.GetByID(ctx, tenantID, id); err != nil {
		return err
	}
	return scope.ErrLetterRevoked
}

// CountEntries counts the scope entries naming the letter.
func (r *AuthorizationLetterRepository) CountEntries(ctx context.Context, tenantID, id shared.ID) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM scope_targets WHERE tenant_id = $1 AND letter_id = $2`,
		tenantID.String(), id.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count letter entries: %w", err)
	}
	return n, nil
}
