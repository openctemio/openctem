package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/useridentity"
)

// UserIdentityRepository stores the federated identities bound to accounts
// (user_identities). The table is global, like users; a SAML identity carries
// the organization it is trusted in (scope_tenant_id) and is only ever looked
// up with that organization.
type UserIdentityRepository struct {
	db *DB
}

// NewUserIdentityRepository creates a UserIdentityRepository.
func NewUserIdentityRepository(db *DB) *UserIdentityRepository {
	return &UserIdentityRepository{db: db}
}

var _ useridentity.Repository = (*UserIdentityRepository)(nil)

const userIdentityColumns = `id, user_id, issuer, subject, scope_tenant_id, created_at, last_used_at`

// GetByKey returns the identity for (issuer, subject) in the key's scope.
func (r *UserIdentityRepository) GetByKey(ctx context.Context, key useridentity.Key) (*useridentity.Identity, error) {
	row := r.db.QueryRowContext(ctx, `
		SELECT `+userIdentityColumns+`
		FROM user_identities
		WHERE issuer = $1 AND subject = $2 AND scope_tenant_id IS NOT DISTINCT FROM $3::uuid`,
		key.Issuer, key.Subject, nullID(key.ScopeTenantID))
	ident, err := scanUserIdentity(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, useridentity.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get user identity: %w", err)
	}
	return ident, nil
}

// ListByUser returns the identities bound to an account (a handful at most).
func (r *UserIdentityRepository) ListByUser(ctx context.Context, userID shared.ID) ([]*useridentity.Identity, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT `+userIdentityColumns+`
		FROM user_identities
		WHERE user_id = $1
		ORDER BY created_at
		LIMIT 100`, userID.String())
	if err != nil {
		return nil, fmt.Errorf("list user identities: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*useridentity.Identity
	for rows.Next() {
		ident, err := scanUserIdentity(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user identity: %w", err)
		}
		out = append(out, ident)
	}
	return out, rows.Err()
}

// Create binds the identity. Both unique indexes map to ErrConflict: the
// identity is bound elsewhere, or the account already has a subject from
// this issuer.
func (r *UserIdentityRepository) Create(ctx context.Context, ident *useridentity.Identity) error {
	if ident == nil || !ident.Key.Valid() {
		return useridentity.ErrInvalid
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO user_identities (id, user_id, issuer, subject, scope_tenant_id, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		ident.ID.String(), ident.UserID.String(), ident.Key.Issuer, ident.Key.Subject,
		nullID(ident.Key.ScopeTenantID), ident.CreatedAt, nullTime(ident.LastUsedAt))
	if isUniqueViolation(err) {
		return useridentity.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("create user identity: %w", err)
	}
	return nil
}

// ChangeSubject re-keys an identity in place.
func (r *UserIdentityRepository) ChangeSubject(ctx context.Context, id shared.ID, subject string) error {
	if subject == "" {
		return useridentity.ErrInvalid
	}
	res, err := r.db.ExecContext(ctx, `UPDATE user_identities SET subject = $2 WHERE id = $1`, id.String(), subject)
	if isUniqueViolation(err) {
		return useridentity.ErrConflict
	}
	if err != nil {
		return fmt.Errorf("change identity subject: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return useridentity.ErrNotFound
	}
	return nil
}

// MarkUsed records a sign-in with the identity.
func (r *UserIdentityRepository) MarkUsed(ctx context.Context, id shared.ID, at time.Time) error {
	if _, err := r.db.ExecContext(ctx, `UPDATE user_identities SET last_used_at = $2 WHERE id = $1`, id.String(), at); err != nil {
		return fmt.Errorf("mark identity used: %w", err)
	}
	return nil
}

func scanUserIdentity(s interface{ Scan(dest ...any) error }) (*useridentity.Identity, error) {
	var (
		id, userID      string
		issuer, subject string
		scope           sql.NullString
		createdAt       time.Time
		lastUsed        sql.NullTime
	)
	if err := s.Scan(&id, &userID, &issuer, &subject, &scope, &createdAt, &lastUsed); err != nil {
		return nil, err
	}
	ident := &useridentity.Identity{
		ID:         shared.MustIDFromString(id),
		UserID:     shared.MustIDFromString(userID),
		Key:        useridentity.Key{Issuer: issuer, Subject: subject},
		CreatedAt:  createdAt,
		LastUsedAt: nullTimeValue(lastUsed),
	}
	if scope.Valid {
		t := shared.MustIDFromString(scope.String)
		ident.Key.ScopeTenantID = &t
	}
	return ident, nil
}
