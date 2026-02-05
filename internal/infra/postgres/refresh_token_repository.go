package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/openctemio/api/pkg/domain/session"
	"github.com/openctemio/api/pkg/domain/shared"
)

const refreshTokenColumns = `id, user_id, session_id, token_hash, family,
	expires_at, used_at, revoked_at, created_at`

// RefreshTokenRepository implements session.RefreshTokenRepository using PostgreSQL.
type RefreshTokenRepository struct {
	db *sql.DB
}

// NewRefreshTokenRepository creates a new PostgreSQL refresh token repository.
func NewRefreshTokenRepository(db *sql.DB) *RefreshTokenRepository {
	return &RefreshTokenRepository{db: db}
}

// Create creates a new refresh token.
func (r *RefreshTokenRepository) Create(ctx context.Context, token *session.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (
			id, user_id, session_id, token_hash, family,
			expires_at, used_at, revoked_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

	_, err := r.db.ExecContext(ctx, query,
		token.ID().String(),
		token.UserID().String(),
		token.SessionID().String(),
		token.TokenHash(),
		token.Family().String(),
		token.ExpiresAt(),
		nullTime(token.UsedAt()),
		nullTime(token.RevokedAt()),
		token.CreatedAt(),
	)
	if err != nil {
		return err
	}

	return nil
}

// GetByID retrieves a refresh token by its ID.
func (r *RefreshTokenRepository) GetByID(ctx context.Context, id shared.ID) (*session.RefreshToken, error) {
	query := `SELECT ` + refreshTokenColumns + ` FROM refresh_tokens WHERE id = $1`

	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanRefreshToken(row)
}

// GetByTokenHash retrieves a refresh token by its hash.
func (r *RefreshTokenRepository) GetByTokenHash(ctx context.Context, hash string) (*session.RefreshToken, error) {
	query := `SELECT ` + refreshTokenColumns + ` FROM refresh_tokens WHERE token_hash = $1`

	row := r.db.QueryRowContext(ctx, query, hash)
	return r.scanRefreshToken(row)
}

// GetByFamily retrieves all refresh tokens in a family.
func (r *RefreshTokenRepository) GetByFamily(ctx context.Context, family shared.ID) ([]*session.RefreshToken, error) {
	query := `SELECT ` + refreshTokenColumns + ` FROM refresh_tokens
		WHERE family = $1
		ORDER BY created_at DESC`

	rows, err := r.db.QueryContext(ctx, query, family.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*session.RefreshToken
	for rows.Next() {
		token, err := r.scanRefreshTokenFromRows(rows)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return tokens, nil
}

// Update updates a refresh token.
func (r *RefreshTokenRepository) Update(ctx context.Context, token *session.RefreshToken) error {
	query := `
		UPDATE refresh_tokens SET
			used_at = $2,
			revoked_at = $3
		WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query,
		token.ID().String(),
		nullTime(token.UsedAt()),
		nullTime(token.RevokedAt()),
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return session.ErrRefreshTokenNotFound
	}

	return nil
}

// Delete deletes a refresh token.
func (r *RefreshTokenRepository) Delete(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM refresh_tokens WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return session.ErrRefreshTokenNotFound
	}

	return nil
}

// RevokeByFamily revokes all tokens in a family (for replay attack detection).
func (r *RefreshTokenRepository) RevokeByFamily(ctx context.Context, family shared.ID) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE family = $1 AND revoked_at IS NULL`

	_, err := r.db.ExecContext(ctx, query, family.String())
	return err
}

// RevokeBySessionID revokes all tokens for a session.
func (r *RefreshTokenRepository) RevokeBySessionID(ctx context.Context, sessionID shared.ID) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE session_id = $1 AND revoked_at IS NULL`

	_, err := r.db.ExecContext(ctx, query, sessionID.String())
	return err
}

// RevokeByUserID revokes all tokens for a user.
func (r *RefreshTokenRepository) RevokeByUserID(ctx context.Context, userID shared.ID) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE user_id = $1 AND revoked_at IS NULL`

	_, err := r.db.ExecContext(ctx, query, userID.String())
	return err
}

// DeleteExpired deletes all expired tokens.
func (r *RefreshTokenRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM refresh_tokens WHERE expires_at < NOW()`

	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// scanRefreshToken scans a single row into a RefreshToken.
func (r *RefreshTokenRepository) scanRefreshToken(row *sql.Row) (*session.RefreshToken, error) {
	var fields refreshTokenScanFields
	err := row.Scan(
		&fields.id,
		&fields.userID,
		&fields.sessionID,
		&fields.tokenHash,
		&fields.family,
		&fields.expiresAt,
		&fields.usedAt,
		&fields.revokedAt,
		&fields.createdAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, session.ErrRefreshTokenNotFound
		}
		return nil, err
	}

	return r.reconstructRefreshToken(fields), nil
}

// scanRefreshTokenFromRows scans a row from Rows into a RefreshToken.
func (r *RefreshTokenRepository) scanRefreshTokenFromRows(rows *sql.Rows) (*session.RefreshToken, error) {
	var fields refreshTokenScanFields
	err := rows.Scan(
		&fields.id,
		&fields.userID,
		&fields.sessionID,
		&fields.tokenHash,
		&fields.family,
		&fields.expiresAt,
		&fields.usedAt,
		&fields.revokedAt,
		&fields.createdAt,
	)
	if err != nil {
		return nil, err
	}

	return r.reconstructRefreshToken(fields), nil
}

// reconstructRefreshToken creates a RefreshToken from scanned fields.
func (r *RefreshTokenRepository) reconstructRefreshToken(f refreshTokenScanFields) *session.RefreshToken {
	var usedAt *time.Time
	if f.usedAt.Valid {
		usedAt = &f.usedAt.Time
	}

	var revokedAt *time.Time
	if f.revokedAt.Valid {
		revokedAt = &f.revokedAt.Time
	}

	return session.ReconstituteRefreshToken(
		shared.IDFromUUID(f.id),
		shared.IDFromUUID(f.userID),
		shared.IDFromUUID(f.sessionID),
		f.tokenHash,
		shared.IDFromUUID(f.family),
		f.expiresAt,
		usedAt,
		revokedAt,
		f.createdAt,
	)
}

// refreshTokenScanFields holds scanned fields from database.
type refreshTokenScanFields struct {
	id        uuid.UUID
	userID    uuid.UUID
	sessionID uuid.UUID
	tokenHash string
	family    uuid.UUID
	expiresAt time.Time
	usedAt    sql.NullTime
	revokedAt sql.NullTime
	createdAt time.Time
}
