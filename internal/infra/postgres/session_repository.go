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

const sessionColumns = `id, user_id, access_token_hash, ip_address, user_agent,
	device_fingerprint, expires_at, last_activity_at, status, created_at, updated_at`

// SessionRepository implements session.Repository using PostgreSQL.
type SessionRepository struct {
	db *sql.DB
}

// NewSessionRepository creates a new PostgreSQL session repository.
func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

// Create creates a new session.
func (r *SessionRepository) Create(ctx context.Context, s *session.Session) error {
	query := `
		INSERT INTO sessions (
			id, user_id, access_token_hash, ip_address, user_agent,
			device_fingerprint, expires_at, last_activity_at, status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`

	_, err := r.db.ExecContext(ctx, query,
		s.ID().String(),
		s.UserID().String(),
		s.AccessTokenHash(),
		nullString(s.IPAddress()),
		nullString(s.UserAgent()),
		nullString(s.DeviceFingerprint()),
		s.ExpiresAt(),
		s.LastActivityAt(),
		s.Status().String(),
		s.CreatedAt(),
		s.UpdatedAt(),
	)
	if err != nil {
		return err
	}

	return nil
}

// GetByID retrieves a session by its ID.
func (r *SessionRepository) GetByID(ctx context.Context, id shared.ID) (*session.Session, error) {
	query := `SELECT ` + sessionColumns + ` FROM sessions WHERE id = $1`

	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanSession(row)
}

// GetByAccessTokenHash retrieves a session by access token hash.
func (r *SessionRepository) GetByAccessTokenHash(ctx context.Context, hash string) (*session.Session, error) {
	query := `SELECT ` + sessionColumns + ` FROM sessions WHERE access_token_hash = $1`

	row := r.db.QueryRowContext(ctx, query, hash)
	return r.scanSession(row)
}

// GetActiveByUserID retrieves all active sessions for a user.
func (r *SessionRepository) GetActiveByUserID(ctx context.Context, userID shared.ID) ([]*session.Session, error) {
	query := `SELECT ` + sessionColumns + ` FROM sessions
		WHERE user_id = $1 AND status = 'active' AND expires_at > NOW()
		ORDER BY last_activity_at DESC`

	rows, err := r.db.QueryContext(ctx, query, userID.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*session.Session
	for rows.Next() {
		s, err := r.scanSessionFromRows(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, s)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return sessions, nil
}

// Update updates an existing session.
func (r *SessionRepository) Update(ctx context.Context, s *session.Session) error {
	query := `
		UPDATE sessions SET
			access_token_hash = $2,
			ip_address = $3,
			user_agent = $4,
			device_fingerprint = $5,
			expires_at = $6,
			last_activity_at = $7,
			status = $8,
			updated_at = $9
		WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query,
		s.ID().String(),
		s.AccessTokenHash(),
		nullString(s.IPAddress()),
		nullString(s.UserAgent()),
		nullString(s.DeviceFingerprint()),
		s.ExpiresAt(),
		s.LastActivityAt(),
		s.Status().String(),
		s.UpdatedAt(),
	)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return session.ErrSessionNotFound
	}

	return nil
}

// Delete deletes a session.
func (r *SessionRepository) Delete(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM sessions WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return session.ErrSessionNotFound
	}

	return nil
}

// RevokeAllByUserID revokes all sessions for a user.
func (r *SessionRepository) RevokeAllByUserID(ctx context.Context, userID shared.ID) error {
	query := `
		UPDATE sessions
		SET status = 'revoked', updated_at = NOW()
		WHERE user_id = $1 AND status = 'active'`

	_, err := r.db.ExecContext(ctx, query, userID.String())
	return err
}

// RevokeAllByUserIDExcept revokes all sessions for a user except the specified session.
func (r *SessionRepository) RevokeAllByUserIDExcept(ctx context.Context, userID shared.ID, exceptSessionID shared.ID) error {
	query := `
		UPDATE sessions
		SET status = 'revoked', updated_at = NOW()
		WHERE user_id = $1 AND status = 'active' AND id != $2`

	_, err := r.db.ExecContext(ctx, query, userID.String(), exceptSessionID.String())
	return err
}

// CountActiveByUserID counts active sessions for a user.
func (r *SessionRepository) CountActiveByUserID(ctx context.Context, userID shared.ID) (int, error) {
	query := `
		SELECT COUNT(*) FROM sessions
		WHERE user_id = $1 AND status = 'active' AND expires_at > NOW()`

	var count int
	err := r.db.QueryRowContext(ctx, query, userID.String()).Scan(&count)
	if err != nil {
		return 0, err
	}

	return count, nil
}

// GetOldestActiveByUserID retrieves the oldest active session for a user.
func (r *SessionRepository) GetOldestActiveByUserID(ctx context.Context, userID shared.ID) (*session.Session, error) {
	query := `SELECT ` + sessionColumns + ` FROM sessions
		WHERE user_id = $1 AND status = 'active' AND expires_at > NOW()
		ORDER BY created_at ASC
		LIMIT 1`

	row := r.db.QueryRowContext(ctx, query, userID.String())
	s, err := r.scanSession(row)
	if err != nil {
		if errors.Is(err, session.ErrSessionNotFound) {
			return nil, nil // No active sessions
		}
		return nil, err
	}
	return s, nil
}

// DeleteExpired deletes all expired sessions.
func (r *SessionRepository) DeleteExpired(ctx context.Context) (int64, error) {
	query := `DELETE FROM sessions WHERE expires_at < NOW() OR status IN ('expired', 'revoked')`

	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// scanSession scans a single row into a Session.
func (r *SessionRepository) scanSession(row *sql.Row) (*session.Session, error) {
	var fields sessionScanFields
	err := row.Scan(
		&fields.id,
		&fields.userID,
		&fields.accessTokenHash,
		&fields.ipAddress,
		&fields.userAgent,
		&fields.deviceFingerprint,
		&fields.expiresAt,
		&fields.lastActivityAt,
		&fields.status,
		&fields.createdAt,
		&fields.updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, session.ErrSessionNotFound
		}
		return nil, err
	}

	return r.reconstructSession(fields), nil
}

// scanSessionFromRows scans a row from Rows into a Session.
func (r *SessionRepository) scanSessionFromRows(rows *sql.Rows) (*session.Session, error) {
	var fields sessionScanFields
	err := rows.Scan(
		&fields.id,
		&fields.userID,
		&fields.accessTokenHash,
		&fields.ipAddress,
		&fields.userAgent,
		&fields.deviceFingerprint,
		&fields.expiresAt,
		&fields.lastActivityAt,
		&fields.status,
		&fields.createdAt,
		&fields.updatedAt,
	)
	if err != nil {
		return nil, err
	}

	return r.reconstructSession(fields), nil
}

// reconstructSession creates a Session from scanned fields.
func (r *SessionRepository) reconstructSession(f sessionScanFields) *session.Session {
	return session.Reconstitute(
		shared.IDFromUUID(f.id),
		shared.IDFromUUID(f.userID),
		f.accessTokenHash,
		nullStringValue(f.ipAddress),
		nullStringValue(f.userAgent),
		nullStringValue(f.deviceFingerprint),
		f.expiresAt,
		f.lastActivityAt,
		session.StatusFromString(f.status),
		f.createdAt,
		f.updatedAt,
	)
}

// sessionScanFields holds scanned fields from database.
type sessionScanFields struct {
	id                uuid.UUID
	userID            uuid.UUID
	accessTokenHash   string
	ipAddress         sql.NullString
	userAgent         sql.NullString
	deviceFingerprint sql.NullString
	expiresAt         time.Time
	lastActivityAt    time.Time
	status            string
	createdAt         time.Time
	updatedAt         time.Time
}
