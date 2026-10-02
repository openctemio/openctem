package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AdminConsoleRepository persists platform admin console credentials and
// sessions (RFC-022). These tables are platform-level, not tenant-scoped.
type AdminConsoleRepository struct {
	db *DB
}

// NewAdminConsoleRepository creates a new AdminConsoleRepository.
func NewAdminConsoleRepository(db *DB) *AdminConsoleRepository {
	return &AdminConsoleRepository{db: db}
}

var _ admin.ConsoleRepository = (*AdminConsoleRepository)(nil)

// GetCredentials returns the admin's console credentials.
func (r *AdminConsoleRepository) GetCredentials(ctx context.Context, adminID shared.ID) (*admin.Credentials, error) {
	const q = `
		SELECT admin_id, COALESCE(mfa_secret_encrypted, ''), mfa_enabled, mfa_last_step
		FROM admin_credentials WHERE admin_id = $1`
	var (
		c  admin.Credentials
		id string
	)
	err := r.db.QueryRowContext(ctx, q, adminID.String()).Scan(
		&id, &c.MFASecretEncrypted, &c.MFAEnabled, &c.MFALastStep,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, admin.ErrCredentialsNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get admin credentials: %w", err)
	}
	parsed, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("get admin credentials: %w", err)
	}
	c.AdminID = parsed
	return &c, nil
}

// SaveCredentials upserts the admin's console credentials.
func (r *AdminConsoleRepository) SaveCredentials(ctx context.Context, c *admin.Credentials) error {
	const q = `
		INSERT INTO admin_credentials
		    (admin_id, mfa_secret_encrypted, mfa_enabled, mfa_last_step, updated_at)
		VALUES ($1, NULLIF($2, ''), $3, $4, NOW())
		ON CONFLICT (admin_id) DO UPDATE SET
		    mfa_secret_encrypted = EXCLUDED.mfa_secret_encrypted,
		    mfa_enabled = EXCLUDED.mfa_enabled,
		    mfa_last_step = EXCLUDED.mfa_last_step,
		    updated_at = NOW()`
	_, err := r.db.ExecContext(ctx, q,
		c.AdminID.String(), c.MFASecretEncrypted, c.MFAEnabled, c.MFALastStep,
	)
	if err != nil {
		return fmt.Errorf("save admin credentials: %w", err)
	}
	return nil
}

// DeleteCredentials removes the admin's second factor.
func (r *AdminConsoleRepository) DeleteCredentials(ctx context.Context, adminID shared.ID) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM admin_credentials WHERE admin_id = $1`, adminID.String()); err != nil {
		return fmt.Errorf("delete admin credentials: %w", err)
	}
	return nil
}

// AdvanceMFAStep records step as used only if it is newer than the last one,
// in a single statement so two concurrent requests cannot both use one code.
func (r *AdminConsoleRepository) AdvanceMFAStep(ctx context.Context, adminID shared.ID, step int64) (bool, error) {
	res, err := r.db.ExecContext(ctx,
		`UPDATE admin_credentials SET mfa_last_step = $2, updated_at = NOW()
		 WHERE admin_id = $1 AND mfa_last_step < $2`,
		adminID.String(), step)
	if err != nil {
		return false, fmt.Errorf("advance admin mfa step: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("advance admin mfa step: %w", err)
	}
	return n == 1, nil
}

// CreateSession inserts a console session.
func (r *AdminConsoleRepository) CreateSession(ctx context.Context, s *admin.Session) error {
	const q = `
		INSERT INTO admin_sessions
		    (id, admin_id, token_hash, mfa_verified, created_at, expires_at, last_seen_at, ip, user_agent, auth_method)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), NULLIF($9, ''), $10)`
	method := s.AuthMethod
	if method == "" {
		method = admin.AuthMethodPassword
	}
	_, err := r.db.ExecContext(ctx, q,
		s.ID.String(), s.AdminID.String(), s.TokenHash, s.MFAVerified,
		s.CreatedAt, s.ExpiresAt, s.LastSeenAt, s.IP, s.UserAgent, method)
	if err != nil {
		return fmt.Errorf("create admin session: %w", err)
	}
	return nil
}

// GetSessionByTokenHash looks a session up by its token hash.
func (r *AdminConsoleRepository) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*admin.Session, error) {
	const q = `
		SELECT id, admin_id, token_hash, mfa_verified, created_at, expires_at, last_seen_at,
		       COALESCE(ip, ''), COALESCE(user_agent, ''), auth_method
		FROM admin_sessions WHERE token_hash = $1`
	var (
		s           admin.Session
		id, adminID string
	)
	err := r.db.QueryRowContext(ctx, q, tokenHash).Scan(
		&id, &adminID, &s.TokenHash, &s.MFAVerified, &s.CreatedAt, &s.ExpiresAt, &s.LastSeenAt, &s.IP, &s.UserAgent, &s.AuthMethod,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, admin.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get admin session: %w", err)
	}
	if s.ID, err = shared.IDFromString(id); err != nil {
		return nil, fmt.Errorf("get admin session: %w", err)
	}
	if s.AdminID, err = shared.IDFromString(adminID); err != nil {
		return nil, fmt.Errorf("get admin session: %w", err)
	}
	return &s, nil
}

// TouchSession records that a session was just used.
func (r *AdminConsoleRepository) TouchSession(ctx context.Context, id shared.ID, at time.Time) error {
	if _, err := r.db.ExecContext(ctx, `UPDATE admin_sessions SET last_seen_at = $2 WHERE id = $1`, id.String(), at); err != nil {
		return fmt.Errorf("touch admin session: %w", err)
	}
	return nil
}

// DeleteSession ends one session.
func (r *AdminConsoleRepository) DeleteSession(ctx context.Context, id shared.ID) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE id = $1`, id.String()); err != nil {
		return fmt.Errorf("delete admin session: %w", err)
	}
	return nil
}

// DeleteSessionsForAdmin ends every session of one admin.
func (r *AdminConsoleRepository) DeleteSessionsForAdmin(ctx context.Context, adminID shared.ID) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE admin_id = $1`, adminID.String()); err != nil {
		return fmt.Errorf("delete admin sessions: %w", err)
	}
	return nil
}

// DeleteExpiredSessions removes sessions past their absolute expiry.
func (r *AdminConsoleRepository) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := r.db.ExecContext(ctx, `DELETE FROM admin_sessions WHERE expires_at < $1`, now)
	if err != nil {
		return 0, fmt.Errorf("delete expired admin sessions: %w", err)
	}
	return res.RowsAffected()
}

// DeletePasswordSessionsExceptBreakGlass ends every password-authenticated
// session (verified or pending) of a non-break-glass administrator.
func (r *AdminConsoleRepository) DeletePasswordSessionsExceptBreakGlass(ctx context.Context) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		DELETE FROM admin_sessions s
		USING admin_users a
		WHERE s.admin_id = a.id AND s.auth_method = 'password' AND NOT a.is_break_glass`)
	if err != nil {
		return 0, fmt.Errorf("delete password admin sessions: %w", err)
	}
	return res.RowsAffected()
}
