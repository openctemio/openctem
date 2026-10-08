package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The console's view of open administrator sessions (Security > Sessions).
// Platform-level, wired only into /api/v1/admin behind the console session.

// AdminSessionRow is one open console session and the administrator it
// belongs to.
type AdminSessionRow struct {
	ID          string
	AdminID     string
	AdminEmail  string
	AdminName   string
	AdminRole   string
	BreakGlass  bool
	AuthMethod  string
	MFAVerified bool
	IP          string
	UserAgent   string
	CreatedAt   time.Time
	LastSeenAt  time.Time
	ExpiresAt   time.Time
}

// AdminSessionDirectory lists and ends console sessions.
type AdminSessionDirectory struct{ db *DB }

// NewAdminSessionDirectory creates the directory.
func NewAdminSessionDirectory(db *DB) *AdminSessionDirectory { return &AdminSessionDirectory{db: db} }

const adminSessionListLimit = 200

// ListOpen returns the console sessions that have not expired, newest
// activity first (at most 200; a console has a handful).
func (d *AdminSessionDirectory) ListOpen(ctx context.Context) ([]AdminSessionRow, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT s.id::text, a.id::text, a.email, a.name, a.role, a.is_break_glass,
		       s.auth_method, s.mfa_verified, COALESCE(s.ip, ''), COALESCE(s.user_agent, ''),
		       s.created_at, s.last_seen_at, s.expires_at
		FROM admin_sessions s JOIN admin_users a ON a.id = s.admin_id
		WHERE s.expires_at > now()
		ORDER BY s.last_seen_at DESC, s.id
		LIMIT $1`, adminSessionListLimit)
	if err != nil {
		return nil, fmt.Errorf("list admin sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []AdminSessionRow
	for rows.Next() {
		var r AdminSessionRow
		if err := rows.Scan(&r.ID, &r.AdminID, &r.AdminEmail, &r.AdminName, &r.AdminRole, &r.BreakGlass,
			&r.AuthMethod, &r.MFAVerified, &r.IP, &r.UserAgent, &r.CreatedAt, &r.LastSeenAt, &r.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan admin session: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// End deletes one session and returns the administrator it belonged to;
// shared.ErrNotFound when there is no such session.
func (d *AdminSessionDirectory) End(ctx context.Context, id shared.ID) (adminID string, err error) {
	err = d.db.QueryRowContext(ctx, `DELETE FROM admin_sessions WHERE id = $1 RETURNING admin_id::text`, id.String()).Scan(&adminID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("%w: session", shared.ErrNotFound)
	}
	if err != nil {
		return "", fmt.Errorf("end admin session: %w", err)
	}
	return adminID, nil
}
