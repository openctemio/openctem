package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/supportaccess"
)

// SupportAccessRepository stores support grants and sessions
// (docs/rfcs/RFC-063-support-access.md). Every grant query carries the
// tenant, except the console's own list, which is keyed on the administrator.
type SupportAccessRepository struct {
	db *DB
}

// NewSupportAccessRepository creates the repository.
func NewSupportAccessRepository(db *DB) *SupportAccessRepository {
	return &SupportAccessRepository{db: db}
}

var _ supportaccess.Repository = (*SupportAccessRepository)(nil)

const supportGrantColumns = `
	g.id, g.tenant_id, g.admin_id, g.admin_email, g.admin_name, g.access_level, g.scopes,
	g.reason, COALESCE(g.case_ref, ''), COALESCE(g.granted_by::text, ''), g.starts_at, g.expires_at,
	g.revoked_at, g.revoked_by, g.created_at,
	(SELECT count(*) FROM support_sessions s WHERE s.tenant_id = g.tenant_id AND s.grant_id = g.id),
	(SELECT max(COALESCE(s.last_access_at, s.started_at)) FROM support_sessions s WHERE s.tenant_id = g.tenant_id AND s.grant_id = g.id),
	EXISTS (SELECT 1 FROM support_sessions s WHERE s.tenant_id = g.tenant_id AND s.grant_id = g.id AND s.ended_at IS NULL)`

func scanSupportGrant(row interface{ Scan(...any) error }) (*supportaccess.Grant, error) {
	var (
		g                                supportaccess.Grant
		id, tenantID, adminID, grantedBy string
		scopes                           pq.StringArray
		revokedAt, lastAccess            sql.NullTime
		revokedBy                        sql.NullString
	)
	if err := row.Scan(&id, &tenantID, &adminID, &g.AdminEmail, &g.AdminName, &g.Level, &scopes,
		&g.Reason, &g.CaseRef, &grantedBy, &g.StartsAt, &g.ExpiresAt,
		&revokedAt, &revokedBy, &g.CreatedAt, &g.SessionCount, &lastAccess, &g.OpenSession); err != nil {
		return nil, err
	}
	var err error
	if g.ID, err = shared.IDFromString(id); err != nil {
		return nil, err
	}
	if g.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, err
	}
	if g.AdminID, err = shared.IDFromString(adminID); err != nil {
		return nil, err
	}
	if grantedBy != "" { // the granter's account was deleted
		if g.GrantedBy, err = shared.IDFromString(grantedBy); err != nil {
			return nil, err
		}
	}
	g.Scopes = []string(scopes)
	if revokedAt.Valid {
		t := revokedAt.Time
		g.RevokedAt = &t
	}
	if revokedBy.Valid {
		if rb, perr := shared.IDFromString(revokedBy.String); perr == nil {
			g.RevokedBy = &rb
		}
	}
	if lastAccess.Valid {
		t := lastAccess.Time
		g.LastAccessAt = &t
	}
	return &g, nil
}

func (r *SupportAccessRepository) queryGrants(ctx context.Context, q string, args ...any) ([]*supportaccess.Grant, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("query support grants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*supportaccess.Grant, 0, 8)
	for rows.Next() {
		g, err := scanSupportGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("scan support grant: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// CreateGrant stores a new grant.
func (r *SupportAccessRepository) CreateGrant(ctx context.Context, g *supportaccess.Grant) error {
	var caseRef any
	if g.CaseRef != "" {
		caseRef = g.CaseRef
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO support_grants
		    (id, tenant_id, admin_id, admin_email, admin_name, access_level, scopes, reason, case_ref,
		     granted_by, starts_at, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		g.ID.String(), g.TenantID.String(), g.AdminID.String(), g.AdminEmail, g.AdminName, g.Level,
		pq.StringArray(g.Scopes), g.Reason, caseRef, g.GrantedBy.String(), g.StartsAt, g.ExpiresAt, g.CreatedAt)
	if err != nil {
		return fmt.Errorf("create support grant: %w", err)
	}
	return nil
}

// GetGrant returns one grant of tenantID.
func (r *SupportAccessRepository) GetGrant(ctx context.Context, tenantID, id shared.ID) (*supportaccess.Grant, error) {
	g, err := scanSupportGrant(r.db.QueryRowContext(ctx,
		`SELECT `+supportGrantColumns+` FROM support_grants g WHERE g.tenant_id = $1 AND g.id = $2`,
		tenantID.String(), id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, supportaccess.ErrGrantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get support grant: %w", err)
	}
	return g, nil
}

// ListGrants returns the organization's grants, newest first.
func (r *SupportAccessRepository) ListGrants(ctx context.Context, tenantID shared.ID, limit int) ([]*supportaccess.Grant, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	return r.queryGrants(ctx, `SELECT `+supportGrantColumns+` FROM support_grants g
		WHERE g.tenant_id = $1 ORDER BY g.created_at DESC, g.id LIMIT $2`, tenantID.String(), limit)
}

// ListActiveGrants returns the organization's grants usable at now.
func (r *SupportAccessRepository) ListActiveGrants(ctx context.Context, tenantID shared.ID, now time.Time) ([]*supportaccess.Grant, error) {
	return r.queryGrants(ctx, `SELECT `+supportGrantColumns+` FROM support_grants g
		WHERE g.tenant_id = $1 AND g.revoked_at IS NULL AND g.starts_at <= $2 AND g.expires_at > $2
		ORDER BY g.expires_at, g.id`, tenantID.String(), now)
}

// RevokeGrant revokes a live grant of tenantID and ends its open sessions.
func (r *SupportAccessRepository) RevokeGrant(ctx context.Context, tenantID, id, by shared.ID, now time.Time) (*supportaccess.Grant, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("revoke support grant: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `
		UPDATE support_grants SET revoked_at = $3, revoked_by = $4
		WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL AND expires_at > $3`,
		tenantID.String(), id.String(), now, by.String())
	if err != nil {
		return nil, fmt.Errorf("revoke support grant: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, supportaccess.ErrGrantNotFound
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE support_sessions SET ended_at = $3, end_reason = 'grant_revoked'
		WHERE tenant_id = $1 AND grant_id = $2 AND ended_at IS NULL`,
		tenantID.String(), id.String(), now); err != nil {
		return nil, fmt.Errorf("end support sessions: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("revoke support grant: %w", err)
	}
	return r.GetGrant(ctx, tenantID, id)
}

// ListGrantsForAdmin returns the grants naming adminID usable at now, with
// the organization's name.
func (r *SupportAccessRepository) ListGrantsForAdmin(ctx context.Context, adminID shared.ID, now time.Time) ([]*supportaccess.Grant, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT t.name, `+supportGrantColumns+` FROM support_grants g
		JOIN tenants t ON t.id = g.tenant_id
		WHERE g.admin_id = $1 AND g.revoked_at IS NULL AND g.starts_at <= $2 AND g.expires_at > $2
		ORDER BY g.expires_at, g.id`, adminID.String(), now)
	if err != nil {
		return nil, fmt.Errorf("query support grants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*supportaccess.Grant, 0, 4)
	for rows.Next() {
		var name string
		g, err := scanSupportGrant(rowsPrefixScanner{rows: rows, prefix: []any{&name}})
		if err != nil {
			return nil, fmt.Errorf("scan support grant: %w", err)
		}
		g.TenantName = name
		out = append(out, g)
	}
	return out, rows.Err()
}

type rowsPrefixScanner struct {
	rows   *sql.Rows
	prefix []any
}

func (p rowsPrefixScanner) Scan(dest ...any) error {
	return p.rows.Scan(append(append([]any{}, p.prefix...), dest...)...)
}

// GetGrantForAdmin returns a grant only when it names adminID and is usable at now.
func (r *SupportAccessRepository) GetGrantForAdmin(ctx context.Context, adminID, id shared.ID, now time.Time) (*supportaccess.Grant, error) {
	g, err := scanSupportGrant(r.db.QueryRowContext(ctx, `SELECT `+supportGrantColumns+` FROM support_grants g
		WHERE g.id = $1 AND g.admin_id = $2 AND g.revoked_at IS NULL AND g.starts_at <= $3 AND g.expires_at > $3`,
		id.String(), adminID.String(), now))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, supportaccess.ErrGrantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get support grant: %w", err)
	}
	return g, nil
}

// CreateSession stores a new support session. An earlier open session of
// the same administrator under the same grant ends first (superseded), so
// one administrator holds at most one open session per grant.
func (r *SupportAccessRepository) CreateSession(ctx context.Context, s *supportaccess.Session) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("create support session: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		UPDATE support_sessions SET ended_at = $4, end_reason = 'superseded'
		WHERE tenant_id = $1 AND grant_id = $2 AND admin_id = $3 AND ended_at IS NULL`,
		s.TenantID.String(), s.GrantID.String(), s.AdminID.String(), s.StartedAt); err != nil {
		return fmt.Errorf("end superseded support sessions: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO support_sessions (id, tenant_id, grant_id, admin_id, console_session_id, reason, started_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		s.ID.String(), s.TenantID.String(), s.GrantID.String(), s.AdminID.String(),
		s.ConsoleSessionID.String(), s.Reason, s.StartedAt); err != nil {
		return fmt.Errorf("create support session: %w", err)
	}
	return tx.Commit()
}

// LiveSession resolves a session for one request (no cache): open, opened by
// adminID in consoleSessionID, grant not revoked and inside its window. It
// records the access time in the same statement.
func (r *SupportAccessRepository) LiveSession(ctx context.Context, id, adminID, consoleSessionID shared.ID, now time.Time) (*supportaccess.LiveSession, error) {
	row := r.db.QueryRowContext(ctx, `
		WITH live AS (
		    UPDATE support_sessions s SET last_access_at = $4
		    FROM support_grants g
		    WHERE s.id = $1 AND s.admin_id = $2 AND s.console_session_id = $3 AND s.ended_at IS NULL
		      AND g.tenant_id = s.tenant_id AND g.id = s.grant_id AND g.admin_id = s.admin_id
		      AND g.revoked_at IS NULL AND g.starts_at <= $4 AND g.expires_at > $4
		    RETURNING s.id, s.tenant_id, s.grant_id, s.reason, s.started_at
		)
		SELECT live.id, live.reason, live.started_at, t.name, `+supportGrantColumns+`
		FROM live
		JOIN support_grants g ON g.tenant_id = live.tenant_id AND g.id = live.grant_id
		JOIN tenants t ON t.id = live.tenant_id`,
		id.String(), adminID.String(), consoleSessionID.String(), now)
	var (
		ls      supportaccess.LiveSession
		sid     string
		reason  string
		started time.Time
		name    string
	)
	dest := []any{&sid, &reason, &started, &name}
	g, err := scanSupportGrant(prefixScanner{row: row, prefix: dest})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, supportaccess.ErrNoLiveSession
	}
	if err != nil {
		return nil, fmt.Errorf("resolve support session: %w", err)
	}
	ls.Grant = *g
	ls.TenantName = name
	ls.Session = supportaccess.Session{
		TenantID: g.TenantID, GrantID: g.ID, AdminID: adminID, ConsoleSessionID: consoleSessionID,
		Reason: reason, StartedAt: started, LastAccessAt: &now,
	}
	if ls.Session.ID, err = shared.IDFromString(sid); err != nil {
		return nil, err
	}
	return &ls, nil
}

// prefixScanner scans a row whose leading columns go to prefix and the rest
// to the destinations the caller passes.
type prefixScanner struct {
	row    *sql.Row
	prefix []any
}

func (p prefixScanner) Scan(dest ...any) error {
	return p.row.Scan(append(append([]any{}, p.prefix...), dest...)...)
}

// EndSessionForPlatform ends an open session of adminID (a platform
// principal: keyed on the administrator, the tenant comes back).
func (r *SupportAccessRepository) EndSessionForPlatform(ctx context.Context, id, adminID shared.ID, reason string, now time.Time) (*supportaccess.Session, error) {
	var (
		s                       supportaccess.Session
		tenantID, grantID, csID string
		sreason                 string
	)
	err := r.db.QueryRowContext(ctx, `
		UPDATE support_sessions SET ended_at = $3, end_reason = $4
		WHERE id = $1 AND admin_id = $2 AND ended_at IS NULL
		RETURNING tenant_id, grant_id, console_session_id, reason, started_at`,
		id.String(), adminID.String(), now, reason).Scan(&tenantID, &grantID, &csID, &sreason, &s.StartedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, supportaccess.ErrNoLiveSession
	}
	if err != nil {
		return nil, fmt.Errorf("end support session: %w", err)
	}
	s.ID, s.AdminID, s.Reason, s.EndReason = id, adminID, sreason, reason
	s.EndedAt = &now
	if s.TenantID, err = shared.IDFromString(tenantID); err != nil {
		return nil, err
	}
	if s.GrantID, err = shared.IDFromString(grantID); err != nil {
		return nil, err
	}
	if s.ConsoleSessionID, err = shared.IDFromString(csID); err != nil {
		return nil, err
	}
	return &s, nil
}
