package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The platform admin console's cross-organization user directory (Console >
// Users). Deliberately NOT tenant-scoped: it is wired only into
// /api/v1/admin behind the console session. It reads account-level facts
// (identity, sign-in state, which organizations an account belongs to) and
// never anything an organization holds (findings, assets, settings).

// PlatformUserSummary is one account in a directory search.
type PlatformUserSummary struct {
	ID              string
	Email           string
	Name            string
	Status          string
	AuthProvider    string
	EmailVerified   bool
	LockedUntil     *time.Time
	FailedLogins    int
	LastLoginAt     *time.Time
	CreatedAt       time.Time
	Memberships     int
	MFAEnabled      bool
	IsPlatformAdmin bool
	Erased          bool
	// Blocked platform-wide by an administrator (users.status 'suspended'),
	// when and why (docs/architecture/organization-suspension.md).
	BlockedAt     *time.Time
	BlockedReason string
}

// PlatformUserMembership is one organization the account belongs to.
type PlatformUserMembership struct {
	TenantID   string
	TenantName string
	TenantSlug string
	Role       string
	Status     string
	JoinedAt   time.Time
}

// PlatformUserIdentity is one federated identity linked to the account.
type PlatformUserIdentity struct {
	Issuer     string
	Subject    string
	TenantID   string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// PlatformUserSession is one active sign-in session.
type PlatformUserSession struct {
	ID           string
	IPAddress    string
	UserAgent    string
	AuthMethod   string
	CreatedAt    time.Time
	LastActivity time.Time
	ExpiresAt    time.Time
}

// PlatformUserDetail is one account with its memberships, identities and
// active sessions.
type PlatformUserDetail struct {
	PlatformUserSummary
	Memberships []PlatformUserMembership
	Identities  []PlatformUserIdentity
	Sessions    []PlatformUserSession
}

// PlatformUserDirectory reads the directory.
type PlatformUserDirectory struct{ db *DB }

// NewPlatformUserDirectory creates the directory.
func NewPlatformUserDirectory(db *DB) *PlatformUserDirectory { return &PlatformUserDirectory{db: db} }

// platformUserSessionLimit caps the sessions returned for one account.
const platformUserSessionLimit = 50

const platformUserSelect = `
	SELECT u.id::text, u.email, u.name, u.status::text, u.auth_provider, u.email_verified,
	       u.locked_until, u.failed_login_attempts, u.last_login_at, u.created_at,
	       (SELECT count(*) FROM tenant_members m WHERE m.user_id = u.id),
	       COALESCE((SELECT f.enabled FROM user_mfa f WHERE f.user_id = u.id), FALSE),
	       EXISTS (SELECT 1 FROM admin_users a WHERE a.user_id = u.id),
	       u.erased_at IS NOT NULL,
	       u.blocked_at, COALESCE(u.blocked_reason, '')
	FROM users u`

func scanPlatformUser(sc interface{ Scan(...any) error }) (PlatformUserSummary, error) {
	var (
		s                 PlatformUserSummary
		locked, lastLogin sql.NullTime
		blockedAt         sql.NullTime
		memberships       int64
	)
	if err := sc.Scan(&s.ID, &s.Email, &s.Name, &s.Status, &s.AuthProvider, &s.EmailVerified,
		&locked, &s.FailedLogins, &lastLogin, &s.CreatedAt, &memberships, &s.MFAEnabled,
		&s.IsPlatformAdmin, &s.Erased, &blockedAt, &s.BlockedReason); err != nil {
		return s, err
	}
	if blockedAt.Valid {
		t := blockedAt.Time
		s.BlockedAt = &t
	}
	if locked.Valid {
		t := locked.Time
		s.LockedUntil = &t
	}
	if lastLogin.Valid {
		t := lastLogin.Time
		s.LastLoginAt = &t
	}
	s.Memberships = int(memberships)
	return s, nil
}

// Account states the console's Users list filters on. Erased accounts are
// in "all" only.
const (
	PlatformUserStateAll        = "all"
	PlatformUserStateActive     = "active"
	PlatformUserStateBlocked    = "blocked"
	PlatformUserStateLocked     = "locked"
	PlatformUserStateUnverified = "unverified"
	PlatformUserStateMFAOff     = "mfa_off"
	PlatformUserStateAdmins     = "platform_admins"
)

// platformUserStates maps each state to its condition on users u. Every
// condition is a constant: the state never reaches the SQL text.
var platformUserStates = map[string]string{
	PlatformUserStateAll: `TRUE`,
	PlatformUserStateActive: `(u.status = 'active' AND u.blocked_at IS NULL AND u.erased_at IS NULL
		AND u.email_verified AND (u.locked_until IS NULL OR u.locked_until <= now()))`,
	PlatformUserStateBlocked:    `(u.blocked_at IS NOT NULL AND u.erased_at IS NULL)`,
	PlatformUserStateLocked:     `(u.locked_until > now() AND u.erased_at IS NULL)`,
	PlatformUserStateUnverified: `(NOT u.email_verified AND u.erased_at IS NULL)`,
	PlatformUserStateMFAOff: `(u.erased_at IS NULL AND u.auth_provider = 'local'
		AND NOT COALESCE((SELECT f.enabled FROM user_mfa f WHERE f.user_id = u.id), FALSE))`,
	PlatformUserStateAdmins: `EXISTS (SELECT 1 FROM admin_users a WHERE a.user_id = u.id)`,
}

// PlatformUserStates lists the states in tab order.
var PlatformUserStates = []string{PlatformUserStateAll, PlatformUserStateActive, PlatformUserStateUnverified,
	PlatformUserStateLocked, PlatformUserStateBlocked, PlatformUserStateMFAOff, PlatformUserStateAdmins}

// ValidPlatformUserState reports whether s is a known state.
func ValidPlatformUserState(s string) bool {
	_, ok := platformUserStates[s]
	return ok
}

// PlatformUserFilter narrows the Users list: Q is part of an email or name
// (or a whole id); State is one of the states ("" = all).
type PlatformUserFilter struct {
	Q     string
	State string
}

// List returns one page of accounts matching the filter, newest first, the
// total for the filter, and the count of each state under the search (the
// list's tabs). The email and name have trigram indexes.
func (d *PlatformUserDirectory) List(ctx context.Context, f PlatformUserFilter, limit, offset int) ([]PlatformUserSummary, int, map[string]int, error) {
	q := strings.TrimSpace(f.Q)
	search := `TRUE`
	var args []any
	id, idErr := shared.IDFromString(q)
	switch {
	case q == "":
	case idErr == nil:
		search, args = `u.id = $1`, []any{id.String()}
	default:
		search, args = `(u.email ILIKE $1 OR u.name ILIKE $1)`, []any{"%" + escapeLikePattern(q) + "%"}
	}
	state := f.State
	if state == "" {
		state = PlatformUserStateAll
	}
	cond, ok := platformUserStates[state]
	if !ok {
		return nil, 0, nil, fmt.Errorf("%w: unknown account state", shared.ErrValidation)
	}

	counts := make(map[string]int, len(PlatformUserStates))
	sel := make([]string, 0, len(PlatformUserStates))
	for _, st := range PlatformUserStates {
		sel = append(sel, `count(*) FILTER (WHERE `+platformUserStates[st]+`)`)
	}
	dest := make([]any, len(PlatformUserStates))
	vals := make([]int, len(PlatformUserStates))
	for i := range vals {
		dest[i] = &vals[i]
	}
	//nolint:gosec // every fragment is a constant of this file; values are bound
	countSQL := `SELECT ` + strings.Join(sel, ", ") + ` FROM users u WHERE ` + search
	if err := d.db.QueryRowContext(ctx, countSQL, args...).Scan(dest...); err != nil {
		return nil, 0, nil, fmt.Errorf("count users: %w", err)
	}
	for i, st := range PlatformUserStates {
		counts[st] = vals[i]
	}

	if limit <= 0 || limit > 100 {
		limit = 25
	}
	//nolint:gosec // as above
	listSQL := platformUserSelect + ` WHERE ` + search + ` AND ` + cond +
		fmt.Sprintf(" ORDER BY u.created_at DESC, u.id LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	rows, err := d.db.QueryContext(ctx, listSQL, append(args, limit, max(offset, 0))...)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("list users: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []PlatformUserSummary{}
	for rows.Next() {
		s, err := scanPlatformUser(rows)
		if err != nil {
			return nil, 0, nil, fmt.Errorf("scan user: %w", err)
		}
		out = append(out, s)
	}
	return out, counts[state], counts, rows.Err()
}

// Get returns one account with its memberships, identities and active
// sessions, or shared.ErrNotFound.
func (d *PlatformUserDirectory) Get(ctx context.Context, id shared.ID) (*PlatformUserDetail, error) {
	s, err := scanPlatformUser(d.db.QueryRowContext(ctx, platformUserSelect+` WHERE u.id = $1`, id.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("%w: user", shared.ErrNotFound)
	}
	if err != nil {
		return nil, fmt.Errorf("get user: %w", err)
	}
	out := &PlatformUserDetail{PlatformUserSummary: s}
	if out.Memberships, err = d.memberships(ctx, id); err != nil {
		return nil, fmt.Errorf("user memberships: %w", err)
	}
	if out.Identities, err = d.identities(ctx, id); err != nil {
		return nil, fmt.Errorf("user identities: %w", err)
	}
	if out.Sessions, err = d.sessions(ctx, id); err != nil {
		return nil, fmt.Errorf("user sessions: %w", err)
	}
	return out, nil
}

func (d *PlatformUserDirectory) memberships(ctx context.Context, id shared.ID) ([]PlatformUserMembership, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT t.id::text, t.name, t.slug, ver.role, COALESCE(m.status, 'active'), m.joined_at
		FROM tenant_members m JOIN tenants t ON t.id = m.tenant_id
		JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.user_id = $1
		ORDER BY t.name, t.id`, id.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []PlatformUserMembership
	for rows.Next() {
		var m PlatformUserMembership
		if err := rows.Scan(&m.TenantID, &m.TenantName, &m.TenantSlug, &m.Role, &m.Status, &m.JoinedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (d *PlatformUserDirectory) identities(ctx context.Context, id shared.ID) ([]PlatformUserIdentity, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT issuer, subject, COALESCE(scope_tenant_id::text, ''), created_at, last_used_at
		FROM user_identities WHERE user_id = $1
		ORDER BY created_at, id`, id.String())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []PlatformUserIdentity
	for rows.Next() {
		var (
			i    PlatformUserIdentity
			used sql.NullTime
		)
		if err := rows.Scan(&i.Issuer, &i.Subject, &i.TenantID, &i.CreatedAt, &used); err != nil {
			return nil, err
		}
		if used.Valid {
			t := used.Time
			i.LastUsedAt = &t
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

func (d *PlatformUserDirectory) sessions(ctx context.Context, id shared.ID) ([]PlatformUserSession, error) {
	rows, err := d.db.QueryContext(ctx, `
		SELECT id::text, COALESCE(ip_address, ''), COALESCE(user_agent, ''), auth_method,
		       created_at, last_activity_at, expires_at
		FROM sessions
		WHERE user_id = $1 AND status = 'active' AND expires_at > now()
		ORDER BY last_activity_at DESC, id
		LIMIT $2`, id.String(), platformUserSessionLimit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []PlatformUserSession
	for rows.Next() {
		var s PlatformUserSession
		if err := rows.Scan(&s.ID, &s.IPAddress, &s.UserAgent, &s.AuthMethod, &s.CreatedAt, &s.LastActivity, &s.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// AccountState reports whether the account is linked to a platform
// administrator (active or not) and whether it was erased; shared.ErrNotFound
// when it does not exist.
func (d *PlatformUserDirectory) AccountState(ctx context.Context, id shared.ID) (isAdmin, erased bool, err error) {
	err = d.db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM admin_users a WHERE a.user_id = u.id), u.erased_at IS NOT NULL
		FROM users u WHERE u.id = $1`, id.String()).Scan(&isAdmin, &erased)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, fmt.Errorf("%w: user", shared.ErrNotFound)
	}
	return isAdmin, erased, err
}

// ClearLockout clears the failed sign-in count and the lockout of an account
// (and nothing else: last_login_at stays). shared.ErrNotFound when the
// account does not exist.
func (d *PlatformUserDirectory) ClearLockout(ctx context.Context, id shared.ID) error {
	res, err := d.db.ExecContext(ctx, `
		UPDATE users SET failed_login_attempts = 0, locked_until = NULL, updated_at = now()
		WHERE id = $1`, id.String())
	if err != nil {
		return fmt.Errorf("clear lockout: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return fmt.Errorf("%w: user", shared.ErrNotFound)
	}
	return nil
}

// SetBlocked blocks an account platform-wide (users.status 'suspended', with
// who and why) or lifts the block (status 'active', the blocked_* columns
// cleared). Only an active account is blocked and only a blocked one is
// unblocked: false when the account was not in that state. An erased
// account never matches. The user repository's Update never lifts a block
// (it keeps 'suspended'), so this is the one way back.
func (d *PlatformUserDirectory) SetBlocked(ctx context.Context, id shared.ID, blocked bool, by *shared.ID, reason string) (bool, error) {
	var (
		res sql.Result
		err error
	)
	if blocked {
		var byArg any
		if by != nil {
			byArg = by.String()
		}
		res, err = d.db.ExecContext(ctx, `
			UPDATE users SET status = 'suspended', blocked_at = now(), blocked_by = $2, blocked_reason = $3, updated_at = now()
			WHERE id = $1 AND status = 'active' AND erased_at IS NULL`, id.String(), byArg, reason)
	} else {
		res, err = d.db.ExecContext(ctx, `
			UPDATE users SET status = 'active', blocked_at = NULL, blocked_by = NULL, blocked_reason = NULL, updated_at = now()
			WHERE id = $1 AND status = 'suspended' AND erased_at IS NULL`, id.String())
	}
	if err != nil {
		return false, fmt.Errorf("set account block: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
