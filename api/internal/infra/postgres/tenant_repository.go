package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// TenantRepository implements tenant.Repository using PostgreSQL.
type TenantRepository struct {
	db *DB
}

// NewTenantRepository creates a new TenantRepository.
func NewTenantRepository(db *DB) *TenantRepository {
	return &TenantRepository{db: db}
}

// =============================================================================
// Tenant CRUD
// =============================================================================

// Create persists a new tenant.
func (r *TenantRepository) Create(ctx context.Context, t *tenant.Tenant) error {
	settings, err := json.Marshal(t.Settings())
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	query := `
		INSERT INTO tenants (id, name, slug, description, logo_url, settings, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err = r.db.ExecContext(ctx, query,
		t.ID().String(),
		t.Name(),
		t.Slug(),
		t.Description(),
		t.LogoURL(),
		settings,
		t.CreatedBy(),
		t.CreatedAt(),
		t.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	return nil
}

// GetByID retrieves a tenant by ID.
//
//getbyid:unsafe - Tenants ARE the scope unit; lookup by tenant ID alone is the correct primary-key access pattern.
func (r *TenantRepository) GetByID(ctx context.Context, id shared.ID) (*tenant.Tenant, error) {
	query := `
		SELECT id, name, slug, description, logo_url, settings, created_by, created_at, updated_at
		FROM tenants
		WHERE id = $1
	`

	return r.scanTenant(r.db.QueryRowContext(ctx, query, id.String()))
}

// GetBySlug retrieves a tenant by slug.
func (r *TenantRepository) GetBySlug(ctx context.Context, slug string) (*tenant.Tenant, error) {
	query := `
		SELECT id, name, slug, description, logo_url, settings, created_by, created_at, updated_at
		FROM tenants
		WHERE slug = $1
	`

	return r.scanTenant(r.db.QueryRowContext(ctx, query, slug))
}

// UpdateProfile writes the organization profile columns. It never touches
// settings, so a profile save cannot revert a concurrent settings change.
func (r *TenantRepository) UpdateProfile(ctx context.Context, t *tenant.Tenant) error {
	query := `
		UPDATE tenants
		SET name = $2, slug = $3, description = $4, logo_url = $5, updated_at = $6
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		t.ID().String(),
		t.Name(),
		t.Slug(),
		t.Description(),
		t.LogoURL(),
		t.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}

	rows, rowErr := result.RowsAffected()
	if rowErr != nil {
		return fmt.Errorf("rows affected: %w", rowErr)
	}
	if rows == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// UpdateSettingsSection replaces one top-level key of tenants.settings with a
// compare-and-swap on that key alone (jsonb_set), so writers of different
// sections never overwrite each other and a writer whose snapshot is stale
// loses instead of reverting the newer value. jsonb equality is semantic
// (key order and number formatting do not matter).
func (r *TenantRepository) UpdateSettingsSection(
	ctx context.Context, id shared.ID, section string, expected any, expectedPresent bool, next any,
) error {
	if !tenant.IsSettingsSection(section) {
		return fmt.Errorf("%w: unknown settings section %q", shared.ErrValidation, section)
	}
	nextJSON, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("failed to marshal settings section: %w", err)
	}
	var expectedJSON any // SQL NULL = the key must be absent
	if expectedPresent {
		b, err := json.Marshal(expected)
		if err != nil {
			return fmt.Errorf("failed to marshal settings section: %w", err)
		}
		expectedJSON = string(b)
	}

	const query = `
		UPDATE tenants
		SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), ARRAY[$2::text], $4::jsonb, true),
		    updated_at = NOW()
		WHERE id = $1
		  AND (COALESCE(settings, '{}'::jsonb) -> $2::text) IS NOT DISTINCT FROM $3::jsonb
	`
	result, err := r.db.ExecContext(ctx, query, id.String(), section, expectedJSON, string(nextJSON))
	if err != nil {
		return fmt.Errorf("failed to update settings section %s: %w", section, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 1 {
		return nil
	}

	// Nothing updated: the tenant is gone, or the section changed.
	var current []byte
	err = r.db.QueryRowContext(ctx,
		`SELECT COALESCE(settings, '{}'::jsonb) -> $2::text FROM tenants WHERE id = $1`,
		id.String(), section).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return shared.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("failed to read settings section %s: %w", section, err)
	}
	var cur any
	if len(current) > 0 {
		_ = json.Unmarshal(current, &cur)
	}
	return &tenant.SettingsConflictError{Section: section, ETag: tenant.SectionETag(cur), Current: cur}
}

// Delete removes a tenant.
func (r *TenantRepository) Delete(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM tenants WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	rows, rowErr := result.RowsAffected()
	if rowErr != nil {
		return fmt.Errorf("rows affected: %w", rowErr)
	}
	if rows == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// ExistsBySlug checks if a tenant with the given slug exists.
func (r *TenantRepository) ExistsBySlug(ctx context.Context, slug string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM tenants WHERE slug = $1)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, slug).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check slug existence: %w", err)
	}

	return exists, nil
}

// ListActiveTenantIDs returns all active tenant IDs.
// Used by background jobs that need to process data across all tenants.
func (r *TenantRepository) ListActiveTenantIDs(ctx context.Context) ([]shared.ID, error) {
	// The system tenant is excluded: it is not a customer tenant, and every
	// sweep that received it failed on it (cert-monitor warned on every tick).
	query := `SELECT id FROM tenants WHERE id <> $1::uuid ORDER BY id`

	rows, err := r.db.QueryContext(ctx, query, tenant.SystemTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenant IDs: %w", err)
	}
	defer rows.Close()

	var ids []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan tenant ID: %w", err)
		}

		id, err := shared.IDFromString(idStr)
		if err != nil {
			continue // Skip invalid IDs
		}
		ids = append(ids, id)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate tenant IDs: %w", err)
	}

	return ids, nil
}

// =============================================================================
// Membership Operations
// =============================================================================

// CreateMembership creates a new membership.
// Inserts into tenant_members (membership record) and user_roles (role assignment).
func (r *TenantRepository) CreateMembership(ctx context.Context, m *tenant.Membership) error {
	// Insert into tenant_members with role. The offboarded tombstone of a
	// person who left is reused for a re-join (member lifecycle): it is
	// re-activated with the new id, role and inviter, and starts from zero
	// because the offboarding stripped every access source. An active or
	// suspended row is left alone and reported as a conflict.
	memberQuery := `
		INSERT INTO tenant_members (id, user_id, tenant_id, role, invited_by, joined_at,
		                            kind, home_tenant_id, home_domain, expires_at, expiry_reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (user_id, tenant_id) DO UPDATE
		SET id = EXCLUDED.id, role = EXCLUDED.role, invited_by = EXCLUDED.invited_by,
		    joined_at = EXCLUDED.joined_at, status = 'active',
		    offboarded_at = NULL, offboarded_by = NULL, suspended_at = NULL, suspended_by = NULL,
		    suspended_reason = NULL, kind = EXCLUDED.kind, home_tenant_id = EXCLUDED.home_tenant_id,
		    home_domain = EXCLUDED.home_domain, expires_at = EXCLUDED.expires_at,
		    expiry_reason = EXCLUDED.expiry_reason
		WHERE tenant_members.status = 'offboarded'
	`

	var invitedBy sql.NullString
	if m.InvitedBy() != nil {
		invitedBy = sql.NullString{String: m.InvitedBy().String(), Valid: true}
	}

	res, err := r.db.ExecContext(ctx, memberQuery, append([]any{
		m.ID().String(),
		m.UserID().String(),
		m.TenantID().String(),
		m.Role().String(),
		invitedBy,
		m.JoinedAt(),
	}, memberAccessArgs(m)...)...)
	if err != nil {
		if isCheckViolation(err) {
			return tenant.ErrPlatformAdminMembership
		}
		return fmt.Errorf("failed to create membership: %w", err)
	}
	if n, rerr := res.RowsAffected(); rerr == nil && n == 0 {
		return tenant.ErrAlreadyMember
	}

	// Insert role into user_roles table (this is the source of truth for roles)
	userRolesQuery := `
		INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_at, assigned_by)
		SELECT $1, $2, r.id, $3, $4
		FROM roles r
		WHERE r.slug = $5 AND r.is_system = TRUE AND r.tenant_id IS NULL
		ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING
	`

	_, err = r.db.ExecContext(ctx, userRolesQuery,
		m.UserID().String(),
		m.TenantID().String(),
		m.JoinedAt(),
		invitedBy,
		m.Role().String(),
	)
	if err != nil {
		return fmt.Errorf("failed to create user role: %w", err)
	}

	return nil
}

// CreateWithOwner atomically creates a tenant and its owner membership (the
// tenant_members row + the user_roles row) in a single transaction.
//
// Previously the service created the tenant, then the membership, in separate
// statements and attempted a manual rollback (Delete) if the membership failed —
// which could itself fail and leave an orphan tenant with no owner. This makes
// the whole operation all-or-nothing.
func (r *TenantRepository) CreateWithOwner(ctx context.Context, t *tenant.Tenant, m *tenant.Membership) (err error) {
	settings, err := json.Marshal(t.Settings())
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin tx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	const tenantQuery = `
		INSERT INTO tenants (id, name, slug, description, logo_url, settings, created_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	if _, err = tx.ExecContext(ctx, tenantQuery,
		t.ID().String(), t.Name(), t.Slug(), t.Description(), t.LogoURL(),
		settings, t.CreatedBy(), t.CreatedAt(), t.UpdatedAt(),
	); err != nil {
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	var invitedBy sql.NullString
	if m.InvitedBy() != nil {
		invitedBy = sql.NullString{String: m.InvitedBy().String(), Valid: true}
	}

	const memberQuery = `
		INSERT INTO tenant_members (id, user_id, tenant_id, role, invited_by, joined_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	if _, err = tx.ExecContext(ctx, memberQuery,
		m.ID().String(), m.UserID().String(), m.TenantID().String(),
		m.Role().String(), invitedBy, m.JoinedAt(),
	); err != nil {
		if isCheckViolation(err) {
			return tenant.ErrPlatformAdminMembership
		}
		return fmt.Errorf("failed to create membership: %w", err)
	}

	const userRolesQuery = `
		INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_at, assigned_by)
		SELECT $1, $2, r.id, $3, $4
		FROM roles r
		WHERE r.slug = $5 AND r.is_system = TRUE AND r.tenant_id IS NULL
		ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING
	`
	if _, err = tx.ExecContext(ctx, userRolesQuery,
		m.UserID().String(), m.TenantID().String(), m.JoinedAt(), invitedBy, m.Role().String(),
	); err != nil {
		return fmt.Errorf("failed to create user role: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit tenant creation: %w", err)
	}
	return nil
}

// GetMembership retrieves a membership by user and tenant.
// Role is fetched from v_user_effective_role view.
// Status fields are populated so callers (e.g. RequireMembership middleware)
// can enforce suspension on every request.
func (r *TenantRepository) GetMembership(ctx context.Context, userID shared.ID, tenantID shared.ID) (*tenant.Membership, error) {
	query := `
		SELECT m.id, m.user_id, m.tenant_id, COALESCE(ver.role, 'member') as role,
		       m.invited_by, m.joined_at,
		       COALESCE(m.status, 'active') as status, m.suspended_at, m.suspended_by,
		       m.kind, m.home_tenant_id, m.home_domain, m.expires_at, m.expiry_reason, m.suspended_reason
		FROM tenant_members m
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.user_id = $1 AND m.tenant_id = $2
	`

	return r.scanMembership(r.db.QueryRowContext(ctx, query, userID.String(), tenantID.String()))
}

// GetMembershipByID retrieves a membership by ID.
// Role is fetched from v_user_effective_role view.
// Status fields are populated so the service layer can branch on suspension.
func (r *TenantRepository) GetMembershipByID(ctx context.Context, tenantID, id shared.ID) (*tenant.Membership, error) {
	query := `
		SELECT m.id, m.user_id, m.tenant_id, COALESCE(ver.role, 'member') as role,
		       m.invited_by, m.joined_at,
		       COALESCE(m.status, 'active') as status, m.suspended_at, m.suspended_by,
		       m.kind, m.home_tenant_id, m.home_domain, m.expires_at, m.expiry_reason, m.suspended_reason
		FROM tenant_members m
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.id = $1 AND m.tenant_id = $2
	`

	return r.scanMembership(r.db.QueryRowContext(ctx, query, id.String(), tenantID.String()))
}

// UpdateMembership updates a membership's role.
// Role is updated in user_roles table (tenant_members no longer has role column).
func (r *TenantRepository) UpdateMembership(ctx context.Context, m *tenant.Membership) error {
	// One transaction: the membership label and the user's system role in
	// user_roles change together or not at all. As three separate statements a
	// failure after the DELETE left the user with no system role (settings
	// audit I-M3), and two concurrent role changes could interleave. The
	// membership row is locked first so concurrent changes run one after the
	// other.
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin membership update: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var userID, tenantID string
	err = tx.QueryRowContext(ctx,
		"SELECT user_id, tenant_id FROM tenant_members WHERE id = $1 AND tenant_id = $2 FOR UPDATE",
		m.ID().String(), m.TenantID().String(),
	).Scan(&userID, &tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return shared.ErrNotFound
		}
		return fmt.Errorf("failed to get membership: %w", err)
	}

	// Get current role from user_roles via view
	var oldRole string
	err = tx.QueryRowContext(ctx,
		"SELECT COALESCE(role, 'member') FROM v_user_effective_role WHERE user_id = $1 AND tenant_id = $2",
		userID, tenantID,
	).Scan(&oldRole)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to get current role: %w", err)
	}

	if oldRole == m.Role().String() {
		return nil
	}

	// Update role in tenant_members
	if _, err := tx.ExecContext(ctx,
		"UPDATE tenant_members SET role = $1 WHERE id = $2 AND tenant_id = $3",
		m.Role().String(), m.ID().String(), tenantID,
	); err != nil {
		return fmt.Errorf("failed to update membership role: %w", err)
	}

	// Remove old system role (only system roles, keep custom roles)
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM user_roles
		WHERE user_id = $1 AND tenant_id = $2 AND role_id IN (
			SELECT id FROM roles WHERE is_system = TRUE AND tenant_id IS NULL
		)
	`, userID, tenantID); err != nil {
		return fmt.Errorf("failed to remove old role: %w", err)
	}

	// Add new role
	res, err := tx.ExecContext(ctx, `
		INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_at)
		SELECT $1, $2, r.id, NOW()
		FROM roles r
		WHERE r.slug = $3 AND r.is_system = TRUE AND r.tenant_id IS NULL
		ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING
	`, userID, tenantID, m.Role().String())
	if err != nil {
		return fmt.Errorf("failed to add new role: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		// The DELETE above removed every system role, so the insert must
		// have added one; nothing added means no such system role exists.
		return fmt.Errorf("%w: no system role %q", shared.ErrValidation, m.Role().String())
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit membership update: %w", err)
	}
	return nil
}

// UpdateMembershipStatus persists the status / suspended_at /
// suspended_by fields on a membership. Called by SuspendMember and
// ReactivateMember in the service layer.
func (r *TenantRepository) UpdateMembershipStatus(ctx context.Context, m *tenant.Membership) error {
	query := `
		UPDATE tenant_members
		SET status = $2, suspended_at = $3, suspended_by = $4, suspended_reason = $6,
		    expires_at = $7, expiry_reason = $8
		WHERE id = $1 AND tenant_id = $5
	`
	result, err := r.db.ExecContext(ctx, query,
		m.ID().String(),
		string(m.Status()),
		nullTime(m.SuspendedAt()),
		nullIDPtr(m.SuspendedBy()),
		m.TenantID().String(),
		nullString(m.SuspendedReason()),
		nullTime(m.ExpiresAt()),
		nullString(m.ExpiryReason()),
	)
	if err != nil {
		return fmt.Errorf("update membership status: %w", err)
	}
	rows, rowErr := result.RowsAffected()
	if rowErr != nil {
		return fmt.Errorf("rows affected: %w", rowErr)
	}
	if rows == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// DeleteMembership removes a membership.
// Also removes all user_roles for this user in this tenant.
func (r *TenantRepository) DeleteMembership(ctx context.Context, memberTenantID, id shared.ID) error {
	// First get user_id and tenant_id for user_roles cleanup
	var userID, tenantID string
	err := r.db.QueryRowContext(ctx,
		"SELECT user_id, tenant_id FROM tenant_members WHERE id = $1 AND tenant_id = $2",
		id.String(), memberTenantID.String(),
	).Scan(&userID, &tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return shared.ErrNotFound
		}
		return fmt.Errorf("failed to get membership: %w", err)
	}

	// Delete from tenant_members
	query := `DELETE FROM tenant_members WHERE id = $1 AND tenant_id = $2`

	result, err := r.db.ExecContext(ctx, query, id.String(), tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete membership: %w", err)
	}

	rows, rowErr := result.RowsAffected()
	if rowErr != nil {
		return fmt.Errorf("rows affected: %w", rowErr)
	}
	if rows == 0 {
		return shared.ErrNotFound
	}

	// Also remove all user_roles for this user in this tenant
	// (trigger also does this as backup)
	_, _ = r.db.ExecContext(ctx, `
		DELETE FROM user_roles WHERE user_id = $1 AND tenant_id = $2
	`, userID, tenantID)

	return nil
}

// ListMembersByTenant lists the members of a tenant (active and suspended;
// offboarded tombstones are left out). Role is fetched from
// v_user_effective_role view, status from tenant_members.
func (r *TenantRepository) ListMembersByTenant(ctx context.Context, tenantID shared.ID) ([]*tenant.Membership, error) {
	query := `
		SELECT m.id, m.user_id, m.tenant_id, COALESCE(ver.role, 'member') as role, m.invited_by, m.joined_at,
		       COALESCE(m.status, 'active') as status, m.suspended_at, m.suspended_by,
		       m.kind, m.home_tenant_id, m.home_domain, m.expires_at, m.expiry_reason, m.suspended_reason
		FROM tenant_members m
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1 AND m.status <> 'offboarded'
		ORDER BY m.joined_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list members: %w", err)
	}
	defer rows.Close()

	var members []*tenant.Membership
	for rows.Next() {
		m, err := r.scanMembershipRow(rows)
		if err != nil {
			return nil, err
		}
		members = append(members, m)
	}

	return members, rows.Err()
}

// ListTenantsByUser lists all tenants a user belongs to.
// Role is fetched from v_user_effective_role view.
func (r *TenantRepository) ListTenantsByUser(ctx context.Context, userID shared.ID) ([]*tenant.TenantWithRole, error) {
	query := `
		SELECT t.id, t.name, t.slug, t.description, t.logo_url, t.settings, t.created_by, t.created_at, t.updated_at,
		       COALESCE(ver.role, 'member') as role, m.joined_at
		FROM tenants t
		INNER JOIN tenant_members m ON t.id = m.tenant_id
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.user_id = $1 AND m.status <> 'offboarded'
		ORDER BY m.joined_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list tenants by user: %w", err)
	}
	defer rows.Close()

	var tenants []*tenant.TenantWithRole
	for rows.Next() {
		var (
			idStr, name, slug    string
			createdBy            sql.NullString
			description, logoURL sql.NullString
			settingsJSON         []byte
			createdAt, updatedAt time.Time
			roleStr              string
			joinedAt             time.Time
		)

		err := rows.Scan(
			&idStr, &name, &slug, &description, &logoURL, &settingsJSON, &createdBy, &createdAt, &updatedAt,
			&roleStr, &joinedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan tenant with role: %w", err)
		}

		id, _ := shared.IDFromString(idStr)
		role, _ := tenant.ParseRole(roleStr)

		var settings map[string]any
		if err := json.Unmarshal(settingsJSON, &settings); err != nil {
			settings = make(map[string]any)
		}

		t := tenant.Reconstitute(
			id, name, slug, description.String, logoURL.String,
			settings, createdBy.String, createdAt, updatedAt,
		)

		tenants = append(tenants, &tenant.TenantWithRole{
			Tenant:   t,
			Role:     role,
			JoinedAt: joinedAt,
		})
	}

	return tenants, rows.Err()
}

// CountMembersByTenant counts members in a tenant.
func (r *TenantRepository) CountMembersByTenant(ctx context.Context, tenantID shared.ID) (int64, error) {
	query := `SELECT COUNT(*) FROM tenant_members WHERE tenant_id = $1 AND status <> 'offboarded'`

	var count int64
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count members: %w", err)
	}

	return count, nil
}

// ListMembersWithUserInfo lists all members of a tenant with user details.
// Role is fetched from v_user_effective_role view.
// Status is the MEMBERSHIP status (tenant_members.status), not the user-level
// status — see the comment on GetMemberStats for the rationale.
func (r *TenantRepository) ListMembersWithUserInfo(ctx context.Context, tenantID shared.ID) ([]*tenant.MemberWithUser, error) {
	query := `
		SELECT
			m.id, m.user_id, COALESCE(ver.role, 'member') as role, m.invited_by, m.joined_at,
			u.email, u.name, u.avatar_url, COALESCE(m.status, 'active') as status, u.last_login_at,
			(u.auth_provider = 'local' AND u.password_hash IS NULL AND u.last_login_at IS NULL) AS pending_setup,
			m.kind, m.home_domain, ht.name, m.expires_at, m.suspended_reason
		FROM tenant_members m
		INNER JOIN users u ON u.id = m.user_id
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		LEFT JOIN tenants ht ON ht.id = m.home_tenant_id
		WHERE m.tenant_id = $1 AND m.status <> 'offboarded'
		ORDER BY m.joined_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list members with user info: %w", err)
	}
	defer rows.Close()

	var members []*tenant.MemberWithUser
	for rows.Next() {
		var (
			idStr, userIDStr, roleStr string
			invitedByStr              sql.NullString
			joinedAt                  time.Time
			email, name               string
			avatarURL                 sql.NullString
			status                    string
			lastLoginAt               sql.NullTime
			pendingSetup              bool
			kind                      string
			homeDomain, homeName      sql.NullString
			expiresAt                 sql.NullTime
			suspendedReason           sql.NullString
		)

		if err := rows.Scan(
			&idStr, &userIDStr, &roleStr, &invitedByStr, &joinedAt,
			&email, &name, &avatarURL, &status, &lastLoginAt, &pendingSetup,
			&kind, &homeDomain, &homeName, &expiresAt, &suspendedReason,
		); err != nil {
			return nil, fmt.Errorf("failed to scan member with user: %w", err)
		}

		id, _ := shared.IDFromString(idStr)
		userID, _ := shared.IDFromString(userIDStr)
		role, _ := tenant.ParseRole(roleStr)

		var invitedBy *shared.ID
		if invitedByStr.Valid {
			parsed, err := shared.IDFromString(invitedByStr.String)
			if err == nil {
				invitedBy = &parsed
			}
		}

		var lastLogin *time.Time
		if lastLoginAt.Valid {
			lastLogin = &lastLoginAt.Time
		}

		members = append(members, &tenant.MemberWithUser{
			ID:              id,
			UserID:          userID,
			Role:            role,
			InvitedBy:       invitedBy,
			JoinedAt:        joinedAt,
			Email:           email,
			Name:            name,
			AvatarURL:       avatarURL.String,
			Status:          status,
			LastLoginAt:     lastLogin,
			PendingSetup:    pendingSetup,
			Kind:            tenant.MemberKind(kind),
			HomeDomain:      homeDomain.String,
			HomeTenantName:  homeName.String,
			ExpiresAt:       nullTimeValue(expiresAt),
			SuspendedReason: suspendedReason.String,
		})
	}

	return members, rows.Err()
}

// SearchMembersWithUserInfo searches members with filtering and pagination.
// Search is case-insensitive and matches name or email (name only when
// filters.SearchNameOnly is set).
// Uses COUNT(*) OVER() window function to get total count in a single query (optimization).
func (r *TenantRepository) SearchMembersWithUserInfo(ctx context.Context, tenantID shared.ID, filters tenant.MemberSearchFilters) (*tenant.MemberSearchResult, error) {
	// Build WHERE clause with optional search filter
	whereClause := "WHERE m.tenant_id = $1"
	args := []any{tenantID.String()}
	argIndex := 2

	// Status filter. The default leaves out offboarded tombstones, so every
	// picker built on this list (assignee, group member, approver) never
	// offers a person who left.
	switch filters.Status {
	case "":
		whereClause += " AND m.status <> 'offboarded'"
	case tenant.MemberFilterAll:
	default:
		whereClause += fmt.Sprintf(" AND m.status = $%d", argIndex)
		args = append(args, filters.Status)
		argIndex++
	}

	// Add search filter if provided
	if filters.Search != "" {
		searchPattern := "%" + escapeLikePattern(filters.Search) + "%"
		if filters.SearchNameOnly {
			whereClause += fmt.Sprintf(" AND LOWER(u.name) LIKE LOWER($%d)", argIndex)
		} else {
			whereClause += fmt.Sprintf(" AND (LOWER(u.name) LIKE LOWER($%d) OR LOWER(u.email) LIKE LOWER($%d))", argIndex, argIndex)
		}
		args = append(args, searchPattern)
		argIndex++
	}
	if filters.Role != "" {
		whereClause += fmt.Sprintf(" AND COALESCE(ver.role, 'member') = $%d", argIndex)
		args = append(args, filters.Role)
		argIndex++
	}

	// Single query with COUNT(*) OVER() window function to avoid 2 round-trips
	// This returns total matching count alongside each row.
	// Status is the MEMBERSHIP status (tenant_members.status), see GetMemberStats.
	selectQuery := fmt.Sprintf(`
		SELECT
			m.id, m.user_id, COALESCE(ver.role, 'member') as role, m.invited_by, m.joined_at,
			u.email, u.name, u.avatar_url, COALESCE(m.status, 'active') as status, u.last_login_at,
			CASE
				WHEN u.auth_provider <> 'local' THEN 'idp'
				WHEN EXISTS (SELECT 1 FROM user_mfa f WHERE f.user_id = m.user_id AND f.enabled) THEN 'enabled'
				ELSE 'disabled'
			END as mfa_status,
			(u.auth_provider = 'local' AND u.password_hash IS NULL AND u.last_login_at IS NULL) AS pending_setup,
			m.kind, m.home_domain, ht.name, m.expires_at, m.suspended_reason,
			COUNT(*) OVER() as total_count
		FROM tenant_members m
		INNER JOIN users u ON u.id = m.user_id
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		LEFT JOIN tenants ht ON ht.id = m.home_tenant_id
		%s
		ORDER BY u.name ASC, m.joined_at ASC
	`, whereClause)

	// Add limit and offset
	if filters.Limit > 0 {
		selectQuery += fmt.Sprintf(" LIMIT $%d", argIndex)
		args = append(args, filters.Limit)
		argIndex++
	}
	if filters.Offset > 0 {
		selectQuery += fmt.Sprintf(" OFFSET $%d", argIndex)
		args = append(args, filters.Offset)
	}

	rows, err := r.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to search members: %w", err)
	}
	defer rows.Close()

	// Pre-allocate at the const cold-cap max so make() has ZERO
	// user-influenced size input. Even after a clamp,
	// CodeQL's go/unsafe-slice-allocation keeps the taint tag on
	// filters.Limit; the only path to a clean flow is to hand the
	// literal to make. 1000 pointer slots = ~8 KB, an acceptable
	// ceiling for a member-search result and a trivial cost when
	// the page returns fewer rows.
	const maxMembersCap = 1000
	members := make([]*tenant.MemberWithUser, 0, maxMembersCap)
	var total int

	for rows.Next() {
		var (
			idStr, userIDStr, roleStr string
			invitedByStr              sql.NullString
			joinedAt                  time.Time
			email, name               string
			avatarURL                 sql.NullString
			status                    string
			lastLoginAt               sql.NullTime
			mfaStatus                 string
			pendingSetup              bool
			totalCount                int
			kind                      string
			homeDomain, homeName      sql.NullString
			expiresAt                 sql.NullTime
			suspendedReason           sql.NullString
		)

		if err := rows.Scan(
			&idStr, &userIDStr, &roleStr, &invitedByStr, &joinedAt,
			&email, &name, &avatarURL, &status, &lastLoginAt,
			&mfaStatus, &pendingSetup,
			&kind, &homeDomain, &homeName, &expiresAt, &suspendedReason,
			&totalCount,
		); err != nil {
			return nil, fmt.Errorf("failed to scan member: %w", err)
		}

		// Total is the same for all rows, capture from first row
		if total == 0 {
			total = totalCount
		}

		id, _ := shared.IDFromString(idStr)
		userID, _ := shared.IDFromString(userIDStr)
		role, _ := tenant.ParseRole(roleStr)

		var invitedBy *shared.ID
		if invitedByStr.Valid {
			parsed, err := shared.IDFromString(invitedByStr.String)
			if err == nil {
				invitedBy = &parsed
			}
		}

		var lastLogin *time.Time
		if lastLoginAt.Valid {
			lastLogin = &lastLoginAt.Time
		}

		members = append(members, &tenant.MemberWithUser{
			ID:              id,
			UserID:          userID,
			Role:            role,
			InvitedBy:       invitedBy,
			JoinedAt:        joinedAt,
			Email:           email,
			Name:            name,
			AvatarURL:       avatarURL.String,
			Status:          status,
			LastLoginAt:     lastLogin,
			MFAStatus:       mfaStatus,
			PendingSetup:    pendingSetup,
			Kind:            tenant.MemberKind(kind),
			HomeDomain:      homeDomain.String,
			HomeTenantName:  homeName.String,
			ExpiresAt:       nullTimeValue(expiresAt),
			SuspendedReason: suspendedReason.String,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate members: %w", err)
	}

	return &tenant.MemberSearchResult{
		Members: members,
		Total:   total,
	}, nil
}

// GetMemberByEmail retrieves a member by email address within a tenant.
// Role is fetched from v_user_effective_role view.
// Status is the MEMBERSHIP status (tenant_members.status), see GetMemberStats.
func (r *TenantRepository) GetMemberByEmail(ctx context.Context, tenantID shared.ID, email string) (*tenant.MemberWithUser, error) {
	query := `
		SELECT
			m.id, m.user_id, COALESCE(ver.role, 'member') as role, m.invited_by, m.joined_at,
			u.email, u.name, u.avatar_url, COALESCE(m.status, 'active') as status, u.last_login_at,
			(u.auth_provider = 'local' AND u.password_hash IS NULL AND u.last_login_at IS NULL) AS pending_setup
		FROM tenant_members m
		INNER JOIN users u ON u.id = m.user_id
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1 AND LOWER(u.email) = LOWER($2)
	`

	var (
		idStr, userIDStr, roleStr string
		invitedByStr              sql.NullString
		joinedAt                  time.Time
		memberEmail, name         string
		avatarURL                 sql.NullString
		status                    string
		lastLoginAt               sql.NullTime
		pendingSetup              bool
	)

	err := r.db.QueryRowContext(ctx, query, tenantID.String(), email).Scan(
		&idStr, &userIDStr, &roleStr, &invitedByStr, &joinedAt,
		&memberEmail, &name, &avatarURL, &status, &lastLoginAt, &pendingSetup,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get member by email: %w", err)
	}

	id, _ := shared.IDFromString(idStr)
	userID, _ := shared.IDFromString(userIDStr)
	role, _ := tenant.ParseRole(roleStr)

	var invitedBy *shared.ID
	if invitedByStr.Valid {
		parsed, err := shared.IDFromString(invitedByStr.String)
		if err == nil {
			invitedBy = &parsed
		}
	}

	var lastLogin *time.Time
	if lastLoginAt.Valid {
		lastLogin = &lastLoginAt.Time
	}

	return &tenant.MemberWithUser{
		ID:           id,
		UserID:       userID,
		Role:         role,
		InvitedBy:    invitedBy,
		JoinedAt:     joinedAt,
		Email:        memberEmail,
		Name:         name,
		AvatarURL:    avatarURL.String,
		Status:       status,
		LastLoginAt:  lastLogin,
		PendingSetup: pendingSetup,
	}, nil
}

// GetMemberStats retrieves member statistics for a tenant.
// Role counts are fetched from v_user_effective_role view.
//
// "Active" here means the MEMBERSHIP is active (tenant_members.status='active').
// We deliberately do NOT use users.status — that field is a global, platform-
// wide state that has no tenant context and no UI to manage it. The tenant
// admin only cares whether a member's access to *this* tenant is active or
// suspended; that information lives on tenant_members.status.
//
// All seven aggregates (total / active / role counts × 4 / pending invites)
// are computed in a SINGLE round trip via a CTE that materialises the
// member rows once and feeds the COUNT() FILTER aggregates from that
// CTE plus a sub-SELECT for invitations. The previous version issued
// three sequential queries to the same table set.
func (r *TenantRepository) GetMemberStats(ctx context.Context, tenantID shared.ID) (*tenant.MemberStats, error) {
	query := `
		WITH members AS (
			SELECT m.user_id, COALESCE(m.status, 'active') AS status, ver.role AS effective_role
			FROM tenant_members m
			LEFT JOIN v_user_effective_role ver
			    ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
			WHERE m.tenant_id = $1
		)
		SELECT
			COUNT(*) FILTER (WHERE status <> 'offboarded')                     AS total,
			COUNT(*) FILTER (WHERE status = 'active')                          AS active,
			COUNT(*) FILTER (WHERE status = 'suspended')                       AS suspended,
			COUNT(*) FILTER (WHERE status = 'offboarded')                      AS offboarded,
			COUNT(*) FILTER (WHERE effective_role = 'owner' AND status <> 'offboarded')  AS owners,
			COUNT(*) FILTER (WHERE effective_role = 'admin' AND status <> 'offboarded')  AS admins,
			COUNT(*) FILTER (WHERE (effective_role = 'member' OR effective_role IS NULL) AND status <> 'offboarded') AS members_cnt,
			COUNT(*) FILTER (WHERE effective_role = 'viewer' AND status <> 'offboarded') AS viewers,
			(
				SELECT COUNT(*)
				FROM tenant_invitations
				WHERE tenant_id = $1 AND accepted_at IS NULL AND expires_at > NOW()
			) AS pending_invites
		FROM members
	`

	var (
		total, active, suspended, offboarded  int
		owners, admins, membersCount, viewers int
		pendingInvites                        int
	)
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(
		&total, &active, &suspended, &offboarded,
		&owners, &admins, &membersCount, &viewers,
		&pendingInvites,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get member stats: %w", err)
	}

	return &tenant.MemberStats{
		TotalMembers:      total,
		ActiveMembers:     active,
		SuspendedMembers:  suspended,
		OffboardedMembers: offboarded,
		PendingInvites:    pendingInvites,
		RoleCounts: map[string]int{
			"owner":  owners,
			"admin":  admins,
			"member": membersCount,
			"viewer": viewers,
		},
	}, nil
}

// GetUserSuspendedMemberships returns the suspended memberships for a user.
// Mirrors GetUserMemberships but with the inverted status filter. Used by
// the login flow so the UI can surface "your access to {tenant} is suspended"
// instead of routing the user to onboarding when they have only-suspended
// memberships left.
func (r *TenantRepository) GetUserSuspendedMemberships(ctx context.Context, userID shared.ID) ([]tenant.UserMembership, error) {
	query := `
		SELECT
			t.id,
			t.slug,
			t.name,
			COALESCE(ver.role, m.role) as effective_role
		FROM tenant_members m
		INNER JOIN tenants t ON t.id = m.tenant_id
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.user_id = $1
		  AND m.status = 'suspended'
		ORDER BY m.suspended_at DESC NULLS LAST, m.joined_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get suspended memberships: %w", err)
	}
	defer rows.Close()

	var memberships []tenant.UserMembership
	for rows.Next() {
		var m tenant.UserMembership
		if err := rows.Scan(&m.TenantID, &m.TenantSlug, &m.TenantName, &m.Role); err != nil {
			return nil, fmt.Errorf("failed to scan suspended membership: %w", err)
		}
		memberships = append(memberships, m)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate suspended memberships: %w", err)
	}

	return memberships, nil
}

// GetUserMembershipsWithStatus returns BOTH active and suspended
// memberships in a single query, partitioned by status. The login
// flow needs both lists (active for token exchange, suspended for
// the "your access is suspended" UI message); the previous
// implementation called GetUserMemberships and
// GetUserSuspendedMemberships sequentially, doubling the round-trip
// cost on every login.
//
// The returned struct keeps the API stable: callers that only need
// active memberships read .Active, callers that need both read both.
func (r *TenantRepository) GetUserMembershipsWithStatus(
	ctx context.Context, userID shared.ID,
) (*tenant.UserMembershipsByStatus, error) {
	query := `
		SELECT
			t.id,
			t.slug,
			t.name,
			COALESCE(ver.role, m.role) as effective_role,
			COALESCE(m.status, 'active') as status
		FROM tenant_members m
		INNER JOIN tenants t ON t.id = m.tenant_id
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.user_id = $1
		ORDER BY
		    CASE WHEN m.status = 'suspended' THEN m.suspended_at ELSE m.joined_at END DESC NULLS LAST
	`

	rows, err := r.db.QueryContext(ctx, query, userID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get user memberships: %w", err)
	}
	defer rows.Close()

	result := &tenant.UserMembershipsByStatus{}
	for rows.Next() {
		var (
			m      tenant.UserMembership
			status string
		)
		if err := rows.Scan(&m.TenantID, &m.TenantSlug, &m.TenantName, &m.Role, &status); err != nil {
			return nil, fmt.Errorf("failed to scan membership: %w", err)
		}
		// Positive buckets only: an offboarded tombstone (or any status
		// added later) is in neither list, so it never yields a token.
		switch status {
		case "suspended":
			result.Suspended = append(result.Suspended, m)
		case "active":
			result.Active = append(result.Active, m)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate memberships: %w", err)
	}

	return result, nil
}

// GetUserMemberships returns lightweight membership data for JWT tokens.
// Uses v_user_effective_role view to get the highest-priority role from user_roles table.
// SECURITY: Suspended memberships are excluded so suspended users cannot exchange
// refresh tokens for tenant-scoped access tokens.
func (r *TenantRepository) GetUserMemberships(ctx context.Context, userID shared.ID) ([]tenant.UserMembership, error) {
	// Query using the effective role view (gets highest-hierarchy role from user_roles)
	// Falls back to tenant_members.role if user_roles hasn't been synced yet
	query := `
		SELECT
			t.id,
			t.slug,
			t.name,
			COALESCE(ver.role, m.role) as effective_role
		FROM tenant_members m
		INNER JOIN tenants t ON t.id = m.tenant_id
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.user_id = $1
		  AND m.status = 'active'
		ORDER BY m.joined_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, userID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get user memberships: %w", err)
	}
	defer rows.Close()

	var memberships []tenant.UserMembership
	for rows.Next() {
		var m tenant.UserMembership
		if err := rows.Scan(&m.TenantID, &m.TenantSlug, &m.TenantName, &m.Role); err != nil {
			return nil, fmt.Errorf("failed to scan membership: %w", err)
		}
		memberships = append(memberships, m)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate memberships: %w", err)
	}

	return memberships, nil
}

// =============================================================================
// Invitation Operations
// =============================================================================

// CreateInvitation creates a new invitation.
func (r *TenantRepository) CreateInvitation(ctx context.Context, inv *tenant.Invitation) error {
	query := `
		INSERT INTO tenant_invitations (id, tenant_id, email, role, role_ids, token, invited_by, expires_at, created_at,
		                                access_expires_at, access_expiry_reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	_, err := r.db.ExecContext(ctx, query,
		inv.ID().String(),
		inv.TenantID().String(),
		inv.Email(),
		inv.Role().String(),
		pq.Array(inv.RoleIDs()),
		inv.Token(),
		inv.InvitedBy().String(),
		inv.ExpiresAt(),
		inv.CreatedAt(),
		nullTime(inv.Access().ExpiresAt),
		nullString(inv.Access().Reason),
	)
	if err != nil {
		return fmt.Errorf("failed to create invitation: %w", err)
	}

	return nil
}

// GetInvitationByToken retrieves an invitation by token.
func (r *TenantRepository) GetInvitationByToken(ctx context.Context, token string) (*tenant.Invitation, error) {
	query := `
		SELECT id, tenant_id, email, role, role_ids, token, invited_by, expires_at, accepted_at, created_at,
		       access_expires_at, access_expiry_reason
		FROM tenant_invitations
		WHERE token = $1
	`

	return r.scanInvitation(r.db.QueryRowContext(ctx, query, token))
}

// GetInvitationByID retrieves an invitation by ID.
func (r *TenantRepository) GetInvitationByID(ctx context.Context, tenantID, id shared.ID) (*tenant.Invitation, error) {
	query := `
		SELECT id, tenant_id, email, role, role_ids, token, invited_by, expires_at, accepted_at, created_at,
		       access_expires_at, access_expiry_reason
		FROM tenant_invitations
		WHERE id = $1 AND tenant_id = $2
	`

	return r.scanInvitation(r.db.QueryRowContext(ctx, query, id.String(), tenantID.String()))
}

// UpdateInvitation updates an invitation's mutable fields (accepted_at and the
// stored token hash — the latter changes when an invitation is resent, which
// rotates the token).
func (r *TenantRepository) UpdateInvitation(ctx context.Context, inv *tenant.Invitation) error {
	query := `
		UPDATE tenant_invitations
		SET accepted_at = $2, token = $3
		WHERE id = $1 AND tenant_id = $4
	`

	result, err := r.db.ExecContext(ctx, query, inv.ID().String(), inv.AcceptedAt(), inv.Token(), inv.TenantID().String())
	if err != nil {
		return fmt.Errorf("failed to update invitation: %w", err)
	}

	rows, rowErr := result.RowsAffected()
	if rowErr != nil {
		return fmt.Errorf("rows affected: %w", rowErr)
	}
	if rows == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// DeleteInvitation removes an invitation.
func (r *TenantRepository) DeleteInvitation(ctx context.Context, tenantID, id shared.ID) error {
	query := `DELETE FROM tenant_invitations WHERE tenant_id = $1 AND id = $2`

	result, err := r.db.ExecContext(ctx, query, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("failed to delete invitation: %w", err)
	}

	rows, rowErr := result.RowsAffected()
	if rowErr != nil {
		return fmt.Errorf("rows affected: %w", rowErr)
	}
	if rows == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// ListPendingInvitationsByTenant lists pending invitations for a tenant.
func (r *TenantRepository) ListPendingInvitationsByTenant(ctx context.Context, tenantID shared.ID) ([]*tenant.Invitation, error) {
	query := `
		SELECT id, tenant_id, email, role, role_ids, token, invited_by, expires_at, accepted_at, created_at,
		       access_expires_at, access_expiry_reason
		FROM tenant_invitations
		WHERE tenant_id = $1 AND accepted_at IS NULL AND expires_at > NOW()
		ORDER BY created_at DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list invitations: %w", err)
	}
	defer rows.Close()

	var invitations []*tenant.Invitation
	for rows.Next() {
		inv, err := r.scanInvitationRow(rows)
		if err != nil {
			return nil, err
		}
		invitations = append(invitations, inv)
	}

	return invitations, rows.Err()
}

// GetPendingInvitationByEmail gets a pending invitation by email for a tenant.
func (r *TenantRepository) GetPendingInvitationByEmail(ctx context.Context, tenantID shared.ID, email string) (*tenant.Invitation, error) {
	query := `
		SELECT id, tenant_id, email, role, role_ids, token, invited_by, expires_at, accepted_at, created_at,
		       access_expires_at, access_expiry_reason
		FROM tenant_invitations
		WHERE tenant_id = $1 AND email = $2 AND accepted_at IS NULL AND expires_at > NOW()
	`

	return r.scanInvitation(r.db.QueryRowContext(ctx, query, tenantID.String(), email))
}

// DeleteExpiredInvitations removes all expired invitations.
func (r *TenantRepository) DeleteExpiredInvitations(ctx context.Context) (int64, error) {
	query := `DELETE FROM tenant_invitations WHERE expires_at < NOW() AND accepted_at IS NULL`

	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired invitations: %w", err)
	}

	return result.RowsAffected()
}

// DeletePendingInvitationsByUserID removes EVERY pending (unaccepted)
// invitation for the user's email address in the given tenant. Used
// when a member is removed from a tenant — we want to make sure they
// can't rejoin via a stale invitation token still sitting in their
// inbox.
//
// The user's email is looked up via JOIN so the caller doesn't need
// to fetch it first. Email matching is case-insensitive (LOWER) to
// match the acceptance flow's strings.EqualFold semantics.
//
// Already-accepted invitations are NOT deleted because they are a
// historical audit record. Only unaccepted rows (where the token is
// still potentially usable) get wiped.
//
// Returns the number of rows deleted (0 is not an error — it just
// means the user had no pending invitations to clean up).
func (r *TenantRepository) DeletePendingInvitationsByUserID(
	ctx context.Context,
	tenantID, userID shared.ID,
) (int64, error) {
	query := `
		DELETE FROM tenant_invitations ti
		USING users u
		WHERE ti.tenant_id = $1
		  AND u.id = $2
		  AND LOWER(ti.email) = LOWER(u.email)
		  AND ti.accepted_at IS NULL
	`
	result, err := r.db.ExecContext(ctx, query, tenantID.String(), userID.String())
	if err != nil {
		return 0, fmt.Errorf("failed to delete pending invitations by user id: %w", err)
	}
	return result.RowsAffected()
}

// AcceptInvitationTx atomically updates the invitation and creates the membership in a single transaction.
// Creates membership in tenant_members and role assignment in user_roles.
func (r *TenantRepository) AcceptInvitationTx(ctx context.Context, inv *tenant.Invitation, m *tenant.Membership) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		// Update invitation
		updateQuery := `
			UPDATE tenant_invitations
			SET accepted_at = $2
			WHERE id = $1 AND tenant_id = $3
		`
		// The membership is created in the invitation's own tenant.
		if m.TenantID() != inv.TenantID() {
			return shared.ErrNotFound
		}
		result, err := tx.ExecContext(ctx, updateQuery, inv.ID().String(), inv.AcceptedAt(), inv.TenantID().String())
		if err != nil {
			return fmt.Errorf("failed to update invitation: %w", err)
		}

		rows, rowErr := result.RowsAffected()
		if rowErr != nil {
			return fmt.Errorf("rows affected: %w", rowErr)
		}
		if rows == 0 {
			return shared.ErrNotFound
		}

		// Create membership in tenant_members with role (an offboarded
		// tombstone is re-activated from zero, see CreateMembership).
		insertQuery := `
			INSERT INTO tenant_members (id, user_id, tenant_id, role, invited_by, joined_at,
		                            kind, home_tenant_id, home_domain, expires_at, expiry_reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (user_id, tenant_id) DO UPDATE
		SET id = EXCLUDED.id, role = EXCLUDED.role, invited_by = EXCLUDED.invited_by,
		    joined_at = EXCLUDED.joined_at, status = 'active',
		    offboarded_at = NULL, offboarded_by = NULL, suspended_at = NULL, suspended_by = NULL,
		    suspended_reason = NULL, kind = EXCLUDED.kind, home_tenant_id = EXCLUDED.home_tenant_id,
		    home_domain = EXCLUDED.home_domain, expires_at = EXCLUDED.expires_at,
		    expiry_reason = EXCLUDED.expiry_reason
		WHERE tenant_members.status = 'offboarded'
		`

		var invitedBy sql.NullString
		if m.InvitedBy() != nil {
			invitedBy = sql.NullString{String: m.InvitedBy().String(), Valid: true}
		}

		insRes, err := tx.ExecContext(ctx, insertQuery, append([]any{
			m.ID().String(),
			m.UserID().String(),
			m.TenantID().String(),
			m.Role().String(),
			invitedBy,
			m.JoinedAt(),
		}, memberAccessArgs(m)...)...)
		if err != nil {
			if isCheckViolation(err) {
				return tenant.ErrPlatformAdminMembership
			}
			return fmt.Errorf("failed to create membership: %w", err)
		}
		if n, rerr := insRes.RowsAffected(); rerr == nil && n == 0 {
			return tenant.ErrAlreadyMember
		}

		// Assign RBAC roles from invitation.RoleIDs using multi-row INSERT
		// These are the roles selected by admin when creating the invitation
		roleIDs := inv.RoleIDs()
		if len(roleIDs) > 0 {
			valueStrings := make([]string, 0, len(roleIDs))
			args := make([]any, 0, len(roleIDs)*5)
			for i, roleID := range roleIDs {
				valueStrings = append(valueStrings, fmt.Sprintf("($%d, $%d, $%d, $%d, $%d)", i*5+1, i*5+2, i*5+3, i*5+4, i*5+5))
				args = append(args, m.UserID().String(), m.TenantID().String(), roleID, m.JoinedAt(), invitedBy)
			}

			userRolesQuery := fmt.Sprintf(`
				INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_at, assigned_by)
				VALUES %s
				ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING
			`, strings.Join(valueStrings, ", "))

			_, err = tx.ExecContext(ctx, userRolesQuery, args...)
			if err != nil {
				return fmt.Errorf("failed to assign roles: %w", err)
			}
		}

		return nil
	})
}

// =============================================================================
// Helper functions
// =============================================================================

func (r *TenantRepository) scanTenant(row *sql.Row) (*tenant.Tenant, error) {
	var (
		idStr, name, slug    string
		createdBy            sql.NullString
		description, logoURL sql.NullString
		settingsJSON         []byte
		createdAt, updatedAt time.Time
	)

	err := row.Scan(&idStr, &name, &slug, &description, &logoURL, &settingsJSON, &createdBy, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan tenant: %w", err)
	}

	id, _ := shared.IDFromString(idStr)

	var settings map[string]any
	if err := json.Unmarshal(settingsJSON, &settings); err != nil {
		settings = make(map[string]any)
	}

	return tenant.Reconstitute(
		id, name, slug, description.String, logoURL.String,
		settings, createdBy.String, createdAt, updatedAt,
	), nil
}

func (r *TenantRepository) scanMembership(row *sql.Row) (*tenant.Membership, error) {
	var (
		idStr, userIDStr, tenantIDStr, roleStr string
		invitedByStr                           sql.NullString
		joinedAt                               time.Time
		statusStr                              string
		suspendedAt                            sql.NullTime
		suspendedByStr                         sql.NullString
	)

	var acc memberAccessCols
	err := row.Scan(
		&idStr, &userIDStr, &tenantIDStr, &roleStr,
		&invitedByStr, &joinedAt,
		&statusStr, &suspendedAt, &suspendedByStr,
		&acc.kind, &acc.home, &acc.domain, &acc.expiresAt, &acc.reason, &acc.suspendedReason,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan membership: %w", err)
	}

	id, _ := shared.IDFromString(idStr)
	userID, _ := shared.IDFromString(userIDStr)
	tenantID, _ := shared.IDFromString(tenantIDStr)
	role, _ := tenant.ParseRole(roleStr)

	var invitedBy *shared.ID
	if invitedByStr.Valid {
		parsed, err := shared.IDFromString(invitedByStr.String)
		if err == nil {
			invitedBy = &parsed
		}
	}

	var suspendedAtPtr *time.Time
	if suspendedAt.Valid {
		t := suspendedAt.Time
		suspendedAtPtr = &t
	}

	var suspendedBy *shared.ID
	if suspendedByStr.Valid {
		parsed, err := shared.IDFromString(suspendedByStr.String)
		if err == nil {
			suspendedBy = &parsed
		}
	}

	return acc.apply(tenant.ReconstituteMembershipWithStatus(
		id, userID, tenantID, role, invitedBy, joinedAt,
		tenant.MemberStatus(statusStr), suspendedAtPtr, suspendedBy,
	)), nil
}

func (r *TenantRepository) scanMembershipRow(rows *sql.Rows) (*tenant.Membership, error) {
	var (
		idStr, userIDStr, tenantIDStr, roleStr string
		invitedByStr                           sql.NullString
		joinedAt                               time.Time
		statusStr                              string
		suspendedAt                            sql.NullTime
		suspendedByStr                         sql.NullString
	)

	var acc memberAccessCols
	err := rows.Scan(&idStr, &userIDStr, &tenantIDStr, &roleStr, &invitedByStr, &joinedAt,
		&statusStr, &suspendedAt, &suspendedByStr,
		&acc.kind, &acc.home, &acc.domain, &acc.expiresAt, &acc.reason, &acc.suspendedReason)
	if err != nil {
		return nil, fmt.Errorf("failed to scan membership: %w", err)
	}

	id, _ := shared.IDFromString(idStr)
	userID, _ := shared.IDFromString(userIDStr)
	tenantID, _ := shared.IDFromString(tenantIDStr)
	role, _ := tenant.ParseRole(roleStr)

	var invitedBy *shared.ID
	if invitedByStr.Valid {
		parsed, err := shared.IDFromString(invitedByStr.String)
		if err == nil {
			invitedBy = &parsed
		}
	}

	var suspendedAtPtr *time.Time
	if suspendedAt.Valid {
		t := suspendedAt.Time
		suspendedAtPtr = &t
	}
	var suspendedBy *shared.ID
	if suspendedByStr.Valid {
		if parsed, perr := shared.IDFromString(suspendedByStr.String); perr == nil {
			suspendedBy = &parsed
		}
	}
	return acc.apply(tenant.ReconstituteMembershipWithStatus(id, userID, tenantID, role, invitedBy, joinedAt,
		tenant.MemberStatus(statusStr), suspendedAtPtr, suspendedBy)), nil
}

// memberAccessCols are the external-member columns of tenant_members.
type memberAccessCols struct {
	kind            string
	home            sql.NullString
	domain          sql.NullString
	expiresAt       sql.NullTime
	reason          sql.NullString
	suspendedReason sql.NullString
}

func (c memberAccessCols) apply(m *tenant.Membership) *tenant.Membership {
	var home *shared.ID
	if c.home.Valid {
		if id, err := shared.IDFromString(c.home.String); err == nil {
			home = &id
		}
	}
	return m.WithAccessState(tenant.MemberKind(c.kind), home, c.domain.String,
		nullTimeValue(c.expiresAt), c.reason.String, c.suspendedReason.String)
}

// memberAccessArgs are the insert values of the external-member columns.
func memberAccessArgs(m *tenant.Membership) []any {
	return []any{string(m.Kind()), nullID(m.HomeTenantID()), nullString(m.HomeDomain()),
		nullTime(m.ExpiresAt()), nullString(m.ExpiryReason())}
}

func (r *TenantRepository) scanInvitation(row *sql.Row) (*tenant.Invitation, error) {
	var (
		idStr, tenantIDStr, email, roleStr, token, invitedByStr string
		roleIDs                                                 pq.StringArray
		expiresAt, createdAt                                    time.Time
		acceptedAt                                              sql.NullTime
	)

	var accessAt sql.NullTime
	var accessReason sql.NullString
	err := row.Scan(&idStr, &tenantIDStr, &email, &roleStr, &roleIDs, &token, &invitedByStr, &expiresAt, &acceptedAt, &createdAt,
		&accessAt, &accessReason)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan invitation: %w", err)
	}

	id, _ := shared.IDFromString(idStr)
	tenantID, _ := shared.IDFromString(tenantIDStr)
	role, _ := tenant.ParseRole(roleStr)
	invitedBy, _ := shared.IDFromString(invitedByStr)

	var acceptedAtPtr *time.Time
	if acceptedAt.Valid {
		acceptedAtPtr = &acceptedAt.Time
	}

	inv := tenant.ReconstituteInvitation(
		id, tenantID, email, role, []string(roleIDs), token, invitedBy, expiresAt, acceptedAtPtr, createdAt,
	)
	inv.SetAccess(tenant.ExternalAccess{ExpiresAt: nullTimeValue(accessAt), Reason: accessReason.String})
	return inv, nil
}

func (r *TenantRepository) scanInvitationRow(rows *sql.Rows) (*tenant.Invitation, error) {
	var (
		idStr, tenantIDStr, email, roleStr, token, invitedByStr string
		roleIDs                                                 pq.StringArray
		expiresAt, createdAt                                    time.Time
		acceptedAt                                              sql.NullTime
	)

	var accessAt sql.NullTime
	var accessReason sql.NullString
	err := rows.Scan(&idStr, &tenantIDStr, &email, &roleStr, &roleIDs, &token, &invitedByStr, &expiresAt, &acceptedAt, &createdAt,
		&accessAt, &accessReason)
	if err != nil {
		return nil, fmt.Errorf("failed to scan invitation: %w", err)
	}

	id, _ := shared.IDFromString(idStr)
	tenantID, _ := shared.IDFromString(tenantIDStr)
	role, _ := tenant.ParseRole(roleStr)
	invitedBy, _ := shared.IDFromString(invitedByStr)

	var acceptedAtPtr *time.Time
	if acceptedAt.Valid {
		acceptedAtPtr = &acceptedAt.Time
	}

	inv := tenant.ReconstituteInvitation(
		id, tenantID, email, role, []string(roleIDs), token, invitedBy, expiresAt, acceptedAtPtr, createdAt,
	)
	inv.SetAccess(tenant.ExternalAccess{ExpiresAt: nullTimeValue(accessAt), Reason: accessReason.String})
	return inv, nil
}

// AllowedRecipients reports, for each (lower-cased) address, whether it may
// receive the organization's scheduled reports: an active member of the
// tenant, or an address in one of its Security.AllowedDomains (owner decision
// D12). With no allowed domains, members only.
func (r *TenantRepository) AllowedRecipients(ctx context.Context, tenantID shared.ID, emails []string) (map[string]bool, error) {
	out := make(map[string]bool, len(emails))
	if len(emails) == 0 {
		return out, nil
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT LOWER(u.email) FROM tenant_members m JOIN users u ON u.id = m.user_id
		 WHERE m.tenant_id = $1 AND m.status = 'active' AND LOWER(u.email) = ANY($2)`,
		tenantID.String(), pq.Array(emails))
	if err != nil {
		return nil, fmt.Errorf("list member recipients: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e string
		if err := rows.Scan(&e); err != nil {
			return nil, fmt.Errorf("scan member recipient: %w", err)
		}
		out[e] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	t, err := r.GetByID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load tenant settings: %w", err)
	}
	sec := t.TypedSettings().Security
	if len(sec.AllowedDomains) > 0 {
		for _, e := range emails {
			if !out[e] && sec.EmailDomainAllowed(e) {
				out[e] = true
			}
		}
	}
	return out, nil
}

// ListExpiredMemberships returns active memberships whose access expired at or
// before now, across tenants, for the expiry controller (a system path; each
// row carries its own tenant id and is suspended in that tenant only).
func (r *TenantRepository) ListExpiredMemberships(ctx context.Context, now time.Time, limit int) ([]*tenant.Membership, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	query := `
		SELECT m.id, m.user_id, m.tenant_id, COALESCE(ver.role, 'member') as role,
		       m.invited_by, m.joined_at,
		       COALESCE(m.status, 'active') as status, m.suspended_at, m.suspended_by,
		       m.kind, m.home_tenant_id, m.home_domain, m.expires_at, m.expiry_reason, m.suspended_reason
		FROM tenant_members m
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.status = 'active' AND m.expires_at IS NOT NULL AND m.expires_at <= $1
		ORDER BY m.expires_at ASC
		LIMIT $2
	`
	rows, err := r.db.QueryContext(ctx, query, now, limit)
	if err != nil {
		return nil, fmt.Errorf("list expired memberships: %w", err)
	}
	defer rows.Close()
	var out []*tenant.Membership
	for rows.Next() {
		m, err := r.scanMembershipRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ListActiveExternalFromHome returns the active external memberships of host
// whose home organization is home (trust revocation).
func (r *TenantRepository) ListActiveExternalFromHome(ctx context.Context, host, home shared.ID) ([]*tenant.Membership, error) {
	query := `
		SELECT m.id, m.user_id, m.tenant_id, COALESCE(ver.role, 'member') as role,
		       m.invited_by, m.joined_at,
		       COALESCE(m.status, 'active') as status, m.suspended_at, m.suspended_by,
		       m.kind, m.home_tenant_id, m.home_domain, m.expires_at, m.expiry_reason, m.suspended_reason
		FROM tenant_members m
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1 AND m.kind = 'external' AND m.home_tenant_id = $2 AND m.status = 'active'
		LIMIT 5000
	`
	rows, err := r.db.QueryContext(ctx, query, host.String(), home.String())
	if err != nil {
		return nil, fmt.Errorf("list external members from home: %w", err)
	}
	defer rows.Close()
	var out []*tenant.Membership
	for rows.Next() {
		m, err := r.scanMembershipRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
