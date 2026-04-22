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
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
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

// Update updates an existing tenant.
func (r *TenantRepository) Update(ctx context.Context, t *tenant.Tenant) error {
	settings, err := json.Marshal(t.Settings())
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	query := `
		UPDATE tenants
		SET name = $2, slug = $3, description = $4, logo_url = $5, settings = $6, updated_at = $7
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		t.ID().String(),
		t.Name(),
		t.Slug(),
		t.Description(),
		t.LogoURL(),
		settings,
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
	query := `SELECT id FROM tenants ORDER BY id`

	rows, err := r.db.QueryContext(ctx, query)
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
	// Insert into tenant_members with role
	memberQuery := `
		INSERT INTO tenant_members (id, user_id, tenant_id, role, invited_by, joined_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	var invitedBy sql.NullString
	if m.InvitedBy() != nil {
		invitedBy = sql.NullString{String: m.InvitedBy().String(), Valid: true}
	}

	_, err := r.db.ExecContext(ctx, memberQuery,
		m.ID().String(),
		m.UserID().String(),
		m.TenantID().String(),
		m.Role().String(),
		invitedBy,
		m.JoinedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to create membership: %w", err)
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

// GetMembership retrieves a membership by user and tenant.
// Role is fetched from v_user_effective_role view.
// Status fields are populated so callers (e.g. RequireMembership middleware)
// can enforce suspension on every request.
func (r *TenantRepository) GetMembership(ctx context.Context, userID shared.ID, tenantID shared.ID) (*tenant.Membership, error) {
	query := `
		SELECT m.id, m.user_id, m.tenant_id, COALESCE(ver.role, 'member') as role,
		       m.invited_by, m.joined_at,
		       COALESCE(m.status, 'active') as status, m.suspended_at, m.suspended_by
		FROM tenant_members m
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.user_id = $1 AND m.tenant_id = $2
	`

	return r.scanMembership(r.db.QueryRowContext(ctx, query, userID.String(), tenantID.String()))
}

// GetMembershipByID retrieves a membership by ID.
// Role is fetched from v_user_effective_role view.
// Status fields are populated so the service layer can branch on suspension.
func (r *TenantRepository) GetMembershipByID(ctx context.Context, id shared.ID) (*tenant.Membership, error) {
	query := `
		SELECT m.id, m.user_id, m.tenant_id, COALESCE(ver.role, 'member') as role,
		       m.invited_by, m.joined_at,
		       COALESCE(m.status, 'active') as status, m.suspended_at, m.suspended_by
		FROM tenant_members m
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.id = $1
	`

	return r.scanMembership(r.db.QueryRowContext(ctx, query, id.String()))
}

// UpdateMembership updates a membership's role.
// Role is updated in user_roles table (tenant_members no longer has role column).
func (r *TenantRepository) UpdateMembership(ctx context.Context, m *tenant.Membership) error {
	// Verify membership exists
	var userID, tenantID string
	err := r.db.QueryRowContext(ctx,
		"SELECT user_id, tenant_id FROM tenant_members WHERE id = $1",
		m.ID().String(),
	).Scan(&userID, &tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return shared.ErrNotFound
		}
		return fmt.Errorf("failed to get membership: %w", err)
	}

	// Get current role from user_roles via view
	var oldRole string
	err = r.db.QueryRowContext(ctx,
		"SELECT COALESCE(role, 'member') FROM v_user_effective_role WHERE user_id = $1 AND tenant_id = $2",
		userID, tenantID,
	).Scan(&oldRole)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to get current role: %w", err)
	}

	// If role is changing, update both tenant_members and user_roles
	if oldRole != m.Role().String() {
		// Update role in tenant_members
		_, err = r.db.ExecContext(ctx,
			"UPDATE tenant_members SET role = $1 WHERE id = $2",
			m.Role().String(), m.ID().String(),
		)
		if err != nil {
			return fmt.Errorf("failed to update membership role: %w", err)
		}

		// Remove old system role (only system roles, keep custom roles)
		_, err = r.db.ExecContext(ctx, `
			DELETE FROM user_roles
			WHERE user_id = $1 AND tenant_id = $2 AND role_id IN (
				SELECT id FROM roles WHERE is_system = TRUE AND tenant_id IS NULL
			)
		`, userID, tenantID)
		if err != nil {
			return fmt.Errorf("failed to remove old role: %w", err)
		}

		// Add new role
		_, err = r.db.ExecContext(ctx, `
			INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_at)
			SELECT $1, $2, r.id, NOW()
			FROM roles r
			WHERE r.slug = $3 AND r.is_system = TRUE AND r.tenant_id IS NULL
			ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING
		`, userID, tenantID, m.Role().String())
		if err != nil {
			return fmt.Errorf("failed to add new role: %w", err)
		}
	}

	return nil
}

// UpdateMembershipStatus persists the status / suspended_at /
// suspended_by fields on a membership. Called by SuspendMember and
// ReactivateMember in the service layer.
func (r *TenantRepository) UpdateMembershipStatus(ctx context.Context, m *tenant.Membership) error {
	query := `
		UPDATE tenant_members
		SET status = $2, suspended_at = $3, suspended_by = $4
		WHERE id = $1
	`
	result, err := r.db.ExecContext(ctx, query,
		m.ID().String(),
		string(m.Status()),
		nullTime(m.SuspendedAt()),
		nullIDPtr(m.SuspendedBy()),
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
func (r *TenantRepository) DeleteMembership(ctx context.Context, id shared.ID) error {
	// First get user_id and tenant_id for user_roles cleanup
	var userID, tenantID string
	err := r.db.QueryRowContext(ctx,
		"SELECT user_id, tenant_id FROM tenant_members WHERE id = $1",
		id.String(),
	).Scan(&userID, &tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return shared.ErrNotFound
		}
		return fmt.Errorf("failed to get membership: %w", err)
	}

	// Delete from tenant_members
	query := `DELETE FROM tenant_members WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
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

// ListMembersByTenant lists all members of a tenant.
// Role is fetched from v_user_effective_role view.
func (r *TenantRepository) ListMembersByTenant(ctx context.Context, tenantID shared.ID) ([]*tenant.Membership, error) {
	query := `
		SELECT m.id, m.user_id, m.tenant_id, COALESCE(ver.role, 'member') as role, m.invited_by, m.joined_at
		FROM tenant_members m
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1
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
		WHERE m.user_id = $1
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
	query := `SELECT COUNT(*) FROM tenant_members WHERE tenant_id = $1`

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
			u.email, u.name, u.avatar_url, COALESCE(m.status, 'active') as status, u.last_login_at
		FROM tenant_members m
		INNER JOIN users u ON u.id = m.user_id
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1
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
		)

		if err := rows.Scan(
			&idStr, &userIDStr, &roleStr, &invitedByStr, &joinedAt,
			&email, &name, &avatarURL, &status, &lastLoginAt,
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
			ID:          id,
			UserID:      userID,
			Role:        role,
			InvitedBy:   invitedBy,
			JoinedAt:    joinedAt,
			Email:       email,
			Name:        name,
			AvatarURL:   avatarURL.String,
			Status:      status,
			LastLoginAt: lastLogin,
		})
	}

	return members, rows.Err()
}

// SearchMembersWithUserInfo searches members with filtering and pagination.
// Search is case-insensitive and matches name or email.
// Uses COUNT(*) OVER() window function to get total count in a single query (optimization).
func (r *TenantRepository) SearchMembersWithUserInfo(ctx context.Context, tenantID shared.ID, filters tenant.MemberSearchFilters) (*tenant.MemberSearchResult, error) {
	// Build WHERE clause with optional search filter
	whereClause := "WHERE m.tenant_id = $1"
	args := []any{tenantID.String()}
	argIndex := 2

	// Add search filter if provided
	if filters.Search != "" {
		searchPattern := "%" + escapeLikePattern(filters.Search) + "%"
		whereClause += fmt.Sprintf(" AND (LOWER(u.name) LIKE LOWER($%d) OR LOWER(u.email) LIKE LOWER($%d))", argIndex, argIndex)
		args = append(args, searchPattern)
		argIndex++
	}

	// Single query with COUNT(*) OVER() window function to avoid 2 round-trips
	// This returns total matching count alongside each row.
	// Status is the MEMBERSHIP status (tenant_members.status), see GetMemberStats.
	selectQuery := fmt.Sprintf(`
		SELECT
			m.id, m.user_id, COALESCE(ver.role, 'member') as role, m.invited_by, m.joined_at,
			u.email, u.name, u.avatar_url, COALESCE(m.status, 'active') as status, u.last_login_at,
			COUNT(*) OVER() as total_count
		FROM tenant_members m
		INNER JOIN users u ON u.id = m.user_id
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
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
			totalCount                int
		)

		if err := rows.Scan(
			&idStr, &userIDStr, &roleStr, &invitedByStr, &joinedAt,
			&email, &name, &avatarURL, &status, &lastLoginAt,
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
			ID:          id,
			UserID:      userID,
			Role:        role,
			InvitedBy:   invitedBy,
			JoinedAt:    joinedAt,
			Email:       email,
			Name:        name,
			AvatarURL:   avatarURL.String,
			Status:      status,
			LastLoginAt: lastLogin,
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
			u.email, u.name, u.avatar_url, COALESCE(m.status, 'active') as status, u.last_login_at
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
	)

	err := r.db.QueryRowContext(ctx, query, tenantID.String(), email).Scan(
		&idStr, &userIDStr, &roleStr, &invitedByStr, &joinedAt,
		&memberEmail, &name, &avatarURL, &status, &lastLoginAt,
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
		ID:          id,
		UserID:      userID,
		Role:        role,
		InvitedBy:   invitedBy,
		JoinedAt:    joinedAt,
		Email:       memberEmail,
		Name:        name,
		AvatarURL:   avatarURL.String,
		Status:      status,
		LastLoginAt: lastLogin,
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
			COUNT(*)                                                            AS total,
			COUNT(*) FILTER (WHERE status = 'active')                          AS active,
			COUNT(*) FILTER (WHERE effective_role = 'owner')                   AS owners,
			COUNT(*) FILTER (WHERE effective_role = 'admin')                   AS admins,
			COUNT(*) FILTER (WHERE effective_role = 'member' OR effective_role IS NULL) AS members_cnt,
			COUNT(*) FILTER (WHERE effective_role = 'viewer')                  AS viewers,
			(
				SELECT COUNT(*)
				FROM tenant_invitations
				WHERE tenant_id = $1 AND accepted_at IS NULL AND expires_at > NOW()
			) AS pending_invites
		FROM members
	`

	var (
		total, active                         int
		owners, admins, membersCount, viewers int
		pendingInvites                        int
	)
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(
		&total, &active,
		&owners, &admins, &membersCount, &viewers,
		&pendingInvites,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get member stats: %w", err)
	}

	return &tenant.MemberStats{
		TotalMembers:   total,
		ActiveMembers:  active,
		PendingInvites: pendingInvites,
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
		switch status {
		case "suspended":
			result.Suspended = append(result.Suspended, m)
		default:
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
		INSERT INTO tenant_invitations (id, tenant_id, email, role, role_ids, token, invited_by, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
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
	)
	if err != nil {
		return fmt.Errorf("failed to create invitation: %w", err)
	}

	return nil
}

// GetInvitationByToken retrieves an invitation by token.
func (r *TenantRepository) GetInvitationByToken(ctx context.Context, token string) (*tenant.Invitation, error) {
	query := `
		SELECT id, tenant_id, email, role, role_ids, token, invited_by, expires_at, accepted_at, created_at
		FROM tenant_invitations
		WHERE token = $1
	`

	return r.scanInvitation(r.db.QueryRowContext(ctx, query, token))
}

// GetInvitationByID retrieves an invitation by ID.
func (r *TenantRepository) GetInvitationByID(ctx context.Context, id shared.ID) (*tenant.Invitation, error) {
	query := `
		SELECT id, tenant_id, email, role, role_ids, token, invited_by, expires_at, accepted_at, created_at
		FROM tenant_invitations
		WHERE id = $1
	`

	return r.scanInvitation(r.db.QueryRowContext(ctx, query, id.String()))
}

// UpdateInvitation updates an invitation.
func (r *TenantRepository) UpdateInvitation(ctx context.Context, inv *tenant.Invitation) error {
	query := `
		UPDATE tenant_invitations
		SET accepted_at = $2
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query, inv.ID().String(), inv.AcceptedAt())
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
func (r *TenantRepository) DeleteInvitation(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM tenant_invitations WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
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
		SELECT id, tenant_id, email, role, role_ids, token, invited_by, expires_at, accepted_at, created_at
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
		SELECT id, tenant_id, email, role, role_ids, token, invited_by, expires_at, accepted_at, created_at
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
			WHERE id = $1
		`
		result, err := tx.ExecContext(ctx, updateQuery, inv.ID().String(), inv.AcceptedAt())
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

		// Create membership in tenant_members with role
		insertQuery := `
			INSERT INTO tenant_members (id, user_id, tenant_id, role, invited_by, joined_at)
			VALUES ($1, $2, $3, $4, $5, $6)
		`

		var invitedBy sql.NullString
		if m.InvitedBy() != nil {
			invitedBy = sql.NullString{String: m.InvitedBy().String(), Valid: true}
		}

		_, err = tx.ExecContext(ctx, insertQuery,
			m.ID().String(),
			m.UserID().String(),
			m.TenantID().String(),
			m.Role().String(),
			invitedBy,
			m.JoinedAt(),
		)
		if err != nil {
			return fmt.Errorf("failed to create membership: %w", err)
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

	err := row.Scan(
		&idStr, &userIDStr, &tenantIDStr, &roleStr,
		&invitedByStr, &joinedAt,
		&statusStr, &suspendedAt, &suspendedByStr,
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

	return tenant.ReconstituteMembershipWithStatus(
		id, userID, tenantID, role, invitedBy, joinedAt,
		tenant.MemberStatus(statusStr), suspendedAtPtr, suspendedBy,
	), nil
}

func (r *TenantRepository) scanMembershipRow(rows *sql.Rows) (*tenant.Membership, error) {
	var (
		idStr, userIDStr, tenantIDStr, roleStr string
		invitedByStr                           sql.NullString
		joinedAt                               time.Time
	)

	err := rows.Scan(&idStr, &userIDStr, &tenantIDStr, &roleStr, &invitedByStr, &joinedAt)
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

	return tenant.ReconstituteMembership(id, userID, tenantID, role, invitedBy, joinedAt), nil
}

func (r *TenantRepository) scanInvitation(row *sql.Row) (*tenant.Invitation, error) {
	var (
		idStr, tenantIDStr, email, roleStr, token, invitedByStr string
		roleIDs                                                 pq.StringArray
		expiresAt, createdAt                                    time.Time
		acceptedAt                                              sql.NullTime
	)

	err := row.Scan(&idStr, &tenantIDStr, &email, &roleStr, &roleIDs, &token, &invitedByStr, &expiresAt, &acceptedAt, &createdAt)
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

	return tenant.ReconstituteInvitation(
		id, tenantID, email, role, []string(roleIDs), token, invitedBy, expiresAt, acceptedAtPtr, createdAt,
	), nil
}

func (r *TenantRepository) scanInvitationRow(rows *sql.Rows) (*tenant.Invitation, error) {
	var (
		idStr, tenantIDStr, email, roleStr, token, invitedByStr string
		roleIDs                                                 pq.StringArray
		expiresAt, createdAt                                    time.Time
		acceptedAt                                              sql.NullTime
	)

	err := rows.Scan(&idStr, &tenantIDStr, &email, &roleStr, &roleIDs, &token, &invitedByStr, &expiresAt, &acceptedAt, &createdAt)
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

	return tenant.ReconstituteInvitation(
		id, tenantID, email, role, []string(roleIDs), token, invitedBy, expiresAt, acceptedAtPtr, createdAt,
	), nil
}
