package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/lib/pq"
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

	rows, _ := result.RowsAffected()
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

	rows, _ := result.RowsAffected()
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
func (r *TenantRepository) GetMembership(ctx context.Context, userID shared.ID, tenantID shared.ID) (*tenant.Membership, error) {
	query := `
		SELECT m.id, m.user_id, m.tenant_id, COALESCE(ver.role, 'member') as role, m.invited_by, m.joined_at
		FROM tenant_members m
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.user_id = $1 AND m.tenant_id = $2
	`

	return r.scanMembership(r.db.QueryRowContext(ctx, query, userID.String(), tenantID.String()))
}

// GetMembershipByID retrieves a membership by ID.
// Role is fetched from v_user_effective_role view.
func (r *TenantRepository) GetMembershipByID(ctx context.Context, id shared.ID) (*tenant.Membership, error) {
	query := `
		SELECT m.id, m.user_id, m.tenant_id, COALESCE(ver.role, 'member') as role, m.invited_by, m.joined_at
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

	rows, _ := result.RowsAffected()
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
			idStr, name, slug, createdBy string
			description, logoURL         sql.NullString
			settingsJSON                 []byte
			createdAt, updatedAt         time.Time
			roleStr                      string
			joinedAt                     time.Time
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
			settings, createdBy, createdAt, updatedAt,
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
func (r *TenantRepository) ListMembersWithUserInfo(ctx context.Context, tenantID shared.ID) ([]*tenant.MemberWithUser, error) {
	query := `
		SELECT
			m.id, m.user_id, COALESCE(ver.role, 'member') as role, m.invited_by, m.joined_at,
			u.email, u.name, u.avatar_url, u.status, u.last_login_at
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
	// This returns total matching count alongside each row
	selectQuery := fmt.Sprintf(`
		SELECT
			m.id, m.user_id, COALESCE(ver.role, 'member') as role, m.invited_by, m.joined_at,
			u.email, u.name, u.avatar_url, u.status, u.last_login_at,
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

	// Pre-allocate slice with expected capacity
	members := make([]*tenant.MemberWithUser, 0, filters.Limit)
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
func (r *TenantRepository) GetMemberByEmail(ctx context.Context, tenantID shared.ID, email string) (*tenant.MemberWithUser, error) {
	query := `
		SELECT
			m.id, m.user_id, COALESCE(ver.role, 'member') as role, m.invited_by, m.joined_at,
			u.email, u.name, u.avatar_url, u.status, u.last_login_at
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
func (r *TenantRepository) GetMemberStats(ctx context.Context, tenantID shared.ID) (*tenant.MemberStats, error) {
	// Get total and active member counts
	memberQuery := `
		SELECT
			COUNT(*) as total,
			COUNT(CASE WHEN u.status = 'active' THEN 1 END) as active
		FROM tenant_members m
		INNER JOIN users u ON u.id = m.user_id
		WHERE m.tenant_id = $1
	`

	var total, active int
	err := r.db.QueryRowContext(ctx, memberQuery, tenantID.String()).Scan(&total, &active)
	if err != nil {
		return nil, fmt.Errorf("failed to get member stats: %w", err)
	}

	// Get role counts from v_user_effective_role
	roleQuery := `
		SELECT
			COUNT(CASE WHEN ver.role = 'owner' THEN 1 END) as owners,
			COUNT(CASE WHEN ver.role = 'admin' THEN 1 END) as admins,
			COUNT(CASE WHEN ver.role = 'member' OR ver.role IS NULL THEN 1 END) as members,
			COUNT(CASE WHEN ver.role = 'viewer' THEN 1 END) as viewers
		FROM tenant_members m
		LEFT JOIN v_user_effective_role ver ON ver.user_id = m.user_id AND ver.tenant_id = m.tenant_id
		WHERE m.tenant_id = $1
	`

	var owners, admins, membersCount, viewers int
	err = r.db.QueryRowContext(ctx, roleQuery, tenantID.String()).Scan(&owners, &admins, &membersCount, &viewers)
	if err != nil {
		return nil, fmt.Errorf("failed to get role counts: %w", err)
	}

	// Get pending invitations count
	inviteQuery := `
		SELECT COUNT(*)
		FROM tenant_invitations
		WHERE tenant_id = $1 AND accepted_at IS NULL AND expires_at > NOW()
	`

	var pendingInvites int
	err = r.db.QueryRowContext(ctx, inviteQuery, tenantID.String()).Scan(&pendingInvites)
	if err != nil {
		return nil, fmt.Errorf("failed to get pending invites: %w", err)
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

// GetUserMemberships returns lightweight membership data for JWT tokens.
// Uses v_user_effective_role view to get the highest-priority role from user_roles table.
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

	rows, _ := result.RowsAffected()
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

	rows, _ := result.RowsAffected()
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

		rows, _ := result.RowsAffected()
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

		// Assign RBAC roles from invitation.RoleIDs
		// These are the roles selected by admin when creating the invitation
		roleIDs := inv.RoleIDs()
		if len(roleIDs) > 0 {
			userRolesQuery := `
				INSERT INTO user_roles (user_id, tenant_id, role_id, assigned_at, assigned_by)
				VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (user_id, tenant_id, role_id) DO NOTHING
			`

			for _, roleID := range roleIDs {
				_, err = tx.ExecContext(ctx, userRolesQuery,
					m.UserID().String(),
					m.TenantID().String(),
					roleID,
					m.JoinedAt(),
					invitedBy,
				)
				if err != nil {
					return fmt.Errorf("failed to assign role %s: %w", roleID, err)
				}
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
		idStr, name, slug, createdBy string
		description, logoURL         sql.NullString
		settingsJSON                 []byte
		createdAt, updatedAt         time.Time
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
		settings, createdBy, createdAt, updatedAt,
	), nil
}

func (r *TenantRepository) scanMembership(row *sql.Row) (*tenant.Membership, error) {
	var (
		idStr, userIDStr, tenantIDStr, roleStr string
		invitedByStr                           sql.NullString
		joinedAt                               time.Time
	)

	err := row.Scan(&idStr, &userIDStr, &tenantIDStr, &roleStr, &invitedByStr, &joinedAt)
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

	return tenant.ReconstituteMembership(id, userID, tenantID, role, invitedBy, joinedAt), nil
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
