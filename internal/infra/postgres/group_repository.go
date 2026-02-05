package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/group"
	"github.com/openctemio/api/pkg/domain/shared"
)

// GroupRepository implements group.Repository using PostgreSQL.
type GroupRepository struct {
	db *DB
}

// NewGroupRepository creates a new GroupRepository.
func NewGroupRepository(db *DB) *GroupRepository {
	return &GroupRepository{db: db}
}

// =============================================================================
// Group CRUD Operations
// =============================================================================

// Create persists a new group.
func (r *GroupRepository) Create(ctx context.Context, g *group.Group) error {
	settings, err := json.Marshal(g.Settings())
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	notifConfig, err := json.Marshal(g.NotificationConfig())
	if err != nil {
		return fmt.Errorf("failed to marshal notification config: %w", err)
	}

	metadata, err := json.Marshal(g.Metadata())
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO groups (
			id, tenant_id, name, slug, description, group_type,
			external_id, external_source, settings, notification_config,
			metadata, is_active, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	var externalID, externalSource sql.NullString
	if g.ExternalID() != nil {
		externalID = sql.NullString{String: *g.ExternalID(), Valid: true}
	}
	if g.ExternalSource() != nil {
		externalSource = sql.NullString{String: g.ExternalSource().String(), Valid: true}
	}

	_, err = r.db.ExecContext(ctx, query,
		g.ID().String(),
		g.TenantID().String(),
		g.Name(),
		g.Slug(),
		g.Description(),
		g.GroupType().String(),
		externalID,
		externalSource,
		settings,
		notifConfig,
		metadata,
		g.IsActive(),
		g.CreatedAt(),
		g.UpdatedAt(),
	)
	if err != nil {
		if strings.Contains(err.Error(), "groups_tenant_id_slug_key") {
			return group.ErrGroupSlugExists
		}
		return fmt.Errorf("failed to create group: %w", err)
	}

	return nil
}

// GetByID retrieves a group by ID.
func (r *GroupRepository) GetByID(ctx context.Context, id shared.ID) (*group.Group, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, group_type,
			   external_id, external_source, settings, notification_config,
			   metadata, is_active, created_at, updated_at
		FROM groups
		WHERE id = $1
	`

	return r.scanGroup(r.db.QueryRowContext(ctx, query, id.String()))
}

// GetBySlug retrieves a group by tenant and slug.
func (r *GroupRepository) GetBySlug(ctx context.Context, tenantID shared.ID, slug string) (*group.Group, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, group_type,
			   external_id, external_source, settings, notification_config,
			   metadata, is_active, created_at, updated_at
		FROM groups
		WHERE tenant_id = $1 AND slug = $2
	`

	return r.scanGroup(r.db.QueryRowContext(ctx, query, tenantID.String(), slug))
}

// Update updates an existing group.
func (r *GroupRepository) Update(ctx context.Context, g *group.Group) error {
	settings, err := json.Marshal(g.Settings())
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	notifConfig, err := json.Marshal(g.NotificationConfig())
	if err != nil {
		return fmt.Errorf("failed to marshal notification config: %w", err)
	}

	metadata, err := json.Marshal(g.Metadata())
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		UPDATE groups
		SET name = $2, slug = $3, description = $4, group_type = $5,
			external_id = $6, external_source = $7, settings = $8,
			notification_config = $9, metadata = $10, is_active = $11, updated_at = $12
		WHERE id = $1
	`

	var externalID, externalSource sql.NullString
	if g.ExternalID() != nil {
		externalID = sql.NullString{String: *g.ExternalID(), Valid: true}
	}
	if g.ExternalSource() != nil {
		externalSource = sql.NullString{String: g.ExternalSource().String(), Valid: true}
	}

	result, err := r.db.ExecContext(ctx, query,
		g.ID().String(),
		g.Name(),
		g.Slug(),
		g.Description(),
		g.GroupType().String(),
		externalID,
		externalSource,
		settings,
		notifConfig,
		metadata,
		g.IsActive(),
		g.UpdatedAt(),
	)
	if err != nil {
		if strings.Contains(err.Error(), "groups_tenant_id_slug_key") {
			return group.ErrGroupSlugExists
		}
		return fmt.Errorf("failed to update group: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return group.ErrGroupNotFound
	}

	return nil
}

// Delete removes a group.
func (r *GroupRepository) Delete(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM groups WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete group: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return group.ErrGroupNotFound
	}

	return nil
}

// =============================================================================
// Group Query Operations
// =============================================================================

// List lists groups with filtering.
func (r *GroupRepository) List(ctx context.Context, tenantID shared.ID, filter group.ListFilter) ([]*group.Group, error) {
	query, args := r.buildListQuery(tenantID, filter, false)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups: %w", err)
	}
	defer rows.Close()

	var groups []*group.Group
	for rows.Next() {
		g, err := r.scanGroupRow(rows)
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}

	return groups, rows.Err()
}

// Count counts groups with filtering.
func (r *GroupRepository) Count(ctx context.Context, tenantID shared.ID, filter group.ListFilter) (int64, error) {
	query, args := r.buildListQuery(tenantID, filter, true)

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count groups: %w", err)
	}

	return count, nil
}

// ExistsBySlug checks if a group with the given slug exists.
func (r *GroupRepository) ExistsBySlug(ctx context.Context, tenantID shared.ID, slug string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM groups WHERE tenant_id = $1 AND slug = $2)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), slug).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check slug existence: %w", err)
	}

	return exists, nil
}

// ListByIDs retrieves multiple groups by their IDs.
func (r *GroupRepository) ListByIDs(ctx context.Context, ids []shared.ID) ([]*group.Group, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id.String()
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_id, name, slug, description, group_type,
			   external_id, external_source, settings, notification_config,
			   metadata, is_active, created_at, updated_at
		FROM groups
		WHERE id IN (%s)
	`, strings.Join(placeholders, ", "))

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list groups by IDs: %w", err)
	}
	defer rows.Close()

	var groups []*group.Group
	for rows.Next() {
		g, err := r.scanGroupRow(rows)
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}

	return groups, rows.Err()
}

// GetByExternalID retrieves a group by external sync ID.
func (r *GroupRepository) GetByExternalID(ctx context.Context, tenantID shared.ID, source group.ExternalSource, externalID string) (*group.Group, error) {
	query := `
		SELECT id, tenant_id, name, slug, description, group_type,
			   external_id, external_source, settings, notification_config,
			   metadata, is_active, created_at, updated_at
		FROM groups
		WHERE tenant_id = $1 AND external_source = $2 AND external_id = $3
	`

	return r.scanGroup(r.db.QueryRowContext(ctx, query, tenantID.String(), source.String(), externalID))
}

// =============================================================================
// Member Operations
// =============================================================================

// AddMember adds a member to a group.
func (r *GroupRepository) AddMember(ctx context.Context, member *group.Member) error {
	query := `
		INSERT INTO group_members (group_id, user_id, role, joined_at, added_by)
		VALUES ($1, $2, $3, $4, $5)
	`

	var addedBy sql.NullString
	if member.AddedBy() != nil {
		addedBy = sql.NullString{String: member.AddedBy().String(), Valid: true}
	}

	_, err := r.db.ExecContext(ctx, query,
		member.GroupID().String(),
		member.UserID().String(),
		member.Role().String(),
		member.JoinedAt(),
		addedBy,
	)
	if err != nil {
		if strings.Contains(err.Error(), "group_members_pkey") {
			return group.ErrMemberAlreadyExists
		}
		return fmt.Errorf("failed to add member: %w", err)
	}

	return nil
}

// GetMember retrieves a member by group and user ID.
func (r *GroupRepository) GetMember(ctx context.Context, groupID, userID shared.ID) (*group.Member, error) {
	query := `
		SELECT group_id, user_id, role, joined_at, added_by
		FROM group_members
		WHERE group_id = $1 AND user_id = $2
	`

	return r.scanMember(r.db.QueryRowContext(ctx, query, groupID.String(), userID.String()))
}

// UpdateMember updates a member's role.
func (r *GroupRepository) UpdateMember(ctx context.Context, member *group.Member) error {
	query := `
		UPDATE group_members
		SET role = $3
		WHERE group_id = $1 AND user_id = $2
	`

	result, err := r.db.ExecContext(ctx, query,
		member.GroupID().String(),
		member.UserID().String(),
		member.Role().String(),
	)
	if err != nil {
		return fmt.Errorf("failed to update member: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return group.ErrMemberNotFound
	}

	return nil
}

// RemoveMember removes a member from a group.
func (r *GroupRepository) RemoveMember(ctx context.Context, groupID, userID shared.ID) error {
	query := `DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`

	result, err := r.db.ExecContext(ctx, query, groupID.String(), userID.String())
	if err != nil {
		return fmt.Errorf("failed to remove member: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return group.ErrMemberNotFound
	}

	return nil
}

// ListMembers lists all members of a group.
func (r *GroupRepository) ListMembers(ctx context.Context, groupID shared.ID) ([]*group.Member, error) {
	query := `
		SELECT group_id, user_id, role, joined_at, added_by
		FROM group_members
		WHERE group_id = $1
		ORDER BY joined_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, groupID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list members: %w", err)
	}
	defer rows.Close()

	var members []*group.Member
	for rows.Next() {
		m, err := r.scanMemberRow(rows)
		if err != nil {
			return nil, err
		}
		members = append(members, m)
	}

	return members, rows.Err()
}

// ListMembersWithUserInfo lists members with user details.
func (r *GroupRepository) ListMembersWithUserInfo(ctx context.Context, groupID shared.ID) ([]*group.MemberWithUser, error) {
	query := `
		SELECT
			gm.group_id, gm.user_id, gm.role, gm.joined_at, gm.added_by,
			u.email, u.name, u.avatar_url, u.last_login_at
		FROM group_members gm
		INNER JOIN users u ON u.id = gm.user_id
		WHERE gm.group_id = $1
		ORDER BY gm.joined_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, groupID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list members with user info: %w", err)
	}
	defer rows.Close()

	var members []*group.MemberWithUser
	for rows.Next() {
		var (
			groupIDStr, userIDStr, roleStr string
			joinedAt                       time.Time
			addedByStr                     sql.NullString
			email, name                    string
			avatarURL                      sql.NullString
			lastLoginAt                    sql.NullTime
		)

		if err := rows.Scan(
			&groupIDStr, &userIDStr, &roleStr, &joinedAt, &addedByStr,
			&email, &name, &avatarURL, &lastLoginAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan member with user: %w", err)
		}

		groupID, _ := shared.IDFromString(groupIDStr)
		userID, _ := shared.IDFromString(userIDStr)
		role := group.MemberRole(roleStr)

		var addedBy *shared.ID
		if addedByStr.Valid {
			parsed, err := shared.IDFromString(addedByStr.String)
			if err == nil {
				addedBy = &parsed
			}
		}

		var lastLogin *time.Time
		if lastLoginAt.Valid {
			lastLogin = &lastLoginAt.Time
		}

		member := group.ReconstituteMember(groupID, userID, role, joinedAt, addedBy)
		members = append(members, &group.MemberWithUser{
			Member:      member,
			Email:       email,
			Name:        name,
			AvatarURL:   avatarURL.String,
			LastLoginAt: lastLogin,
		})
	}

	return members, rows.Err()
}

// CountMembers counts members in a group.
func (r *GroupRepository) CountMembers(ctx context.Context, groupID shared.ID) (int64, error) {
	query := `SELECT COUNT(*) FROM group_members WHERE group_id = $1`

	var count int64
	err := r.db.QueryRowContext(ctx, query, groupID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count members: %w", err)
	}

	return count, nil
}

// GetMemberStats retrieves member statistics for a group.
func (r *GroupRepository) GetMemberStats(ctx context.Context, groupID shared.ID) (*group.MemberStats, error) {
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(CASE WHEN role = 'owner' THEN 1 END) as owners,
			COUNT(CASE WHEN role = 'lead' THEN 1 END) as leads,
			COUNT(CASE WHEN role = 'member' THEN 1 END) as members
		FROM group_members
		WHERE group_id = $1
	`

	var total, owners, leads, membersCount int
	err := r.db.QueryRowContext(ctx, query, groupID.String()).Scan(
		&total, &owners, &leads, &membersCount,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get member stats: %w", err)
	}

	return &group.MemberStats{
		TotalMembers: total,
		RoleCounts: map[string]int{
			"owner":  owners,
			"lead":   leads,
			"member": membersCount,
		},
	}, nil
}

// IsMember checks if a user is a member of a group.
func (r *GroupRepository) IsMember(ctx context.Context, groupID, userID shared.ID) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM group_members WHERE group_id = $1 AND user_id = $2)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, groupID.String(), userID.String()).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check membership: %w", err)
	}

	return exists, nil
}

// =============================================================================
// User-centric Queries
// =============================================================================

// ListGroupsByUser lists all groups a user belongs to.
func (r *GroupRepository) ListGroupsByUser(ctx context.Context, tenantID, userID shared.ID) ([]*group.GroupWithRole, error) {
	query := `
		SELECT
			g.id, g.tenant_id, g.name, g.slug, g.description, g.group_type,
			g.external_id, g.external_source, g.settings, g.notification_config,
			g.metadata, g.is_active, g.created_at, g.updated_at,
			gm.role
		FROM groups g
		INNER JOIN group_members gm ON g.id = gm.group_id
		WHERE g.tenant_id = $1 AND gm.user_id = $2 AND g.is_active = true
		ORDER BY g.name ASC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), userID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list groups by user: %w", err)
	}
	defer rows.Close()

	var groups []*group.GroupWithRole
	for rows.Next() {
		var (
			idStr, tenantIDStr, name, slug, groupTypeStr string
			description                                  sql.NullString
			externalID, externalSource                   sql.NullString
			settingsJSON, notifConfigJSON, metadataJSON  []byte
			isActive                                     bool
			createdAt, updatedAt                         time.Time
			roleStr                                      string
		)

		err := rows.Scan(
			&idStr, &tenantIDStr, &name, &slug, &description, &groupTypeStr,
			&externalID, &externalSource, &settingsJSON, &notifConfigJSON,
			&metadataJSON, &isActive, &createdAt, &updatedAt,
			&roleStr,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan group with role: %w", err)
		}

		g := r.reconstituteGroup(
			idStr, tenantIDStr, name, slug, description.String, groupTypeStr,
			externalID, externalSource, settingsJSON, notifConfigJSON,
			metadataJSON, isActive, createdAt, updatedAt,
		)

		groups = append(groups, &group.GroupWithRole{
			Group: g,
			Role:  group.MemberRole(roleStr),
		})
	}

	return groups, rows.Err()
}

// ListGroupIDsByUser returns group IDs for a user in a tenant.
func (r *GroupRepository) ListGroupIDsByUser(ctx context.Context, tenantID, userID shared.ID) ([]shared.ID, error) {
	query := `
		SELECT g.id
		FROM groups g
		INNER JOIN group_members gm ON g.id = gm.group_id
		WHERE g.tenant_id = $1 AND gm.user_id = $2 AND g.is_active = true
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), userID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list group IDs by user: %w", err)
	}
	defer rows.Close()

	var ids []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan group ID: %w", err)
		}
		id, _ := shared.IDFromString(idStr)
		ids = append(ids, id)
	}

	return ids, rows.Err()
}

// =============================================================================
// Permission Set Assignment
// =============================================================================

// AssignPermissionSet assigns a permission set to a group.
func (r *GroupRepository) AssignPermissionSet(ctx context.Context, groupID, permissionSetID shared.ID, assignedBy *shared.ID) error {
	query := `
		INSERT INTO group_permission_sets (group_id, permission_set_id, assigned_at, assigned_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (group_id, permission_set_id) DO NOTHING
	`

	var assignedByStr sql.NullString
	if assignedBy != nil {
		assignedByStr = sql.NullString{String: assignedBy.String(), Valid: true}
	}

	_, err := r.db.ExecContext(ctx, query,
		groupID.String(),
		permissionSetID.String(),
		time.Now().UTC(),
		assignedByStr,
	)
	if err != nil {
		return fmt.Errorf("failed to assign permission set: %w", err)
	}

	return nil
}

// RemovePermissionSet removes a permission set from a group.
func (r *GroupRepository) RemovePermissionSet(ctx context.Context, groupID, permissionSetID shared.ID) error {
	query := `DELETE FROM group_permission_sets WHERE group_id = $1 AND permission_set_id = $2`

	_, err := r.db.ExecContext(ctx, query, groupID.String(), permissionSetID.String())
	if err != nil {
		return fmt.Errorf("failed to remove permission set: %w", err)
	}

	return nil
}

// ListPermissionSetIDs lists permission set IDs assigned to a group.
func (r *GroupRepository) ListPermissionSetIDs(ctx context.Context, groupID shared.ID) ([]shared.ID, error) {
	query := `
		SELECT permission_set_id
		FROM group_permission_sets
		WHERE group_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, groupID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list permission set IDs: %w", err)
	}
	defer rows.Close()

	var ids []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan permission set ID: %w", err)
		}
		id, _ := shared.IDFromString(idStr)
		ids = append(ids, id)
	}

	return ids, rows.Err()
}

// ListGroupsWithPermissionSet lists groups that have a specific permission set.
func (r *GroupRepository) ListGroupsWithPermissionSet(ctx context.Context, permissionSetID shared.ID) ([]*group.Group, error) {
	query := `
		SELECT g.id, g.tenant_id, g.name, g.slug, g.description, g.group_type,
			   g.external_id, g.external_source, g.settings, g.notification_config,
			   g.metadata, g.is_active, g.created_at, g.updated_at
		FROM groups g
		INNER JOIN group_permission_sets gps ON g.id = gps.group_id
		WHERE gps.permission_set_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, permissionSetID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list groups with permission set: %w", err)
	}
	defer rows.Close()

	var groups []*group.Group
	for rows.Next() {
		g, err := r.scanGroupRow(rows)
		if err != nil {
			return nil, err
		}
		groups = append(groups, g)
	}

	return groups, rows.Err()
}

// =============================================================================
// Helper Functions
// =============================================================================

func (r *GroupRepository) buildListQuery(tenantID shared.ID, filter group.ListFilter, countOnly bool) (string, []interface{}) {
	var (
		conditions []string
		args       []interface{}
		argIndex   = 1
	)

	conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
	args = append(args, tenantID.String())
	argIndex++

	if len(filter.GroupTypes) > 0 {
		placeholders := make([]string, len(filter.GroupTypes))
		for i, gt := range filter.GroupTypes {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, gt.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("group_type IN (%s)", strings.Join(placeholders, ", ")))
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR slug ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex, argIndex))
		args = append(args, wrapLikePattern(filter.Search))
		argIndex++
	}

	if filter.ExternalSource != nil {
		conditions = append(conditions, fmt.Sprintf("external_source = $%d", argIndex))
		args = append(args, filter.ExternalSource.String())
		argIndex++
	}

	if filter.HasExternalID != nil {
		if *filter.HasExternalID {
			conditions = append(conditions, "external_id IS NOT NULL")
		} else {
			conditions = append(conditions, "external_id IS NULL")
		}
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIndex))
		args = append(args, *filter.IsActive)
		argIndex++
	}

	whereClause := strings.Join(conditions, " AND ")

	if countOnly {
		return fmt.Sprintf("SELECT COUNT(*) FROM groups WHERE %s", whereClause), args
	}

	// Build SELECT query with ordering and pagination
	// SECURITY: Use allowlist to prevent SQL injection via ORDER BY
	orderBy := sortFieldName
	switch filter.OrderBy {
	case sortFieldName, "slug", sortFieldCreatedAt, sortFieldUpdatedAt, "group_type":
		orderBy = filter.OrderBy
	}
	orderDir := sortOrderASC
	if filter.OrderDesc {
		orderDir = sortOrderDESC
	}

	query := fmt.Sprintf(`
		SELECT id, tenant_id, name, slug, description, group_type,
			   external_id, external_source, settings, notification_config,
			   metadata, is_active, created_at, updated_at
		FROM groups
		WHERE %s
		ORDER BY %s %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, orderDir, argIndex, argIndex+1)

	args = append(args, filter.Limit, filter.Offset)

	return query, args
}

func (r *GroupRepository) scanGroup(row *sql.Row) (*group.Group, error) {
	var (
		idStr, tenantIDStr, name, slug, groupTypeStr string
		description                                  sql.NullString
		externalID, externalSource                   sql.NullString
		settingsJSON, notifConfigJSON, metadataJSON  []byte
		isActive                                     bool
		createdAt, updatedAt                         time.Time
	)

	err := row.Scan(
		&idStr, &tenantIDStr, &name, &slug, &description, &groupTypeStr,
		&externalID, &externalSource, &settingsJSON, &notifConfigJSON,
		&metadataJSON, &isActive, &createdAt, &updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, group.ErrGroupNotFound
		}
		return nil, fmt.Errorf("failed to scan group: %w", err)
	}

	return r.reconstituteGroup(
		idStr, tenantIDStr, name, slug, description.String, groupTypeStr,
		externalID, externalSource, settingsJSON, notifConfigJSON,
		metadataJSON, isActive, createdAt, updatedAt,
	), nil
}

func (r *GroupRepository) scanGroupRow(rows *sql.Rows) (*group.Group, error) {
	var (
		idStr, tenantIDStr, name, slug, groupTypeStr string
		description                                  sql.NullString
		externalID, externalSource                   sql.NullString
		settingsJSON, notifConfigJSON, metadataJSON  []byte
		isActive                                     bool
		createdAt, updatedAt                         time.Time
	)

	err := rows.Scan(
		&idStr, &tenantIDStr, &name, &slug, &description, &groupTypeStr,
		&externalID, &externalSource, &settingsJSON, &notifConfigJSON,
		&metadataJSON, &isActive, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan group: %w", err)
	}

	return r.reconstituteGroup(
		idStr, tenantIDStr, name, slug, description.String, groupTypeStr,
		externalID, externalSource, settingsJSON, notifConfigJSON,
		metadataJSON, isActive, createdAt, updatedAt,
	), nil
}

func (r *GroupRepository) reconstituteGroup(
	idStr, tenantIDStr, name, slug, description, groupTypeStr string,
	externalID, externalSource sql.NullString,
	settingsJSON, notifConfigJSON, metadataJSON []byte,
	isActive bool,
	createdAt, updatedAt time.Time,
) *group.Group {
	id, _ := shared.IDFromString(idStr)
	tenantID, _ := shared.IDFromString(tenantIDStr)
	groupType := group.GroupType(groupTypeStr)

	var extID *string
	var extSource *group.ExternalSource
	if externalID.Valid {
		extID = &externalID.String
	}
	if externalSource.Valid {
		src := group.ExternalSource(externalSource.String)
		extSource = &src
	}

	var settings group.GroupSettings
	if err := json.Unmarshal(settingsJSON, &settings); err != nil {
		settings = group.DefaultGroupSettings()
	}

	var notifConfig group.NotificationConfig
	if err := json.Unmarshal(notifConfigJSON, &notifConfig); err != nil {
		notifConfig = group.DefaultNotificationConfig()
	}

	var metadata map[string]any
	if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
		metadata = make(map[string]any)
	}

	return group.Reconstitute(
		id, tenantID, name, slug, description, groupType,
		extID, extSource, settings, notifConfig, metadata,
		isActive, createdAt, updatedAt,
	)
}

func (r *GroupRepository) scanMember(row *sql.Row) (*group.Member, error) {
	var (
		groupIDStr, userIDStr, roleStr string
		joinedAt                       time.Time
		addedByStr                     sql.NullString
	)

	err := row.Scan(&groupIDStr, &userIDStr, &roleStr, &joinedAt, &addedByStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, group.ErrMemberNotFound
		}
		return nil, fmt.Errorf("failed to scan member: %w", err)
	}

	groupID, _ := shared.IDFromString(groupIDStr)
	userID, _ := shared.IDFromString(userIDStr)
	role := group.MemberRole(roleStr)

	var addedBy *shared.ID
	if addedByStr.Valid {
		parsed, err := shared.IDFromString(addedByStr.String)
		if err == nil {
			addedBy = &parsed
		}
	}

	return group.ReconstituteMember(groupID, userID, role, joinedAt, addedBy), nil
}

func (r *GroupRepository) scanMemberRow(rows *sql.Rows) (*group.Member, error) {
	var (
		groupIDStr, userIDStr, roleStr string
		joinedAt                       time.Time
		addedByStr                     sql.NullString
	)

	err := rows.Scan(&groupIDStr, &userIDStr, &roleStr, &joinedAt, &addedByStr)
	if err != nil {
		return nil, fmt.Errorf("failed to scan member: %w", err)
	}

	groupID, _ := shared.IDFromString(groupIDStr)
	userID, _ := shared.IDFromString(userIDStr)
	role := group.MemberRole(roleStr)

	var addedBy *shared.ID
	if addedByStr.Valid {
		parsed, err := shared.IDFromString(addedByStr.String)
		if err == nil {
			addedBy = &parsed
		}
	}

	return group.ReconstituteMember(groupID, userID, role, joinedAt, addedBy), nil
}
