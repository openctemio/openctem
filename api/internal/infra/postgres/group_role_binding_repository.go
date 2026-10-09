package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/group"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// GroupRoleBindingRepository persists team role bindings
// (group_role_bindings). Every statement carries the tenant; the composite
// foreign keys refuse a group or role of another tenant and every built-in
// role (tenant_id NULL).
type GroupRoleBindingRepository struct {
	db *DB
}

// NewGroupRoleBindingRepository creates the repository.
func NewGroupRoleBindingRepository(db *DB) *GroupRoleBindingRepository {
	return &GroupRoleBindingRepository{db: db}
}

var _ group.RoleBindingRepository = (*GroupRoleBindingRepository)(nil)

func (r *GroupRoleBindingRepository) listBindings(ctx context.Context, where string, args ...any) ([]group.RoleBinding, error) {
	query := `
		SELECT b.tenant_id, b.group_id, g.name, b.role_id, ro.name, b.created_by, b.created_at
		FROM group_role_bindings b
		JOIN groups g ON g.id = b.group_id AND g.tenant_id = b.tenant_id
		JOIN roles ro ON ro.id = b.role_id AND ro.tenant_id = b.tenant_id
		WHERE ` + where + `
		ORDER BY g.name, ro.name`
	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list role bindings: %w", err)
	}
	defer rows.Close()
	var out []group.RoleBinding
	for rows.Next() {
		var tid, gid, rid string
		var b group.RoleBinding
		var createdBy sql.NullString
		var at time.Time
		if err := rows.Scan(&tid, &gid, &b.GroupName, &rid, &b.RoleName, &createdBy, &at); err != nil {
			return nil, fmt.Errorf("scan role binding: %w", err)
		}
		b.TenantID, _ = shared.IDFromString(tid)
		b.GroupID, _ = shared.IDFromString(gid)
		b.RoleID, _ = shared.IDFromString(rid)
		if createdBy.Valid {
			if id, err := shared.IDFromString(createdBy.String); err == nil {
				b.CreatedBy = &id
			}
		}
		b.CreatedAt = at
		out = append(out, b)
	}
	return out, rows.Err()
}

// ListGroupRoles returns the roles bound to a team.
func (r *GroupRoleBindingRepository) ListGroupRoles(ctx context.Context, tenantID, groupID shared.ID) ([]group.RoleBinding, error) {
	return r.listBindings(ctx, "b.tenant_id = $1 AND b.group_id = $2", tenantID.String(), groupID.String())
}

// ListRoleGroups returns the teams a role is bound to.
func (r *GroupRoleBindingRepository) ListRoleGroups(ctx context.Context, tenantID, roleID shared.ID) ([]group.RoleBinding, error) {
	return r.listBindings(ctx, "b.tenant_id = $1 AND b.role_id = $2", tenantID.String(), roleID.String())
}

// BindRole binds a custom role of the tenant to a team of the tenant.
func (r *GroupRoleBindingRepository) BindRole(ctx context.Context, tenantID, groupID, roleID shared.ID, createdBy *shared.ID) error {
	var by sql.NullString
	if createdBy != nil {
		by = sql.NullString{String: createdBy.String(), Valid: true}
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO group_role_bindings (tenant_id, group_id, role_id, created_by) VALUES ($1, $2, $3, $4)`,
		tenantID.String(), groupID.String(), roleID.String(), by)
	switch {
	case err == nil:
		return nil
	case isUniqueViolation(err):
		return group.ErrRoleAlreadyBound
	case isForeignKeyViolation(err):
		// A built-in role, or a group or role of another tenant.
		return group.ErrSystemRoleBinding
	default:
		return fmt.Errorf("bind role: %w", err)
	}
}

// UnbindRole removes a binding.
func (r *GroupRoleBindingRepository) UnbindRole(ctx context.Context, tenantID, groupID, roleID shared.ID) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM group_role_bindings WHERE tenant_id = $1 AND group_id = $2 AND role_id = $3`,
		tenantID.String(), groupID.String(), roleID.String())
	if err != nil {
		return fmt.Errorf("unbind role: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("unbind role: %w", err)
	} else if n == 0 {
		return group.ErrRoleBindingMissing
	}
	return nil
}

// ListActiveMemberIDs returns the members of the team whose membership has
// not ended.
func (r *GroupRoleBindingRepository) ListActiveMemberIDs(ctx context.Context, tenantID, groupID shared.ID) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT gm.user_id
		FROM group_members gm
		JOIN groups g ON g.id = gm.group_id AND g.tenant_id = $1
		WHERE gm.group_id = $2 AND (gm.expires_at IS NULL OR gm.expires_at > now())`,
		tenantID.String(), groupID.String())
	if err != nil {
		return nil, fmt.Errorf("list team members: %w", err)
	}
	defer rows.Close()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan team member: %w", err)
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, fmt.Errorf("team member id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// HasExternalMembers reports whether any member of the team is an external
// member of the organization (RFC-058) or a service account: neither may hold
// full data access.
func (r *GroupRoleBindingRepository) HasExternalMembers(ctx context.Context, tenantID, groupID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM group_members gm
			JOIN groups g ON g.id = gm.group_id AND g.tenant_id = $1
			JOIN tenant_members tm ON tm.user_id = gm.user_id AND tm.tenant_id = $1
			JOIN users u ON u.id = gm.user_id
			WHERE gm.group_id = $2 AND (tm.kind = 'external' OR u.kind = 'service'))`,
		tenantID.String(), groupID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check external team members: %w", err)
	}
	return ok, nil
}

// IsExternalMember reports whether the user is an external member of the
// organization or a service account (the full-data ceiling applies to both).
func (r *GroupRoleBindingRepository) IsExternalMember(ctx context.Context, tenantID, userID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM tenant_members WHERE tenant_id = $1 AND user_id = $2 AND kind = 'external')
		     OR EXISTS (SELECT 1 FROM users WHERE id = $2 AND kind = 'service')`,
		tenantID.String(), userID.String()).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("check external member: %w", err)
	}
	return ok, nil
}
