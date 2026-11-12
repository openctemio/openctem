package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scimgroup"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ScimGroupRepository persists SCIM groups and their membership.
type ScimGroupRepository struct {
	db *DB
}

// NewScimGroupRepository creates the repository.
func NewScimGroupRepository(db *DB) *ScimGroupRepository {
	return &ScimGroupRepository{db: db}
}

func (r *ScimGroupRepository) Create(ctx context.Context, g *scimgroup.ScimGroup) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO scim_groups (id, tenant_id, display_name, external_id, created_at, updated_at)
		 VALUES ($1, $2, $3, NULLIF($4,''), $5, $6)`,
		g.ID().String(), g.TenantID().String(), g.DisplayName(), g.ExternalID(), g.CreatedAt(), g.UpdatedAt(),
	); err != nil {
		return fmt.Errorf("insert scim group: %w", err)
	}
	if err := insertGroupMembers(ctx, tx, g.ID(), g.Members()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func insertGroupMembers(ctx context.Context, tx *sql.Tx, groupID shared.ID, userIDs []shared.ID) error {
	for _, uid := range userIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO scim_group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
			groupID.String(), uid.String(),
		); err != nil {
			return fmt.Errorf("insert group member: %w", err)
		}
	}
	return nil
}

func (r *ScimGroupRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*scimgroup.ScimGroup, error) {
	var (
		displayName string
		externalID  sql.NullString
		createdAt   sql.NullTime
		updatedAt   sql.NullTime
	)
	err := r.db.QueryRowContext(ctx,
		`SELECT display_name, external_id, created_at, updated_at FROM scim_groups WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), id.String(),
	).Scan(&displayName, &externalID, &createdAt, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, scimgroup.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get scim group: %w", err)
	}
	members, err := r.membersOf(ctx, id)
	if err != nil {
		return nil, err
	}
	return scimgroup.Reconstruct(id, tenantID, displayName, externalID.String, members, createdAt.Time, updatedAt.Time), nil
}

func (r *ScimGroupRepository) membersOf(ctx context.Context, groupID shared.ID) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT user_id FROM scim_group_members WHERE group_id = $1 ORDER BY user_id`, groupID.String())
	if err != nil {
		return nil, fmt.Errorf("query group members: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		id, perr := shared.IDFromString(s)
		if perr != nil {
			return nil, fmt.Errorf("parse member id: %w", perr)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (r *ScimGroupRepository) ListByTenant(ctx context.Context, tenantID shared.ID) ([]*scimgroup.ScimGroup, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, display_name, external_id, created_at, updated_at FROM scim_groups WHERE tenant_id = $1 ORDER BY created_at`,
		tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list scim groups: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var groups []*scimgroup.ScimGroup
	for rows.Next() {
		var (
			idStr, displayName string
			externalID         sql.NullString
			createdAt          sql.NullTime
			updatedAt          sql.NullTime
		)
		if err := rows.Scan(&idStr, &displayName, &externalID, &createdAt, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan scim group: %w", err)
		}
		id, perr := shared.IDFromString(idStr)
		if perr != nil {
			return nil, fmt.Errorf("parse group id: %w", perr)
		}
		members, merr := r.membersOf(ctx, id)
		if merr != nil {
			return nil, merr
		}
		groups = append(groups, scimgroup.Reconstruct(id, tenantID, displayName, externalID.String, members, createdAt.Time, updatedAt.Time))
	}
	return groups, rows.Err()
}

func (r *ScimGroupRepository) UpdateDisplayName(ctx context.Context, tenantID, id shared.ID, displayName string) error {
	res, err := r.db.ExecContext(ctx,
		`UPDATE scim_groups SET display_name = $1, updated_at = NOW() WHERE tenant_id = $2 AND id = $3`,
		displayName, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("update scim group: %w", err)
	}
	return notFoundIfZero(res)
}

func (r *ScimGroupRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM scim_groups WHERE tenant_id = $1 AND id = $2`, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("delete scim group: %w", err)
	}
	return notFoundIfZero(res)
}

func (r *ScimGroupRepository) SetMembers(ctx context.Context, tenantID, groupID shared.ID, userIDs []shared.ID) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Touch (and lock) the group first: a group of another tenant stops here,
	// before its membership is touched.
	res, err := tx.ExecContext(ctx,
		`UPDATE scim_groups SET updated_at = NOW() WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), groupID.String())
	if err != nil {
		return fmt.Errorf("touch group: %w", err)
	}
	if err := notFoundIfZero(res); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM scim_group_members WHERE group_id = $1`, groupID.String()); err != nil {
		return fmt.Errorf("clear group members: %w", err)
	}
	if err := insertGroupMembers(ctx, tx, groupID, userIDs); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func (r *ScimGroupRepository) AddMembers(ctx context.Context, tenantID, groupID shared.ID, userIDs []shared.ID) error {
	for _, uid := range userIDs {
		if _, err := r.db.ExecContext(ctx,
			`INSERT INTO scim_group_members (group_id, user_id)
			 SELECT g.id, $2 FROM scim_groups g WHERE g.id = $1 AND g.tenant_id = $3
			 ON CONFLICT DO NOTHING`,
			groupID.String(), uid.String(), tenantID.String(),
		); err != nil {
			return fmt.Errorf("add group member: %w", err)
		}
	}
	return nil
}

func (r *ScimGroupRepository) RemoveMembers(ctx context.Context, tenantID, groupID shared.ID, userIDs []shared.ID) error {
	for _, uid := range userIDs {
		if _, err := r.db.ExecContext(ctx,
			`DELETE FROM scim_group_members
			 WHERE group_id = $1 AND user_id = $2
			   AND group_id IN (SELECT id FROM scim_groups WHERE tenant_id = $3)`,
			groupID.String(), uid.String(), tenantID.String(),
		); err != nil {
			return fmt.Errorf("remove group member: %w", err)
		}
	}
	return nil
}

func (r *ScimGroupRepository) RoleGroupNamesForUser(ctx context.Context, tenantID, userID shared.ID) ([]string, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT g.display_name FROM scim_groups g
		   JOIN scim_group_members m ON m.group_id = g.id
		  WHERE g.tenant_id = $1 AND m.user_id = $2`,
		tenantID.String(), userID.String())
	if err != nil {
		return nil, fmt.Errorf("group names for user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("scan group name: %w", err)
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

func (r *ScimGroupRepository) GetRoleMappings(ctx context.Context, tenantID shared.ID) (map[string]scimgroup.RoleMapping, error) {
	return queryRoleMappings(ctx, r.db, tenantID, "")
}

// roleMappingQuerier is *sql.DB or *sql.Tx.
type roleMappingQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

func queryRoleMappings(ctx context.Context, q roleMappingQuerier, tenantID shared.ID, suffix string) (map[string]scimgroup.RoleMapping, error) {
	rows, err := q.QueryContext(ctx,
		`SELECT group_name, role, configured_by, configured_by_owner
		   FROM scim_group_role_mappings WHERE tenant_id = $1`+suffix, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("get role mappings: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]scimgroup.RoleMapping{}
	for rows.Next() {
		var (
			name, role string
			by         sql.NullString
			byOwner    bool
		)
		if err := rows.Scan(&name, &role, &by, &byOwner); err != nil {
			return nil, fmt.Errorf("scan role mapping: %w", err)
		}
		m := scimgroup.RoleMapping{Role: role, ConfiguredByOwner: byOwner}
		if by.Valid {
			if id, perr := shared.IDFromString(by.String); perr == nil {
				m.ConfiguredBy = &id
			}
		}
		out[name] = m
	}
	return out, rows.Err()
}

func (r *ScimGroupRepository) ReplaceRoleMappings(ctx context.Context, tenantID shared.ID, plan scimgroup.RoleMappingPlan) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// One writer per tenant: the plan's checks and the write see the same rows
	// (the mapping set can be empty, so row locks alone would not serialize).
	if _, err := tx.ExecContext(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('scim_group_role_mappings:' || $1::text, 0))`,
		tenantID.String()); err != nil {
		return fmt.Errorf("lock role mappings: %w", err)
	}
	current, err := queryRoleMappings(ctx, tx, tenantID, " FOR UPDATE")
	if err != nil {
		return err
	}
	next, err := plan(current)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM scim_group_role_mappings WHERE tenant_id = $1`, tenantID.String()); err != nil {
		return fmt.Errorf("clear role mappings: %w", err)
	}
	for name, m := range next {
		var by any
		if m.ConfiguredBy != nil {
			by = m.ConfiguredBy.String()
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO scim_group_role_mappings (tenant_id, group_name, role, configured_by, configured_by_owner)
			 VALUES ($1, $2, $3, $4, $5)`,
			tenantID.String(), strings.ToLower(strings.TrimSpace(name)), m.Role, by, m.ConfiguredByOwner,
		); err != nil {
			return fmt.Errorf("insert role mapping: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

func notFoundIfZero(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if n == 0 {
		return scimgroup.ErrNotFound
	}
	return nil
}
