package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/savedview"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SavedViewRepository stores saved views (migration 000701). Every statement
// carries the tenant; reads return only views the user may see.
type SavedViewRepository struct {
	db *DB
}

// NewSavedViewRepository creates a SavedViewRepository.
func NewSavedViewRepository(db *DB) *SavedViewRepository {
	return &SavedViewRepository{db: db}
}

var _ savedview.Repository = (*SavedViewRepository)(nil)

// savedViewVisibleSQL is "the user ($2) may see the view" in tenant $1: they
// own it, or it is shared with an active group of the tenant they belong to.
const savedViewVisibleSQL = `(sv.owner_id = $2 OR sv.group_id IN (
	SELECT gm.group_id FROM group_members gm
	JOIN groups g ON g.id = gm.group_id AND g.tenant_id = $1 AND g.is_active = true
	WHERE gm.user_id = $2))`

const savedViewSelectSQL = `SELECT sv.id, sv.tenant_id, sv.owner_id, COALESCE(u.name, ''), sv.group_id, COALESCE(g.name, ''),
	sv.page, sv.name, COALESCE(sv.description, ''), sv.filter, COALESCE(sv.group_by, ''), sv.columns,
	COALESCE(sv.density, ''), sv.created_at, sv.updated_at
	FROM saved_views sv
	LEFT JOIN users u ON u.id = sv.owner_id
	LEFT JOIN groups g ON g.id = sv.group_id AND g.tenant_id = sv.tenant_id`

func scanSavedView(scan func(...any) error) (*savedview.View, error) {
	var v savedview.View
	var group sql.NullString
	var cols pq.StringArray
	if err := scan(&v.ID, &v.TenantID, &v.OwnerID, &v.OwnerName, &group, &v.GroupName, &v.Page, &v.Name,
		&v.Description, &v.Filter, &v.GroupBy, &cols, &v.Density, &v.CreatedAt, &v.UpdatedAt); err != nil {
		return nil, err
	}
	if group.Valid {
		id, err := shared.IDFromString(group.String)
		if err != nil {
			return nil, err
		}
		v.GroupID = &id
	}
	v.Columns = []string(cols)
	return &v, nil
}

func savedViewGroupArg(id *shared.ID) any {
	if id == nil {
		return nil
	}
	return id.String()
}

func savedViewColumnsArg(cols []string) any {
	if len(cols) == 0 {
		return nil
	}
	return pq.Array(cols)
}

// Create inserts a view.
func (r *SavedViewRepository) Create(ctx context.Context, v *savedview.View) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO saved_views
		(id, tenant_id, owner_id, group_id, page, name, description, filter, group_by, columns, density, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, NULLIF($9, ''), $10, NULLIF($11, ''), $12, $12)`,
		v.ID.String(), v.TenantID.String(), v.OwnerID.String(), savedViewGroupArg(v.GroupID), v.Page, v.Name,
		v.Description, v.Filter, v.GroupBy, savedViewColumnsArg(v.Columns), v.Density, v.CreatedAt)
	if err != nil {
		return fmt.Errorf("create saved view: %w", err)
	}
	return nil
}

// Update changes a view of the tenant that the owner owns.
func (r *SavedViewRepository) Update(ctx context.Context, v *savedview.View) error {
	res, err := r.db.ExecContext(ctx, `UPDATE saved_views SET group_id = $4, name = $5, description = NULLIF($6, ''),
		filter = $7, group_by = NULLIF($8, ''), columns = $9, density = NULLIF($10, ''), updated_at = $11
		WHERE tenant_id = $1 AND id = $2 AND owner_id = $3`,
		v.TenantID.String(), v.ID.String(), v.OwnerID.String(), savedViewGroupArg(v.GroupID), v.Name, v.Description,
		v.Filter, v.GroupBy, savedViewColumnsArg(v.Columns), v.Density, v.UpdatedAt)
	if err != nil {
		return fmt.Errorf("update saved view: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return savedview.ErrNotFound
	}
	return nil
}

// Delete removes a view of the tenant that the owner owns.
func (r *SavedViewRepository) Delete(ctx context.Context, tenantID, id, ownerID shared.ID) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM saved_views WHERE tenant_id = $1 AND id = $2 AND owner_id = $3`,
		tenantID.String(), id.String(), ownerID.String())
	if err != nil {
		return fmt.Errorf("delete saved view: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return savedview.ErrNotFound
	}
	return nil
}

// GetVisible returns a view of the tenant the user may see.
func (r *SavedViewRepository) GetVisible(ctx context.Context, tenantID, id, userID shared.ID) (*savedview.View, error) {
	row := r.db.QueryRowContext(ctx, savedViewSelectSQL+` WHERE sv.tenant_id = $1 AND sv.id = $3 AND `+savedViewVisibleSQL,
		tenantID.String(), userID.String(), id.String())
	v, err := scanSavedView(row.Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, savedview.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get saved view: %w", err)
	}
	return v, nil
}

// ListVisible lists the views of one page the user may see: their own first,
// then shared ones, by name.
func (r *SavedViewRepository) ListVisible(ctx context.Context, tenantID, userID shared.ID, page string) ([]*savedview.View, error) {
	rows, err := r.db.QueryContext(ctx, savedViewSelectSQL+` WHERE sv.tenant_id = $1 AND sv.page = $3 AND `+savedViewVisibleSQL+`
		ORDER BY (sv.owner_id = $2) DESC, lower(sv.name), sv.id LIMIT 500`,
		tenantID.String(), userID.String(), page)
	if err != nil {
		return nil, fmt.Errorf("list saved views: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]*savedview.View, 0, 16)
	for rows.Next() {
		v, err := scanSavedView(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan saved view: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (r *SavedViewRepository) count(ctx context.Context, q string, args ...any) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx, q, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("count saved views: %w", err)
	}
	return n, nil
}

// CountByOwner counts the owner's views in the tenant.
func (r *SavedViewRepository) CountByOwner(ctx context.Context, tenantID, ownerID shared.ID) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM saved_views WHERE tenant_id = $1 AND owner_id = $2`, tenantID.String(), ownerID.String())
}

// CountByGroup counts the views shared with a group of the tenant.
func (r *SavedViewRepository) CountByGroup(ctx context.Context, tenantID, groupID shared.ID) (int, error) {
	return r.count(ctx, `SELECT COUNT(*) FROM saved_views WHERE tenant_id = $1 AND group_id = $2`, tenantID.String(), groupID.String())
}

// IsActiveGroupMember reports whether the user belongs to an active group of the tenant.
func (r *SavedViewRepository) IsActiveGroupMember(ctx context.Context, tenantID, groupID, userID shared.ID) (bool, error) {
	n, err := r.count(ctx, `SELECT COUNT(*) FROM group_members gm JOIN groups g ON g.id = gm.group_id
		WHERE g.tenant_id = $1 AND g.id = $2 AND g.is_active = true AND gm.user_id = $3`,
		tenantID.String(), groupID.String(), userID.String())
	return n > 0, err
}

// ActiveGroupInTenant reports whether the group is an active group of the tenant.
func (r *SavedViewRepository) ActiveGroupInTenant(ctx context.Context, tenantID, groupID shared.ID) (bool, error) {
	n, err := r.count(ctx, `SELECT COUNT(*) FROM groups WHERE tenant_id = $1 AND id = $2 AND is_active = true`,
		tenantID.String(), groupID.String())
	return n > 0, err
}
