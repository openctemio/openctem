package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// UserDashboardRepository persists per-user dashboards (RFC-021). Every query is
// scoped by (tenant_id, user_id) so a dashboard can never be read or mutated
// across users or tenants.
type UserDashboardRepository struct {
	db *DB
}

// NewUserDashboardRepository creates a new UserDashboardRepository.
func NewUserDashboardRepository(db *DB) *UserDashboardRepository {
	return &UserDashboardRepository{db: db}
}

// ListByUser returns all dashboards owned by (tenantID, userID).
func (r *UserDashboardRepository) ListByUser(ctx context.Context, tenantID, userID shared.ID) ([]*dashboard.Dashboard, error) {
	const q = `
		SELECT id, tenant_id, user_id, name, description, column_count, is_default, layout, created_at, updated_at
		  FROM user_dashboards
		 WHERE tenant_id = $1 AND user_id = $2
		 ORDER BY is_default DESC, created_at ASC
	`
	rows, err := r.db.QueryContext(ctx, q, tenantID.String(), userID.String())
	if err != nil {
		return nil, fmt.Errorf("list user dashboards: %w", err)
	}
	defer func() { _ = rows.Close() }()

	items := make([]*dashboard.Dashboard, 0)
	for rows.Next() {
		d, err := scanUserDashboard(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// GetByID returns one dashboard scoped to (tenantID, userID).
func (r *UserDashboardRepository) GetByID(ctx context.Context, tenantID, userID, id shared.ID) (*dashboard.Dashboard, error) {
	const q = `
		SELECT id, tenant_id, user_id, name, description, column_count, is_default, layout, created_at, updated_at
		  FROM user_dashboards
		 WHERE tenant_id = $1 AND user_id = $2 AND id = $3
	`
	return scanUserDashboard(r.db.QueryRowContext(ctx, q, tenantID.String(), userID.String(), id.String()))
}

// Create persists a new dashboard.
func (r *UserDashboardRepository) Create(ctx context.Context, d *dashboard.Dashboard) error {
	layout, err := json.Marshal(d.Widgets())
	if err != nil {
		return fmt.Errorf("marshal layout: %w", err)
	}
	const q = `
		INSERT INTO user_dashboards (id, tenant_id, user_id, name, description, column_count, is_default, layout, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err = r.db.ExecContext(ctx, q,
		d.ID().String(), d.TenantID().String(), d.UserID().String(),
		d.Name(), d.Description(), d.Columns(), d.IsDefault(), layout, d.CreatedAt(), d.UpdatedAt(),
	)
	if err != nil {
		return dashboardWriteError("create user dashboard", err)
	}
	return nil
}

// Update changes the name and layout of an existing dashboard. is_default is
// managed exclusively through SetDefault. Returns shared.ErrNotFound when the
// row does not belong to (tenant, user) or does not exist.
func (r *UserDashboardRepository) Update(ctx context.Context, d *dashboard.Dashboard) error {
	layout, err := json.Marshal(d.Widgets())
	if err != nil {
		return fmt.Errorf("marshal layout: %w", err)
	}
	const q = `
		UPDATE user_dashboards
		   SET name = $4, description = $5, column_count = $6, layout = $7, updated_at = $8
		 WHERE tenant_id = $1 AND user_id = $2 AND id = $3
	`
	res, err := r.db.ExecContext(ctx, q,
		d.TenantID().String(), d.UserID().String(), d.ID().String(),
		d.Name(), d.Description(), d.Columns(), layout, d.UpdatedAt(),
	)
	if err != nil {
		return dashboardWriteError("update user dashboard", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// Delete removes a dashboard scoped to (tenantID, userID).
func (r *UserDashboardRepository) Delete(ctx context.Context, tenantID, userID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM user_dashboards WHERE tenant_id = $1 AND user_id = $2 AND id = $3`,
		tenantID.String(), userID.String(), id.String(),
	)
	if err != nil {
		return fmt.Errorf("delete user dashboard: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// SetDefault clears every other default for the user, then marks id as the
// single default — atomically, in one transaction. Returns shared.ErrNotFound
// if id does not belong to (tenant, user).
func (r *UserDashboardRepository) SetDefault(ctx context.Context, tenantID, userID, id shared.ID) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`UPDATE user_dashboards
			    SET is_default = false, updated_at = now()
			  WHERE tenant_id = $1 AND user_id = $2 AND is_default AND id <> $3`,
			tenantID.String(), userID.String(), id.String(),
		); err != nil {
			return fmt.Errorf("clear defaults: %w", err)
		}
		res, err := tx.ExecContext(ctx,
			`UPDATE user_dashboards
			    SET is_default = true, updated_at = now()
			  WHERE tenant_id = $1 AND user_id = $2 AND id = $3`,
			tenantID.String(), userID.String(), id.String(),
		)
		if err != nil {
			return fmt.Errorf("set default: %w", err)
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return shared.ErrNotFound
		}
		return nil
	})
}

func scanUserDashboard(row interface{ Scan(dest ...any) error }) (*dashboard.Dashboard, error) {
	var (
		id, tenantID, userID string
		name                 string
		description          string
		columnCount          int
		isDefault            bool
		layoutJSON           []byte
		createdAt, updatedAt time.Time
	)
	err := row.Scan(&id, &tenantID, &userID, &name, &description, &columnCount, &isDefault, &layoutJSON, &createdAt, &updatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, err
	}

	var widgets []dashboard.Widget
	if len(layoutJSON) > 0 {
		_ = json.Unmarshal(layoutJSON, &widgets)
	}
	if widgets == nil {
		widgets = make([]dashboard.Widget, 0)
	}

	return dashboard.Reconstruct(
		shared.MustIDFromString(id),
		shared.MustIDFromString(tenantID),
		shared.MustIDFromString(userID),
		name, description, columnCount, isDefault, widgets,
		createdAt, updatedAt,
	), nil
}

// errDashboardNameTaken: the user already has a dashboard with this name
// (uq_user_dashboards_tenant_user_name).
var errDashboardNameTaken = fmt.Errorf("%w: you already have a dashboard with this name", shared.ErrConflict)

// dashboardWriteError maps a unique violation to a conflict the handler
// answers 409; any other error stays an internal one.
func dashboardWriteError(op string, err error) error {
	if !isUniqueViolation(err) {
		return fmt.Errorf("%s: %w", op, err)
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Constraint == "uq_user_dashboards_one_default" {
		return fmt.Errorf("%w: another dashboard is already the default", shared.ErrConflict)
	}
	return errDashboardNameTaken
}
