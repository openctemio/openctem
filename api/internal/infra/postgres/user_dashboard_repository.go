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

// UserDashboardRepository persists dashboards (docs/architecture/dashboards.md).
// Every query is tenant-bound. Personal queries also filter on user_id and
// kind = 'personal'; organization queries filter on kind = 'organization', so
// a personal dashboard is never reachable through an organization path and
// the other way round.
type UserDashboardRepository struct {
	db *DB
}

// NewUserDashboardRepository creates a new UserDashboardRepository.
func NewUserDashboardRepository(db *DB) *UserDashboardRepository {
	return &UserDashboardRepository{db: db}
}

const dashboardColumns = `id, tenant_id, user_id, kind, name, description, column_count, is_default, is_org_default,
	position, refresh_schedule, refresh_daily_minute, next_refresh_at, paused_at, origin, layout, created_at, updated_at`

// ListByUser returns the personal dashboards owned by (tenantID, userID).
func (r *UserDashboardRepository) ListByUser(ctx context.Context, tenantID, userID shared.ID) ([]*dashboard.Dashboard, error) {
	q := `SELECT ` + dashboardColumns + `
		  FROM user_dashboards
		 WHERE tenant_id = $1 AND user_id = $2 AND kind = 'personal'
		 ORDER BY is_default DESC, created_at ASC`
	return r.list(ctx, q, tenantID.String(), userID.String())
}

// GetByID returns one personal dashboard scoped to (tenantID, userID).
func (r *UserDashboardRepository) GetByID(ctx context.Context, tenantID, userID, id shared.ID) (*dashboard.Dashboard, error) {
	q := `SELECT ` + dashboardColumns + `
		  FROM user_dashboards
		 WHERE tenant_id = $1 AND user_id = $2 AND id = $3 AND kind = 'personal'`
	return scanUserDashboard(r.db.QueryRowContext(ctx, q, tenantID.String(), userID.String(), id.String()))
}

// CountByUser counts the personal dashboards of (tenantID, userID).
func (r *UserDashboardRepository) CountByUser(ctx context.Context, tenantID, userID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx,
		`SELECT count(*) FROM user_dashboards WHERE tenant_id = $1 AND user_id = $2 AND kind = 'personal'`,
		tenantID.String(), userID.String()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count personal dashboards: %w", err)
	}
	return n, nil
}

// Create persists a new dashboard. An organization dashboard goes to the end
// of the organization's order.
func (r *UserDashboardRepository) Create(ctx context.Context, d *dashboard.Dashboard) error {
	layout, err := json.Marshal(d.Widgets())
	if err != nil {
		return fmt.Errorf("marshal layout: %w", err)
	}
	const q = `
		INSERT INTO user_dashboards (id, tenant_id, user_id, kind, name, description, column_count, is_default,
		                             layout, origin, position, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
		        CASE WHEN $4 = 'organization'
		             THEN COALESCE((SELECT max(position) + 1 FROM user_dashboards
		                             WHERE tenant_id = $2 AND kind = 'organization'), 0)
		             ELSE 0 END,
		        $11, $12)
	`
	_, err = r.db.ExecContext(ctx, q,
		d.ID().String(), d.TenantID().String(), nullableOwner(d), string(d.Kind()),
		d.Name(), d.Description(), d.Columns(), d.IsDefault(), layout, string(d.Origin()),
		d.CreatedAt(), d.UpdatedAt(),
	)
	if err != nil {
		return dashboardWriteError("create dashboard", d.Kind(), err)
	}
	return nil
}

// Update changes the name, description, columns and layout of an existing
// dashboard of either kind. Defaults, order, audience and schedule have their
// own methods. Returns shared.ErrNotFound when the row does not exist for
// this tenant (and owner, for a personal dashboard).
func (r *UserDashboardRepository) Update(ctx context.Context, d *dashboard.Dashboard) error {
	layout, err := json.Marshal(d.Widgets())
	if err != nil {
		return fmt.Errorf("marshal layout: %w", err)
	}
	var res sql.Result
	if d.Kind() == dashboard.KindOrganization {
		res, err = r.db.ExecContext(ctx, `
			UPDATE user_dashboards
			   SET name = $3, description = $4, column_count = $5, layout = $6, updated_at = $7
			 WHERE tenant_id = $1 AND id = $2 AND kind = 'organization'`,
			d.TenantID().String(), d.ID().String(),
			d.Name(), d.Description(), d.Columns(), layout, d.UpdatedAt())
	} else {
		res, err = r.db.ExecContext(ctx, `
			UPDATE user_dashboards
			   SET name = $4, description = $5, column_count = $6, layout = $7, updated_at = $8
			 WHERE tenant_id = $1 AND user_id = $2 AND id = $3 AND kind = 'personal'`,
			d.TenantID().String(), d.UserID().String(), d.ID().String(),
			d.Name(), d.Description(), d.Columns(), layout, d.UpdatedAt())
	}
	if err != nil {
		return dashboardWriteError("update dashboard", d.Kind(), err)
	}
	return dashboardOneRow(res)
}

// Delete removes a personal dashboard scoped to (tenantID, userID).
func (r *UserDashboardRepository) Delete(ctx context.Context, tenantID, userID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM user_dashboards WHERE tenant_id = $1 AND user_id = $2 AND id = $3 AND kind = 'personal'`,
		tenantID.String(), userID.String(), id.String(),
	)
	if err != nil {
		return fmt.Errorf("delete user dashboard: %w", err)
	}
	return dashboardOneRow(res)
}

// SetDefault clears every other default for the user, then marks id as the
// single default, atomically. Returns shared.ErrNotFound if id is not one of
// the user's personal dashboards.
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
			  WHERE tenant_id = $1 AND user_id = $2 AND id = $3 AND kind = 'personal'`,
			tenantID.String(), userID.String(), id.String(),
		)
		if err != nil {
			return fmt.Errorf("set default: %w", err)
		}
		return dashboardOneRow(res)
	})
}

// SetSchedule writes a dashboard's refresh schedule. userID zero targets an
// organization dashboard; otherwise the owner's personal dashboard.
func (r *UserDashboardRepository) SetSchedule(ctx context.Context, tenantID, userID, id shared.ID, s dashboard.Schedule, next *time.Time) error {
	var interval any
	if s.Interval != dashboard.IntervalDefault {
		interval = string(s.Interval)
	}
	var daily any
	if s.DailyMinute != nil {
		daily = *s.DailyMinute
	}
	var (
		res sql.Result
		err error
	)
	if userID.IsZero() {
		res, err = r.db.ExecContext(ctx, `
			UPDATE user_dashboards
			   SET refresh_schedule = $3, refresh_daily_minute = $4, next_refresh_at = $5, paused_at = NULL, updated_at = now()
			 WHERE tenant_id = $1 AND id = $2 AND kind = 'organization'`,
			tenantID.String(), id.String(), interval, daily, next)
	} else {
		res, err = r.db.ExecContext(ctx, `
			UPDATE user_dashboards
			   SET refresh_schedule = $4, refresh_daily_minute = $5, next_refresh_at = $6, paused_at = NULL, updated_at = now()
			 WHERE tenant_id = $1 AND user_id = $2 AND id = $3 AND kind = 'personal'`,
			tenantID.String(), userID.String(), id.String(), interval, daily, next)
	}
	if err != nil {
		return fmt.Errorf("set dashboard schedule: %w", err)
	}
	return dashboardOneRow(res)
}

// ListOrg returns every organization dashboard of the tenant in order.
func (r *UserDashboardRepository) ListOrg(ctx context.Context, tenantID shared.ID) ([]*dashboard.Dashboard, error) {
	q := `SELECT ` + dashboardColumns + `
		  FROM user_dashboards
		 WHERE tenant_id = $1 AND kind = 'organization'
		 ORDER BY position ASC, created_at ASC`
	return r.list(ctx, q, tenantID.String())
}

// audienceAdmits is true when organization dashboard d (alias) has no
// audience, or one entry names a role the user holds (directly or through an
// active team) or an active team the user belongs to. $1 = tenant, $2 = user.
const audienceAdmits = `(
	NOT EXISTS (SELECT 1 FROM dashboard_audience a WHERE a.tenant_id = $1 AND a.dashboard_id = d.id)
	OR EXISTS (
		SELECT 1 FROM dashboard_audience a
		 WHERE a.tenant_id = $1 AND a.dashboard_id = d.id
		   AND ((a.principal_type = 'role' AND a.principal_id IN (
		            SELECT g.role_id FROM v_user_role_grants g WHERE g.tenant_id = $1 AND g.user_id = $2))
		     OR (a.principal_type = 'group' AND a.principal_id IN (
		            SELECT gm.group_id FROM group_members gm
		              JOIN groups gr ON gr.id = gm.group_id AND gr.tenant_id = $1 AND gr.is_active
		             WHERE gm.user_id = $2 AND (gm.expires_at IS NULL OR gm.expires_at > now()))))))`

// ListOrgVisible returns the organization dashboards whose audience admits
// the user, in order.
func (r *UserDashboardRepository) ListOrgVisible(ctx context.Context, tenantID, userID shared.ID) ([]*dashboard.Dashboard, error) {
	q := `SELECT ` + dashboardColumns + `
		  FROM user_dashboards d
		 WHERE d.tenant_id = $1 AND d.kind = 'organization' AND ` + audienceAdmits + `
		 ORDER BY d.position ASC, d.created_at ASC`
	return r.list(ctx, q, tenantID.String(), userID.String())
}

// GetOrg returns one organization dashboard of the tenant.
func (r *UserDashboardRepository) GetOrg(ctx context.Context, tenantID, id shared.ID) (*dashboard.Dashboard, error) {
	q := `SELECT ` + dashboardColumns + `
		  FROM user_dashboards
		 WHERE tenant_id = $1 AND id = $2 AND kind = 'organization'`
	return scanUserDashboard(r.db.QueryRowContext(ctx, q, tenantID.String(), id.String()))
}

// InAudience reports whether the audience of organization dashboard id admits
// the user (true when it has none).
func (r *UserDashboardRepository) InAudience(ctx context.Context, tenantID, id, userID shared.ID) (bool, error) {
	var ok bool
	err := r.db.QueryRowContext(ctx, `
		SELECT `+audienceAdmits+`
		  FROM user_dashboards d
		 WHERE d.tenant_id = $1 AND d.id = $3 AND d.kind = 'organization'`,
		tenantID.String(), userID.String(), id.String()).Scan(&ok)
	if errors.Is(err, sql.ErrNoRows) {
		return false, shared.ErrNotFound
	}
	if err != nil {
		return false, fmt.Errorf("check dashboard audience: %w", err)
	}
	return ok, nil
}

// CountOrg counts the tenant's organization dashboards.
func (r *UserDashboardRepository) CountOrg(ctx context.Context, tenantID shared.ID) (int, error) {
	var n int
	if err := r.db.QueryRowContext(ctx,
		`SELECT count(*) FROM user_dashboards WHERE tenant_id = $1 AND kind = 'organization'`,
		tenantID.String()).Scan(&n); err != nil {
		return 0, fmt.Errorf("count organization dashboards: %w", err)
	}
	return n, nil
}

// DeleteOrg removes an organization dashboard (its audience cascades).
func (r *UserDashboardRepository) DeleteOrg(ctx context.Context, tenantID, id shared.ID) error {
	res, err := r.db.ExecContext(ctx,
		`DELETE FROM user_dashboards WHERE tenant_id = $1 AND id = $2 AND kind = 'organization'`,
		tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("delete organization dashboard: %w", err)
	}
	return dashboardOneRow(res)
}

// SetOrgDefault makes id the single organization default, atomically.
func (r *UserDashboardRepository) SetOrgDefault(ctx context.Context, tenantID, id shared.ID) error {
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			UPDATE user_dashboards SET is_org_default = false, updated_at = now()
			 WHERE tenant_id = $1 AND is_org_default AND id <> $2`,
			tenantID.String(), id.String()); err != nil {
			return fmt.Errorf("clear organization default: %w", err)
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE user_dashboards SET is_org_default = true, updated_at = now()
			 WHERE tenant_id = $1 AND id = $2 AND kind = 'organization'`,
			tenantID.String(), id.String())
		if err != nil {
			return fmt.Errorf("set organization default: %w", err)
		}
		return dashboardOneRow(res)
	})
}

// Reorder sets the organization order. ids must name every organization
// dashboard of the tenant exactly once, so a stale list (one created or
// deleted meanwhile) is refused rather than half applied.
func (r *UserDashboardRepository) Reorder(ctx context.Context, tenantID shared.ID, ids []shared.ID) error {
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		var total, matched int
		if err := tx.QueryRowContext(ctx, `
			SELECT count(*), count(*) FILTER (WHERE id::text = ANY($2))
			  FROM user_dashboards WHERE tenant_id = $1 AND kind = 'organization'`,
			tenantID.String(), pq.Array(strs)).Scan(&total, &matched); err != nil {
			return fmt.Errorf("check organization order: %w", err)
		}
		if total != len(ids) || matched != len(ids) {
			return fmt.Errorf("%w: the order must list every organization dashboard exactly once", shared.ErrConflict)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE user_dashboards d SET position = o.ord - 1, updated_at = now()
			  FROM unnest($2::uuid[]) WITH ORDINALITY AS o(id, ord)
			 WHERE d.tenant_id = $1 AND d.kind = 'organization' AND d.id = o.id`,
			tenantID.String(), pq.Array(strs)); err != nil {
			return fmt.Errorf("reorder organization dashboards: %w", err)
		}
		return nil
	})
}

// Audience returns the audience of an organization dashboard with the names
// of its roles and teams (empty when one no longer exists).
func (r *UserDashboardRepository) Audience(ctx context.Context, tenantID, id shared.ID) ([]dashboard.AudienceEntry, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT a.principal_type, a.principal_id,
		       COALESCE(CASE a.principal_type
		                  WHEN 'role' THEN (SELECT ro.name FROM roles ro
		                                     WHERE ro.id = a.principal_id AND (ro.tenant_id = $1 OR ro.tenant_id IS NULL))
		                  ELSE (SELECT g.name FROM groups g WHERE g.id = a.principal_id AND g.tenant_id = $1)
		                END, '')
		  FROM dashboard_audience a
		 WHERE a.tenant_id = $1 AND a.dashboard_id = $2
		 ORDER BY a.principal_type, a.created_at`,
		tenantID.String(), id.String())
	if err != nil {
		return nil, fmt.Errorf("list dashboard audience: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := make([]dashboard.AudienceEntry, 0)
	for rows.Next() {
		var typ, pid, name string
		if err := rows.Scan(&typ, &pid, &name); err != nil {
			return nil, err
		}
		out = append(out, dashboard.AudienceEntry{Type: dashboard.PrincipalType(typ), ID: shared.MustIDFromString(pid), Name: name})
	}
	return out, rows.Err()
}

// ReplaceAudience replaces the audience of an organization dashboard. Every
// role must be a system role or one of the tenant's; every team one of the
// tenant's. Anything else is refused as not found, so an id of another
// tenant is never stored.
func (r *UserDashboardRepository) ReplaceAudience(ctx context.Context, tenantID, id, actorID shared.ID, entries []dashboard.AudienceEntry) error {
	var roles, groups []string
	for _, e := range entries {
		if e.Type == dashboard.PrincipalRole {
			roles = append(roles, e.ID.String())
		} else {
			groups = append(groups, e.ID.String())
		}
	}
	var actor any
	if !actorID.IsZero() {
		actor = actorID.String()
	}
	return r.db.Transaction(ctx, func(tx *sql.Tx) error {
		var locked string
		err := tx.QueryRowContext(ctx, `
			SELECT id FROM user_dashboards WHERE tenant_id = $1 AND id = $2 AND kind = 'organization' FOR UPDATE`,
			tenantID.String(), id.String()).Scan(&locked)
		if errors.Is(err, sql.ErrNoRows) {
			return shared.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("lock organization dashboard: %w", err)
		}
		var okRoles, okGroups int
		if err := tx.QueryRowContext(ctx, `
			SELECT (SELECT count(*) FROM roles WHERE id::text = ANY($2) AND (tenant_id = $1 OR tenant_id IS NULL)),
			       (SELECT count(*) FROM groups WHERE id::text = ANY($3) AND tenant_id = $1)`,
			tenantID.String(), pq.Array(roles), pq.Array(groups)).Scan(&okRoles, &okGroups); err != nil {
			return fmt.Errorf("check audience principals: %w", err)
		}
		if okRoles != len(roles) || okGroups != len(groups) {
			return fmt.Errorf("%w: a role or team of the audience does not exist in this organization", shared.ErrValidation)
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM dashboard_audience WHERE tenant_id = $1 AND dashboard_id = $2`,
			tenantID.String(), id.String()); err != nil {
			return fmt.Errorf("clear dashboard audience: %w", err)
		}
		for _, e := range entries {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO dashboard_audience (tenant_id, dashboard_id, principal_type, principal_id, created_by)
				VALUES ($1, $2, $3, $4, $5)`,
				tenantID.String(), id.String(), string(e.Type), e.ID.String(), actor); err != nil {
				return fmt.Errorf("add dashboard audience: %w", err)
			}
		}
		_, err = tx.ExecContext(ctx,
			`UPDATE user_dashboards SET updated_at = now() WHERE tenant_id = $1 AND id = $2 AND kind = 'organization'`,
			tenantID.String(), id.String())
		return err
	})
}

func (r *UserDashboardRepository) list(ctx context.Context, q string, args ...any) ([]*dashboard.Dashboard, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list dashboards: %w", err)
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

func scanUserDashboard(row interface{ Scan(dest ...any) error }) (*dashboard.Dashboard, error) {
	var (
		id, tenantID         string
		userID               sql.NullString
		kind, origin         string
		name, description    string
		columnCount          int
		isDefault, isOrgDef  bool
		position             int
		schedule             sql.NullString
		dailyMinute          sql.NullInt32
		nextAt, pausedAt     sql.NullTime
		layoutJSON           []byte
		createdAt, updatedAt time.Time
	)
	err := row.Scan(&id, &tenantID, &userID, &kind, &name, &description, &columnCount, &isDefault, &isOrgDef,
		&position, &schedule, &dailyMinute, &nextAt, &pausedAt, &origin, &layoutJSON, &createdAt, &updatedAt)
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

	s := dashboard.Schedule{Interval: dashboard.Interval(schedule.String)}
	if dailyMinute.Valid {
		m := int(dailyMinute.Int32)
		s.DailyMinute = &m
	}
	if nextAt.Valid {
		t := nextAt.Time
		s.NextRefreshAt = &t
	}
	if pausedAt.Valid {
		t := pausedAt.Time
		s.PausedAt = &t
	}
	var owner shared.ID
	if userID.Valid {
		owner = shared.MustIDFromString(userID.String)
	}
	return dashboard.Reconstruct(dashboard.Stored{
		ID:           shared.MustIDFromString(id),
		TenantID:     shared.MustIDFromString(tenantID),
		UserID:       owner,
		Kind:         dashboard.Kind(kind),
		Name:         name,
		Description:  description,
		Columns:      columnCount,
		IsDefault:    isDefault,
		IsOrgDefault: isOrgDef,
		Position:     position,
		Schedule:     s,
		Origin:       dashboard.Origin(origin),
		Widgets:      widgets,
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
	}), nil
}

func nullableOwner(d *dashboard.Dashboard) any {
	if d.Kind() == dashboard.KindOrganization || d.UserID().IsZero() {
		return nil
	}
	return d.UserID().String()
}

func dashboardOneRow(res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// dashboardWriteError maps a unique violation to a conflict the handler
// answers 409; any other error stays an internal one.
func dashboardWriteError(op string, kind dashboard.Kind, err error) error {
	if !isUniqueViolation(err) {
		return fmt.Errorf("%s: %w", op, err)
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Constraint {
		case "uq_user_dashboards_one_default", "uq_user_dashboards_one_org_default":
			return fmt.Errorf("%w: another dashboard is already the default", shared.ErrConflict)
		}
	}
	if kind == dashboard.KindOrganization {
		return fmt.Errorf("%w: the organization already has a dashboard with this name", shared.ErrConflict)
	}
	return fmt.Errorf("%w: you already have a dashboard with this name", shared.ErrConflict)
}
