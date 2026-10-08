package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// PlanRepository stores plan defaults (platform_settings 'plan_limits'), each
// organization's plan and its overrides (migration 001325), and counts usage.
// Every per-organization query is scoped by tenant_id.
type PlanRepository struct {
	db *DB
}

// NewPlanRepository creates the repository.
func NewPlanRepository(db *DB) *PlanRepository { return &PlanRepository{db: db} }

var _ plan.Repository = (*PlanRepository)(nil)

// GetDefaults returns the stored defaults, or shared.ErrNotFound.
func (r *PlanRepository) GetDefaults(ctx context.Context) (plan.Defaults, int, error) {
	var (
		raw     []byte
		version int
	)
	err := r.db.QueryRowContext(ctx, `SELECT value, version FROM platform_settings WHERE key = $1`, plan.SettingKey).Scan(&raw, &version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, shared.ErrNotFound
		}
		return nil, 0, fmt.Errorf("get plan defaults: %w", err)
	}
	d, err := plan.DecodeDefaults(raw)
	if err != nil {
		return nil, 0, err
	}
	return d, version, nil
}

// SaveDefaults stores the defaults when the stored version is expected.
func (r *PlanRepository) SaveDefaults(ctx context.Context, d plan.Defaults, expectedVersion int, by shared.ID, at time.Time) (int, error) {
	raw, err := d.Encode()
	if err != nil {
		return 0, err
	}
	var version int
	if expectedVersion == 0 {
		err = r.db.QueryRowContext(ctx, `
			INSERT INTO platform_settings (key, value, version, source, updated_by, updated_at)
			VALUES ($1, $2, 1, 'console', $3, $4)
			ON CONFLICT (key) DO NOTHING
			RETURNING version`, plan.SettingKey, raw, by.String(), at).Scan(&version)
	} else {
		err = r.db.QueryRowContext(ctx, `
			UPDATE platform_settings
			   SET value = $2, version = version + 1, source = 'console', updated_by = $3, updated_at = $4
			 WHERE key = $1 AND version = $5
			RETURNING version`, plan.SettingKey, raw, by.String(), at, expectedVersion).Scan(&version)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, fmt.Errorf("%w: the plan defaults were changed by someone else; reload and try again", shared.ErrConflict)
		}
		return 0, fmt.Errorf("save plan defaults: %w", err)
	}
	return version, nil
}

// TenantPlan returns the organization's plan; ok=false when none is stored.
func (r *PlanRepository) TenantPlan(ctx context.Context, tenantID shared.ID) (plan.Plan, bool, error) {
	var p string
	err := r.db.QueryRowContext(ctx, `SELECT plan FROM tenant_plans WHERE tenant_id = $1`, tenantID.String()).Scan(&p)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("get tenant plan: %w", err)
	}
	return plan.Plan(p), true, nil
}

// SetTenantPlan stores the organization's plan.
func (r *PlanRepository) SetTenantPlan(ctx context.Context, tenantID shared.ID, p plan.Plan, by *shared.ID, at time.Time) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO tenant_plans (tenant_id, plan, updated_by, updated_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id) DO UPDATE SET plan = EXCLUDED.plan, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
		tenantID.String(), string(p), nullID(by), at)
	if err != nil {
		return fmt.Errorf("set tenant plan: %w", err)
	}
	return nil
}

// ListOverrides returns the organization's overrides.
func (r *PlanRepository) ListOverrides(ctx context.Context, tenantID shared.ID) ([]plan.Override, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT limit_key, value, reason, expires_at, set_by, set_at
		  FROM tenant_plan_overrides WHERE tenant_id = $1 ORDER BY limit_key`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list plan overrides: %w", err)
	}
	defer rows.Close()
	out := []plan.Override{}
	for rows.Next() {
		var (
			o       plan.Override
			key     string
			expires sql.NullTime
			setBy   sql.NullString
		)
		if err := rows.Scan(&key, &o.Value, &o.Reason, &expires, &setBy, &o.SetAt); err != nil {
			return nil, fmt.Errorf("scan plan override: %w", err)
		}
		o.TenantID, o.Key, o.ExpiresAt = tenantID, plan.Key(key), nullTimeValue(expires)
		if setBy.Valid {
			if id, perr := shared.IDFromString(setBy.String); perr == nil {
				o.SetBy = &id
			}
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// SetOverride creates or replaces one override.
func (r *PlanRepository) SetOverride(ctx context.Context, o plan.Override) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO tenant_plan_overrides (tenant_id, limit_key, value, reason, expires_at, set_by, set_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, limit_key) DO UPDATE SET
		  value = EXCLUDED.value, reason = EXCLUDED.reason, expires_at = EXCLUDED.expires_at,
		  set_by = EXCLUDED.set_by, set_at = EXCLUDED.set_at`,
		o.TenantID.String(), string(o.Key), o.Value, o.Reason, nullTimePtr(o.ExpiresAt), nullID(o.SetBy), o.SetAt)
	if err != nil {
		return fmt.Errorf("set plan override: %w", err)
	}
	return nil
}

// DeleteOverride removes one override.
func (r *PlanRepository) DeleteOverride(ctx context.Context, tenantID shared.ID, key plan.Key) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM tenant_plan_overrides WHERE tenant_id = $1 AND limit_key = $2`, tenantID.String(), string(key))
	if err != nil {
		return fmt.Errorf("delete plan override: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// Usage counts what the organization uses, one query, every count scoped
// by tenant_id. A seat is every member who is not offboarded: a suspended
// member, or a sign-up awaiting approval, still holds one.
func (r *PlanRepository) Usage(ctx context.Context, tenantID shared.ID) (map[plan.Key]int, error) {
	var seats, assets, sensors, keys, trusts, invites int
	err := r.db.QueryRowContext(ctx, `
		SELECT
		  (SELECT count(*) FROM tenant_members WHERE tenant_id = $1 AND status <> 'offboarded'),
		  (SELECT count(*) FROM assets WHERE tenant_id = $1 AND deleted_at IS NULL AND status <> 'archived'),
		  (SELECT count(*) FROM sensors WHERE tenant_id = $1 AND is_platform_sensor = false AND status <> 'revoked'),
		  (SELECT count(*) FROM api_keys WHERE tenant_id = $1 AND status = 'active'),
		  (SELECT count(*) FROM ci_trust_configs WHERE tenant_id = $1),
		  (SELECT count(*) FROM tenant_invitations WHERE tenant_id = $1 AND created_at > now() - interval '24 hours')`,
		tenantID.String()).Scan(&seats, &assets, &sensors, &keys, &trusts, &invites)
	if err != nil {
		return nil, fmt.Errorf("count plan usage: %w", err)
	}
	return map[plan.Key]int{
		plan.Seats: seats, plan.Assets: assets, plan.Sensors: sensors,
		plan.APIKeys: keys, plan.CITrusts: trusts, plan.InvitesPerDay: invites,
	}, nil
}

// CountOwnedFreeTenants counts the Free organizations the user owns.
func (r *PlanRepository) CountOwnedFreeTenants(ctx context.Context, userID shared.ID) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `
		SELECT count(*) FROM tenant_members m
		  JOIN tenant_plans p ON p.tenant_id = m.tenant_id
		 WHERE m.user_id = $1 AND m.role = 'owner' AND m.status = 'active' AND p.plan = 'free'`,
		userID.String()).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count owned free organizations: %w", err)
	}
	return n, nil
}
