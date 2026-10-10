package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Module entitlements (RFC-064): the plan to module map in platform_settings
// and the per-organization grants in tenant_module_grants.

var _ plan.ModuleRepository = (*PlanRepository)(nil)

// GetPlanModules returns the stored plan to module map and its version.
func (r *PlanRepository) GetPlanModules(ctx context.Context) (plan.PlanModules, int, error) {
	var (
		raw     []byte
		version int
	)
	err := r.db.QueryRowContext(ctx, `SELECT value, version FROM platform_settings WHERE key = $1`,
		plan.ModulesSettingKey).Scan(&raw, &version)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, 0, shared.ErrNotFound
		}
		return nil, 0, fmt.Errorf("get plan modules: %w", err)
	}
	m, err := plan.DecodePlanModules(raw)
	if err != nil {
		return nil, 0, err
	}
	return m, version, nil
}

// SavePlanModules stores the map under optimistic concurrency.
func (r *PlanRepository) SavePlanModules(ctx context.Context, m plan.PlanModules, expectedVersion int, by shared.ID, at time.Time) (int, error) {
	raw, err := m.Encode()
	if err != nil {
		return 0, err
	}
	var version int
	if expectedVersion == 0 {
		err = r.db.QueryRowContext(ctx, `
			INSERT INTO platform_settings (key, value, version, source, updated_by, updated_at)
			VALUES ($1, $2, 1, 'console', $3, $4)
			ON CONFLICT (key) DO NOTHING
			RETURNING version`, plan.ModulesSettingKey, raw, by.String(), at).Scan(&version)
	} else {
		err = r.db.QueryRowContext(ctx, `
			UPDATE platform_settings
			   SET value = $2, version = version + 1, source = 'console', updated_by = $3, updated_at = $4
			 WHERE key = $1 AND version = $5
			RETURNING version`, plan.ModulesSettingKey, raw, by.String(), at, expectedVersion).Scan(&version)
	}
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, fmt.Errorf("%w: the plan modules were changed by someone else; reload and try again", shared.ErrConflict)
		}
		return 0, fmt.Errorf("save plan modules: %w", err)
	}
	return version, nil
}

// ListModuleGrants lists one organization's grants and denies.
func (r *PlanRepository) ListModuleGrants(ctx context.Context, tenantID shared.ID) ([]plan.ModuleGrant, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT module_id, kind, reason, expires_at, set_by, set_at
		  FROM tenant_module_grants WHERE tenant_id = $1 ORDER BY module_id`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list module grants: %w", err)
	}
	defer rows.Close()
	out := []plan.ModuleGrant{}
	for rows.Next() {
		var (
			g       plan.ModuleGrant
			kind    string
			expires sql.NullTime
			setBy   sql.NullString
		)
		if err := rows.Scan(&g.ModuleID, &kind, &g.Reason, &expires, &setBy, &g.SetAt); err != nil {
			return nil, fmt.Errorf("scan module grant: %w", err)
		}
		g.TenantID, g.Kind, g.ExpiresAt = tenantID, plan.GrantKind(kind), nullTimeValue(expires)
		if setBy.Valid {
			if id, perr := shared.IDFromString(setBy.String); perr == nil {
				g.SetBy = &id
			}
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// SetModuleGrant writes one grant or deny (replacing the module's previous one).
func (r *PlanRepository) SetModuleGrant(ctx context.Context, g plan.ModuleGrant) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO tenant_module_grants (tenant_id, module_id, kind, reason, expires_at, set_by, set_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, module_id) DO UPDATE SET
		  kind = EXCLUDED.kind, reason = EXCLUDED.reason, expires_at = EXCLUDED.expires_at,
		  set_by = EXCLUDED.set_by, set_at = EXCLUDED.set_at`,
		g.TenantID.String(), g.ModuleID, string(g.Kind), g.Reason, nullTimePtr(g.ExpiresAt), nullID(g.SetBy), g.SetAt)
	if err != nil {
		return fmt.Errorf("set module grant: %w", err)
	}
	return nil
}

// DeleteModuleGrant removes one organization's grant or deny of a module.
func (r *PlanRepository) DeleteModuleGrant(ctx context.Context, tenantID shared.ID, moduleID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM tenant_module_grants WHERE tenant_id = $1 AND module_id = $2`,
		tenantID.String(), moduleID)
	if err != nil {
		return fmt.Errorf("delete module grant: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return shared.ErrNotFound
	}
	return nil
}

// ListModuleGrace returns the organization's read-only grace per module.
func (r *PlanRepository) ListModuleGrace(ctx context.Context, tenantID shared.ID) (map[string]time.Time, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT module_id, read_only_until FROM tenant_module_grace WHERE tenant_id = $1`, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list module grace: %w", err)
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var (
			id    string
			until time.Time
		)
		if err := rows.Scan(&id, &until); err != nil {
			return nil, fmt.Errorf("scan module grace: %w", err)
		}
		out[id] = until
	}
	return out, rows.Err()
}

// StartModuleGrace starts grace for modules the organization just lost; a
// grace already running is kept as it is.
func (r *PlanRepository) StartModuleGrace(ctx context.Context, tenantID shared.ID, moduleIDs []string, until time.Time) error {
	if len(moduleIDs) == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO tenant_module_grace (tenant_id, module_id, read_only_until)
		SELECT $1, m.id, $3 FROM modules m WHERE m.id = ANY($2)
		ON CONFLICT (tenant_id, module_id) DO NOTHING`,
		tenantID.String(), pq.Array(moduleIDs), until)
	if err != nil {
		return fmt.Errorf("start module grace: %w", err)
	}
	return nil
}

// EndModuleGrace ends the grace of modules the organization has again.
func (r *PlanRepository) EndModuleGrace(ctx context.Context, tenantID shared.ID, moduleIDs []string) error {
	if len(moduleIDs) == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `DELETE FROM tenant_module_grace WHERE tenant_id = $1 AND module_id = ANY($2)`,
		tenantID.String(), pq.Array(moduleIDs))
	if err != nil {
		return fmt.Errorf("end module grace: %w", err)
	}
	return nil
}

// planTenantsSQL selects the organizations on a plan; Enterprise includes
// organizations with no plan stored (created before plans).
const planTenantsSQL = `
	SELECT t.id FROM tenants t
	  LEFT JOIN tenant_plans tp ON tp.tenant_id = t.id
	 WHERE COALESCE(tp.plan, 'enterprise') = $1`

// StartPlanModuleGrace starts grace for every organization on the plan that
// has no active grant of the module.
func (r *PlanRepository) StartPlanModuleGrace(ctx context.Context, p plan.Plan, moduleIDs []string, until time.Time) error {
	if len(moduleIDs) == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO tenant_module_grace (tenant_id, module_id, read_only_until)
		SELECT pt.id, m.id, $3
		  FROM (`+planTenantsSQL+`) pt
		  JOIN modules m ON m.id = ANY($2)
		 WHERE NOT EXISTS (
		       SELECT 1 FROM tenant_module_grants g
		        WHERE g.tenant_id = pt.id AND g.module_id = m.id AND g.kind = 'grant'
		          AND (g.expires_at IS NULL OR g.expires_at > now()))
		ON CONFLICT (tenant_id, module_id) DO NOTHING`,
		string(p), pq.Array(moduleIDs), until)
	if err != nil {
		return fmt.Errorf("start plan module grace: %w", err)
	}
	return nil
}

// EndPlanModuleGrace ends the grace of the modules for every organization on
// the plan.
func (r *PlanRepository) EndPlanModuleGrace(ctx context.Context, p plan.Plan, moduleIDs []string) error {
	if len(moduleIDs) == 0 {
		return nil
	}
	_, err := r.db.ExecContext(ctx, `
		DELETE FROM tenant_module_grace
		 WHERE module_id = ANY($2) AND tenant_id IN (`+planTenantsSQL+`)`,
		string(p), pq.Array(moduleIDs))
	if err != nil {
		return fmt.Errorf("end plan module grace: %w", err)
	}
	return nil
}
