package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/shared"
)

// TenantModuleRepository handles per-tenant module configuration.
type TenantModuleRepository struct {
	db *DB
}

// NewTenantModuleRepository creates a new TenantModuleRepository.
func NewTenantModuleRepository(db *DB) *TenantModuleRepository {
	return &TenantModuleRepository{db: db}
}

// ListByTenant returns all module overrides for a tenant.
func (r *TenantModuleRepository) ListByTenant(ctx context.Context, tenantID shared.ID) ([]*module.TenantModuleOverride, error) {
	query := `
		SELECT tenant_id, module_id, is_enabled, enabled_at, disabled_at, updated_by, updated_at
		FROM tenant_modules
		WHERE tenant_id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenant modules: %w", err)
	}
	defer rows.Close()

	overrides := make([]*module.TenantModuleOverride, 0)
	for rows.Next() {
		var (
			tID        shared.ID
			moduleID   string
			isEnabled  bool
			enabledAt  *time.Time
			disabledAt *time.Time
			updatedBy  *shared.ID
			updatedAt  time.Time
		)

		if err := rows.Scan(&tID, &moduleID, &isEnabled, &enabledAt, &disabledAt, &updatedBy, &updatedAt); err != nil {
			return nil, fmt.Errorf("failed to scan tenant module: %w", err)
		}

		overrides = append(overrides, &module.TenantModuleOverride{
			TenantID:   tID,
			ModuleID:   moduleID,
			IsEnabled:  isEnabled,
			EnabledAt:  enabledAt,
			DisabledAt: disabledAt,
			UpdatedBy:  updatedBy,
			UpdatedAt:  updatedAt,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate tenant modules: %w", err)
	}

	return overrides, nil
}

// UpsertBatch creates or updates multiple module overrides for a tenant.
// Optimized: single multi-row INSERT instead of N individual queries.
func (r *TenantModuleRepository) UpsertBatch(ctx context.Context, tenantID shared.ID, updates []module.TenantModuleUpdate, updatedBy *shared.ID) error {
	if len(updates) == 0 {
		return nil
	}

	now := time.Now().UTC()

	// Build multi-row VALUES clause: 8 columns, 7 unique params (created_at and updated_at share same value)
	const paramsPerRow = 7
	args := make([]interface{}, 0, len(updates)*paramsPerRow)
	valueClauses := make([]string, 0, len(updates))

	for i, u := range updates {
		var enabledAt, disabledAt *time.Time
		if u.IsEnabled {
			enabledAt = &now
		} else {
			disabledAt = &now
		}

		base := i * paramsPerRow
		// $7 used for both created_at and updated_at (same timestamp)
		valueClauses = append(valueClauses, fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+7,
		))
		args = append(args, tenantID, u.ModuleID, u.IsEnabled, enabledAt, disabledAt, updatedBy, now)
	}

	query := `
		INSERT INTO tenant_modules (tenant_id, module_id, is_enabled, enabled_at, disabled_at, updated_by, created_at, updated_at)
		VALUES ` + strings.Join(valueClauses, ", ") + `
		ON CONFLICT (tenant_id, module_id) DO UPDATE SET
			is_enabled = EXCLUDED.is_enabled,
			enabled_at = EXCLUDED.enabled_at,
			disabled_at = EXCLUDED.disabled_at,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at
	`

	if _, err := r.db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("failed to upsert tenant modules: %w", err)
	}

	return nil
}

// DeleteByTenant removes all module overrides for a tenant (reset to defaults).
func (r *TenantModuleRepository) DeleteByTenant(ctx context.Context, tenantID shared.ID) error {
	query := `DELETE FROM tenant_modules WHERE tenant_id = $1`

	if _, err := r.db.ExecContext(ctx, query, tenantID); err != nil {
		return fmt.Errorf("failed to delete tenant modules: %w", err)
	}

	return nil
}
