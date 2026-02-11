package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/openctemio/api/pkg/domain/module"
)

// ModuleRepository handles database operations for modules.
type ModuleRepository struct {
	db *DB
}

// NewModuleRepository creates a new ModuleRepository.
func NewModuleRepository(db *DB) *ModuleRepository {
	return &ModuleRepository{db: db}
}

// ListAllModules returns all modules from the database.
func (r *ModuleRepository) ListAllModules(ctx context.Context) ([]*module.Module, error) {
	return r.listModules(ctx, "1=1")
}

// ListActiveModules returns all active modules.
func (r *ModuleRepository) ListActiveModules(ctx context.Context) ([]*module.Module, error) {
	return r.listModules(ctx, "is_active = TRUE")
}

// GetModuleByID retrieves a module by its ID.
func (r *ModuleRepository) GetModuleByID(ctx context.Context, id string) (*module.Module, error) {
	query := `
		SELECT id, slug, name, description, icon, category, display_order, is_active, release_status, parent_module_id
		FROM modules
		WHERE id = $1
	`

	var (
		moduleID       string
		slug           string
		name           string
		description    sql.NullString
		icon           sql.NullString
		category       string
		displayOrder   int
		isActive       bool
		releaseStatus  string
		parentModuleID sql.NullString
	)

	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&moduleID, &slug, &name, &description, &icon,
		&category, &displayOrder, &isActive, &releaseStatus, &parentModuleID,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("module not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get module: %w", err)
	}

	var parentID *string
	if parentModuleID.Valid {
		parentID = &parentModuleID.String
	}

	return module.ReconstructModule(
		moduleID,
		slug,
		name,
		description.String,
		icon.String,
		category,
		displayOrder,
		isActive,
		releaseStatus,
		parentID,
		nil, // eventTypes
	), nil
}

// listModules is a helper to list modules with a condition.
func (r *ModuleRepository) listModules(ctx context.Context, condition string) ([]*module.Module, error) {
	// SECURITY: Only allow known conditions
	allowedConditions := map[string]bool{
		"1=1":              true,
		"is_active = TRUE": true,
	}
	if !allowedConditions[condition] {
		return nil, fmt.Errorf("security: disallowed query condition: %s", condition)
	}

	query := fmt.Sprintf(`
		SELECT id, slug, name, description, icon, category, display_order, is_active, release_status, parent_module_id
		FROM modules
		WHERE %s
		ORDER BY display_order ASC
	`, condition)

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list modules: %w", err)
	}
	defer rows.Close()

	modules := make([]*module.Module, 0)
	for rows.Next() {
		var (
			id             string
			slug           string
			name           string
			description    sql.NullString
			icon           sql.NullString
			category       string
			displayOrder   int
			isActive       bool
			releaseStatus  string
			parentModuleID sql.NullString
		)

		if err := rows.Scan(
			&id, &slug, &name, &description, &icon,
			&category, &displayOrder, &isActive, &releaseStatus, &parentModuleID,
		); err != nil {
			return nil, fmt.Errorf("failed to scan module: %w", err)
		}

		var parentID *string
		if parentModuleID.Valid {
			parentID = &parentModuleID.String
		}

		modules = append(modules, module.ReconstructModule(
			id,
			slug,
			name,
			description.String,
			icon.String,
			category,
			displayOrder,
			isActive,
			releaseStatus,
			parentID,
			nil, // eventTypes
		))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate modules: %w", err)
	}

	return modules, nil
}

// GetSubModules returns sub-modules for a parent module.
func (r *ModuleRepository) GetSubModules(ctx context.Context, parentModuleID string) ([]*module.Module, error) {
	query := `
		SELECT id, slug, name, description, icon, category, display_order, is_active, release_status, parent_module_id
		FROM modules
		WHERE parent_module_id = $1 AND is_active = TRUE
		ORDER BY display_order ASC
	`

	rows, err := r.db.QueryContext(ctx, query, parentModuleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get sub-modules: %w", err)
	}
	defer rows.Close()

	modules := make([]*module.Module, 0)
	for rows.Next() {
		var (
			id            string
			slug          string
			name          string
			description   sql.NullString
			icon          sql.NullString
			category      string
			displayOrder  int
			isActive      bool
			releaseStatus string
			parentID      sql.NullString
		)

		if err := rows.Scan(
			&id, &slug, &name, &description, &icon,
			&category, &displayOrder, &isActive, &releaseStatus, &parentID,
		); err != nil {
			return nil, fmt.Errorf("failed to scan sub-module: %w", err)
		}

		var pID *string
		if parentID.Valid {
			pID = &parentID.String
		}

		modules = append(modules, module.ReconstructModule(
			id,
			slug,
			name,
			description.String,
			icon.String,
			category,
			displayOrder,
			isActive,
			releaseStatus,
			pID,
			nil, // eventTypes
		))
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate sub-modules: %w", err)
	}

	return modules, nil
}
