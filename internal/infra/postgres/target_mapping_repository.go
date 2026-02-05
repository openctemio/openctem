package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tool"
	"github.com/openctemio/api/pkg/pagination"
)

// TargetMappingRepository implements tool.TargetMappingRepository using PostgreSQL.
type TargetMappingRepository struct {
	db *DB
}

// NewTargetMappingRepository creates a new TargetMappingRepository.
func NewTargetMappingRepository(db *DB) *TargetMappingRepository {
	return &TargetMappingRepository{db: db}
}

// Create persists a new target mapping.
func (r *TargetMappingRepository) Create(ctx context.Context, m *tool.TargetAssetTypeMapping) error {
	var createdBy any
	if m.CreatedBy != nil {
		createdBy = m.CreatedBy.String()
	}

	var description any
	if m.Description != "" {
		description = m.Description
	}

	query := `
		INSERT INTO target_asset_type_mappings (
			id, target_type, asset_type, priority, is_active, description, created_at, updated_at, created_by
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	_, err := r.db.ExecContext(ctx, query,
		m.ID.String(),
		m.TargetType,
		string(m.AssetType),
		m.Priority,
		m.IsActive,
		description,
		m.CreatedAt,
		m.UpdatedAt,
		createdBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create target mapping: %w", err)
	}

	return nil
}

// GetByID retrieves a target mapping by ID.
func (r *TargetMappingRepository) GetByID(ctx context.Context, id shared.ID) (*tool.TargetAssetTypeMapping, error) {
	query := `
		SELECT id, target_type, asset_type, priority, is_active, description, created_at, updated_at, created_by
		FROM target_asset_type_mappings
		WHERE id = $1
	`

	var m tool.TargetAssetTypeMapping
	var idStr, assetTypeStr string
	var createdByStr, descriptionStr sql.NullString

	err := r.db.QueryRowContext(ctx, query, id.String()).Scan(
		&idStr,
		&m.TargetType,
		&assetTypeStr,
		&m.Priority,
		&m.IsActive,
		&descriptionStr,
		&m.CreatedAt,
		&m.UpdatedAt,
		&createdByStr,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get target mapping: %w", err)
	}

	m.ID, _ = shared.IDFromString(idStr)
	m.AssetType = asset.AssetType(assetTypeStr)
	if descriptionStr.Valid {
		m.Description = descriptionStr.String
	}
	if createdByStr.Valid {
		createdBy, _ := shared.IDFromString(createdByStr.String)
		m.CreatedBy = &createdBy
	}

	return &m, nil
}

// Update updates an existing target mapping.
func (r *TargetMappingRepository) Update(ctx context.Context, m *tool.TargetAssetTypeMapping) error {
	var description any
	if m.Description != "" {
		description = m.Description
	}

	query := `
		UPDATE target_asset_type_mappings
		SET target_type = $2, asset_type = $3, priority = $4, is_active = $5, description = $6, updated_at = $7
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		m.ID.String(),
		m.TargetType,
		string(m.AssetType),
		m.Priority,
		m.IsActive,
		description,
		m.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update target mapping: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("target mapping not found: %s", m.ID)
	}

	return nil
}

// Delete removes a target mapping by ID.
func (r *TargetMappingRepository) Delete(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM target_asset_type_mappings WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete target mapping: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("target mapping not found: %s", id)
	}

	return nil
}

// List retrieves target mappings with filtering and pagination.
func (r *TargetMappingRepository) List(ctx context.Context, filter tool.TargetMappingFilter, page pagination.Pagination) (pagination.Result[*tool.TargetAssetTypeMapping], error) {
	var result pagination.Result[*tool.TargetAssetTypeMapping]

	baseQuery := `FROM target_asset_type_mappings WHERE 1=1`
	var args []any
	argIdx := 1

	if filter.TargetType != nil {
		baseQuery += fmt.Sprintf(" AND target_type = $%d", argIdx)
		args = append(args, *filter.TargetType)
		argIdx++
	}

	if filter.AssetType != nil {
		baseQuery += fmt.Sprintf(" AND asset_type = $%d", argIdx)
		args = append(args, *filter.AssetType)
		argIdx++
	}

	if filter.IsActive != nil {
		baseQuery += fmt.Sprintf(" AND is_active = $%d", argIdx)
		args = append(args, *filter.IsActive)
		argIdx++
	}

	if len(filter.TargetTypes) > 0 {
		baseQuery += fmt.Sprintf(" AND target_type = ANY($%d)", argIdx)
		args = append(args, pq.Array(filter.TargetTypes))
		argIdx++
	}

	if len(filter.AssetTypes) > 0 {
		baseQuery += fmt.Sprintf(" AND asset_type = ANY($%d)", argIdx)
		args = append(args, pq.Array(filter.AssetTypes))
		argIdx++
	}

	// Count total
	countQuery := "SELECT COUNT(*) " + baseQuery
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return result, fmt.Errorf("failed to count target mappings: %w", err)
	}

	// Get items
	selectQuery := `SELECT id, target_type, asset_type, priority, is_active, description, created_at, updated_at, created_by ` +
		baseQuery + ` ORDER BY priority ASC, target_type ASC, asset_type ASC`

	if page.Limit() > 0 {
		selectQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", page.Limit(), page.Offset())
	}

	rows, err := r.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list target mappings: %w", err)
	}
	defer rows.Close()

	var items []*tool.TargetAssetTypeMapping
	for rows.Next() {
		var m tool.TargetAssetTypeMapping
		var idStr, assetTypeStr string
		var createdByStr, descriptionStr sql.NullString

		if err := rows.Scan(
			&idStr,
			&m.TargetType,
			&assetTypeStr,
			&m.Priority,
			&m.IsActive,
			&descriptionStr,
			&m.CreatedAt,
			&m.UpdatedAt,
			&createdByStr,
		); err != nil {
			return result, fmt.Errorf("failed to scan target mapping: %w", err)
		}

		m.ID, _ = shared.IDFromString(idStr)
		m.AssetType = asset.AssetType(assetTypeStr)
		if descriptionStr.Valid {
			m.Description = descriptionStr.String
		}
		if createdByStr.Valid {
			createdBy, _ := shared.IDFromString(createdByStr.String)
			m.CreatedBy = &createdBy
		}

		items = append(items, &m)
	}

	return pagination.NewResult(items, total, page), nil
}

// GetAssetTypesForTargets returns all asset types that can be scanned by the given target types.
func (r *TargetMappingRepository) GetAssetTypesForTargets(ctx context.Context, targetTypes []string) ([]asset.AssetType, error) {
	if len(targetTypes) == 0 {
		return nil, nil
	}

	query := `
		SELECT DISTINCT asset_type
		FROM target_asset_type_mappings
		WHERE target_type = ANY($1)
		  AND is_active = TRUE
		ORDER BY asset_type
	`

	rows, err := r.db.QueryContext(ctx, query, pq.Array(targetTypes))
	if err != nil {
		return nil, fmt.Errorf("failed to get asset types for targets: %w", err)
	}
	defer rows.Close()

	var assetTypes []asset.AssetType
	for rows.Next() {
		var assetTypeStr string
		if err := rows.Scan(&assetTypeStr); err != nil {
			return nil, fmt.Errorf("failed to scan asset type: %w", err)
		}
		assetTypes = append(assetTypes, asset.AssetType(assetTypeStr))
	}

	return assetTypes, nil
}

// GetTargetsForAssetType returns all target types that can scan the given asset type.
func (r *TargetMappingRepository) GetTargetsForAssetType(ctx context.Context, assetType asset.AssetType) ([]string, error) {
	query := `
		SELECT DISTINCT target_type
		FROM target_asset_type_mappings
		WHERE asset_type = $1
		  AND is_active = TRUE
		ORDER BY target_type
	`

	rows, err := r.db.QueryContext(ctx, query, string(assetType))
	if err != nil {
		return nil, fmt.Errorf("failed to get targets for asset type: %w", err)
	}
	defer rows.Close()

	var targets []string
	for rows.Next() {
		var target string
		if err := rows.Scan(&target); err != nil {
			return nil, fmt.Errorf("failed to scan target type: %w", err)
		}
		targets = append(targets, target)
	}

	return targets, nil
}

// CanToolScanAssetType checks if a tool (via its supported_targets) can scan a specific asset type.
func (r *TargetMappingRepository) CanToolScanAssetType(ctx context.Context, targetTypes []string, assetType asset.AssetType) (bool, error) {
	if len(targetTypes) == 0 {
		return false, nil
	}

	query := `
		SELECT EXISTS(
			SELECT 1
			FROM target_asset_type_mappings
			WHERE target_type = ANY($1)
			  AND asset_type = $2
			  AND is_active = TRUE
		)
	`

	var exists bool
	if err := r.db.QueryRowContext(ctx, query, pq.Array(targetTypes), string(assetType)).Scan(&exists); err != nil {
		return false, fmt.Errorf("failed to check tool-asset compatibility: %w", err)
	}

	return exists, nil
}

// GetIncompatibleAssetTypes returns asset types from the list that CANNOT be scanned
// by any of the given target types.
func (r *TargetMappingRepository) GetIncompatibleAssetTypes(ctx context.Context, targetTypes []string, assetTypes []asset.AssetType) ([]asset.AssetType, error) {
	if len(targetTypes) == 0 || len(assetTypes) == 0 {
		return assetTypes, nil // All incompatible if no targets
	}

	// Convert to strings for query
	assetTypeStrs := make([]string, len(assetTypes))
	for i, at := range assetTypes {
		assetTypeStrs[i] = string(at)
	}

	// Get compatible types
	query := `
		SELECT DISTINCT asset_type
		FROM target_asset_type_mappings
		WHERE target_type = ANY($1)
		  AND asset_type = ANY($2)
		  AND is_active = TRUE
	`

	rows, err := r.db.QueryContext(ctx, query, pq.Array(targetTypes), pq.Array(assetTypeStrs))
	if err != nil {
		return nil, fmt.Errorf("failed to get compatible types: %w", err)
	}
	defer rows.Close()

	compatibleSet := make(map[string]bool)
	for rows.Next() {
		var assetTypeStr string
		if err := rows.Scan(&assetTypeStr); err != nil {
			return nil, fmt.Errorf("failed to scan compatible type: %w", err)
		}
		compatibleSet[assetTypeStr] = true
	}

	// Return types not in compatible set
	var incompatible []asset.AssetType
	for _, at := range assetTypes {
		if !compatibleSet[string(at)] {
			incompatible = append(incompatible, at)
		}
	}

	return incompatible, nil
}

// GetCompatibleAssetTypes returns asset types from the list that CAN be scanned
// by at least one of the given target types.
func (r *TargetMappingRepository) GetCompatibleAssetTypes(ctx context.Context, targetTypes []string, assetTypes []asset.AssetType) ([]asset.AssetType, error) {
	if len(targetTypes) == 0 || len(assetTypes) == 0 {
		return nil, nil // None compatible if no targets or no types to check
	}

	// Convert to strings for query
	assetTypeStrs := make([]string, len(assetTypes))
	for i, at := range assetTypes {
		assetTypeStrs[i] = string(at)
	}

	query := `
		SELECT DISTINCT asset_type
		FROM target_asset_type_mappings
		WHERE target_type = ANY($1)
		  AND asset_type = ANY($2)
		  AND is_active = TRUE
		ORDER BY asset_type
	`

	rows, err := r.db.QueryContext(ctx, query, pq.Array(targetTypes), pq.Array(assetTypeStrs))
	if err != nil {
		return nil, fmt.Errorf("failed to get compatible types: %w", err)
	}
	defer rows.Close()

	var compatible []asset.AssetType
	for rows.Next() {
		var assetTypeStr string
		if err := rows.Scan(&assetTypeStr); err != nil {
			return nil, fmt.Errorf("failed to scan compatible type: %w", err)
		}
		compatible = append(compatible, asset.AssetType(assetTypeStr))
	}

	return compatible, nil
}

// Ensure TargetMappingRepository implements the interface
var _ tool.TargetMappingRepository = (*TargetMappingRepository)(nil)
