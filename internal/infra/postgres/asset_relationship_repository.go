package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// AssetRelationshipRepository implements asset.RelationshipRepository using PostgreSQL.
type AssetRelationshipRepository struct {
	db *DB
}

// NewAssetRelationshipRepository creates a new AssetRelationshipRepository.
func NewAssetRelationshipRepository(db *DB) *AssetRelationshipRepository {
	return &AssetRelationshipRepository{db: db}
}

// Create persists a new relationship.
func (r *AssetRelationshipRepository) Create(ctx context.Context, rel *asset.Relationship) error {
	query := `
		INSERT INTO asset_relationships (
			id, tenant_id, source_asset_id, target_asset_id,
			relationship_type, description, confidence, discovery_method,
			impact_weight, tags, last_verified, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	_, err := r.db.ExecContext(ctx, query,
		rel.ID().String(),
		rel.TenantID().String(),
		rel.SourceAssetID().String(),
		rel.TargetAssetID().String(),
		rel.Type().String(),
		nullString(rel.Description()),
		rel.Confidence().String(),
		rel.DiscoveryMethod().String(),
		rel.ImpactWeight(),
		pq.Array(rel.Tags()),
		rel.LastVerified(),
		rel.CreatedAt(),
		rel.UpdatedAt(),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return asset.RelationshipAlreadyExistsError()
		}
		return fmt.Errorf("failed to create relationship: %w", err)
	}

	return nil
}

// GetByID retrieves a relationship by ID within a tenant.
func (r *AssetRelationshipRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*asset.RelationshipWithAssets, error) {
	query := r.selectWithAssetsQuery() + ` WHERE ar.tenant_id = $1 AND ar.id = $2`

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	rel, err := r.scanRelationshipWithAssets(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, asset.RelationshipNotFoundError(id)
		}
		return nil, fmt.Errorf("failed to get relationship: %w", err)
	}

	return rel, nil
}

// Update updates an existing relationship.
func (r *AssetRelationshipRepository) Update(ctx context.Context, rel *asset.Relationship) error {
	query := `
		UPDATE asset_relationships SET
			description = $3,
			confidence = $4,
			discovery_method = $5,
			impact_weight = $6,
			tags = $7,
			last_verified = $8,
			updated_at = $9
		WHERE tenant_id = $1 AND id = $2
	`

	result, err := r.db.ExecContext(ctx, query,
		rel.TenantID().String(),
		rel.ID().String(),
		nullString(rel.Description()),
		rel.Confidence().String(),
		rel.DiscoveryMethod().String(),
		rel.ImpactWeight(),
		pq.Array(rel.Tags()),
		rel.LastVerified(),
		rel.UpdatedAt(),
	)
	if err != nil {
		return fmt.Errorf("failed to update relationship: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return asset.RelationshipNotFoundError(rel.ID())
	}

	return nil
}

// Delete removes a relationship by ID within a tenant.
func (r *AssetRelationshipRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	query := `DELETE FROM asset_relationships WHERE tenant_id = $1 AND id = $2`

	result, err := r.db.ExecContext(ctx, query, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("failed to delete relationship: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return asset.RelationshipNotFoundError(id)
	}

	return nil
}

// ListByAsset retrieves all relationships for an asset (both directions).
// Uses UNION ALL of two indexed queries for performance instead of OR.
func (r *AssetRelationshipRepository) ListByAsset(
	ctx context.Context,
	tenantID, assetID shared.ID,
	filter asset.RelationshipFilter,
) ([]*asset.RelationshipWithAssets, int64, error) {
	// Build WHERE conditions for both directions
	filterConditions, filterArgs, argOffset := r.buildFilterConditions(filter, 3)

	// Count query using UNION ALL
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*) FROM (
			SELECT ar.id FROM asset_relationships ar
			WHERE ar.tenant_id = $1 AND ar.source_asset_id = $2 %s
			UNION ALL
			SELECT ar.id FROM asset_relationships ar
			WHERE ar.tenant_id = $1 AND ar.target_asset_id = $2 %s
		) sub
	`, r.applyDirectionFilter(filterConditions, "outgoing", filter.Direction),
		r.applyDirectionFilter(filterConditions, "incoming", filter.Direction))

	countArgs := []any{tenantID.String(), assetID.String()}
	countArgs = append(countArgs, filterArgs...)

	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count relationships: %w", err)
	}

	if total == 0 {
		return []*asset.RelationshipWithAssets{}, 0, nil
	}

	// Data query using UNION ALL with JOINs
	page := filter.Page
	if page < 1 {
		page = 1
	}
	perPage := filter.PerPage
	if perPage < 1 {
		perPage = 20
	}
	if perPage > 100 {
		perPage = 100
	}
	offset := (page - 1) * perPage

	dataQuery := fmt.Sprintf(`
		SELECT ar.id, ar.tenant_id, ar.source_asset_id, ar.target_asset_id,
			   ar.relationship_type, ar.description, ar.confidence, ar.discovery_method,
			   ar.impact_weight, ar.tags, ar.last_verified, ar.created_at, ar.updated_at,
			   sa.name, sa.asset_type, ta.name, ta.asset_type
		FROM (
			SELECT ar2.id FROM asset_relationships ar2
			WHERE ar2.tenant_id = $1 AND ar2.source_asset_id = $2 %s
			UNION ALL
			SELECT ar2.id FROM asset_relationships ar2
			WHERE ar2.tenant_id = $1 AND ar2.target_asset_id = $2 %s
		) sub
		INNER JOIN asset_relationships ar ON ar.id = sub.id
		INNER JOIN assets sa ON ar.source_asset_id = sa.id
		INNER JOIN assets ta ON ar.target_asset_id = ta.id
		ORDER BY ar.created_at DESC
		LIMIT $%d OFFSET $%d
	`, r.applyDirectionFilter(filterConditions, "outgoing", filter.Direction),
		r.applyDirectionFilter(filterConditions, "incoming", filter.Direction),
		argOffset, argOffset+1)

	dataArgs := []any{tenantID.String(), assetID.String()}
	dataArgs = append(dataArgs, filterArgs...)
	dataArgs = append(dataArgs, perPage, offset)

	rows, err := r.db.QueryContext(ctx, dataQuery, dataArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list relationships: %w", err)
	}
	defer rows.Close()

	var results []*asset.RelationshipWithAssets
	for rows.Next() {
		rel, err := r.scanRelationshipWithAssets(rows)
		if err != nil {
			return nil, 0, err
		}
		results = append(results, rel)
	}

	if err = rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("failed to iterate relationships: %w", err)
	}

	return results, total, nil
}

// Exists checks if a specific relationship already exists.
func (r *AssetRelationshipRepository) Exists(
	ctx context.Context,
	tenantID, sourceID, targetID shared.ID,
	relType asset.RelationshipType,
) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM asset_relationships
			WHERE tenant_id = $1 AND source_asset_id = $2 AND target_asset_id = $3
			AND relationship_type = $4
		)
	`
	var exists bool
	err := r.db.QueryRowContext(ctx, query,
		tenantID.String(), sourceID.String(), targetID.String(), relType.String(),
	).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check relationship existence: %w", err)
	}
	return exists, nil
}

// CountByAsset returns the count of relationships for an asset.
func (r *AssetRelationshipRepository) CountByAsset(ctx context.Context, tenantID, assetID shared.ID) (int64, error) {
	query := `
		SELECT COUNT(*) FROM asset_relationships
		WHERE tenant_id = $1 AND (source_asset_id = $2 OR target_asset_id = $2)
	`
	var count int64
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), assetID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count relationships: %w", err)
	}
	return count, nil
}

// =============================================================================
// Internal helpers
// =============================================================================

// selectWithAssetsQuery returns the base SELECT with JOINed asset data.
func (r *AssetRelationshipRepository) selectWithAssetsQuery() string {
	return `
		SELECT ar.id, ar.tenant_id, ar.source_asset_id, ar.target_asset_id,
			   ar.relationship_type, ar.description, ar.confidence, ar.discovery_method,
			   ar.impact_weight, ar.tags, ar.last_verified, ar.created_at, ar.updated_at,
			   sa.name, sa.asset_type, ta.name, ta.asset_type
		FROM asset_relationships ar
		INNER JOIN assets sa ON ar.source_asset_id = sa.id
		INNER JOIN assets ta ON ar.target_asset_id = ta.id
	`
}

// scanner is an interface satisfied by both *sql.Row and *sql.Rows.
type relationshipScanner interface {
	Scan(dest ...any) error
}

// scanRelationshipWithAssets scans a row into a RelationshipWithAssets.
func (r *AssetRelationshipRepository) scanRelationshipWithAssets(row relationshipScanner) (*asset.RelationshipWithAssets, error) {
	var (
		id              string
		tenantID        string
		sourceAssetID   string
		targetAssetID   string
		relType         string
		description     sql.NullString
		confidence      string
		discoveryMethod string
		impactWeight    int
		tags            []string
		lastVerified    *time.Time
		createdAt       time.Time
		updatedAt       time.Time
		sourceAssetName string
		sourceAssetType string
		targetAssetName string
		targetAssetType string
	)

	err := row.Scan(
		&id, &tenantID, &sourceAssetID, &targetAssetID,
		&relType, &description, &confidence, &discoveryMethod,
		&impactWeight, pq.Array(&tags), &lastVerified, &createdAt, &updatedAt,
		&sourceAssetName, &sourceAssetType, &targetAssetName, &targetAssetType,
	)
	if err != nil {
		return nil, err
	}

	rel := asset.ReconstituteRelationship(
		shared.MustIDFromString(id),
		shared.MustIDFromString(tenantID),
		shared.MustIDFromString(sourceAssetID),
		shared.MustIDFromString(targetAssetID),
		asset.RelationshipType(relType),
		description.String,
		asset.RelationshipConfidence(confidence),
		asset.RelationshipDiscoveryMethod(discoveryMethod),
		impactWeight,
		tags,
		lastVerified,
		createdAt,
		updatedAt,
	)

	return &asset.RelationshipWithAssets{
		Relationship:    rel,
		SourceAssetName: sourceAssetName,
		SourceAssetType: asset.AssetType(sourceAssetType),
		TargetAssetName: targetAssetName,
		TargetAssetType: asset.AssetType(targetAssetType),
	}, nil
}

// buildFilterConditions builds additional WHERE conditions from the filter.
// Returns the condition string, args, and next arg index.
func (r *AssetRelationshipRepository) buildFilterConditions(
	filter asset.RelationshipFilter,
	startArg int,
) (string, []any, int) {
	var conditions []string
	var args []any
	argIdx := startArg

	if len(filter.Types) > 0 {
		conditions = append(conditions, fmt.Sprintf("ar2.relationship_type = ANY($%d)", argIdx))
		typeStrs := make([]string, len(filter.Types))
		for i, t := range filter.Types {
			typeStrs[i] = t.String()
		}
		args = append(args, pq.Array(typeStrs))
		argIdx++
	}

	if len(filter.Confidences) > 0 {
		conditions = append(conditions, fmt.Sprintf("ar2.confidence = ANY($%d)", argIdx))
		confStrs := make([]string, len(filter.Confidences))
		for i, c := range filter.Confidences {
			confStrs[i] = c.String()
		}
		args = append(args, pq.Array(confStrs))
		argIdx++
	}

	if filter.MinImpactWeight != nil {
		conditions = append(conditions, fmt.Sprintf("ar2.impact_weight >= $%d", argIdx))
		args = append(args, *filter.MinImpactWeight)
		argIdx++
	}

	if filter.MaxImpactWeight != nil {
		conditions = append(conditions, fmt.Sprintf("ar2.impact_weight <= $%d", argIdx))
		args = append(args, *filter.MaxImpactWeight)
		argIdx++
	}

	condStr := ""
	if len(conditions) > 0 {
		condStr = " AND " + strings.Join(conditions, " AND ")
	}

	return condStr, args, argIdx
}

// applyDirectionFilter returns the filter conditions or empty string based on direction.
func (r *AssetRelationshipRepository) applyDirectionFilter(conditions string, queryDir string, filterDir string) string {
	if filterDir == "" || filterDir == queryDir {
		return conditions
	}
	// If filtering for one direction only, exclude the other
	return " AND FALSE"
}

// Note: nullString is defined in helpers.go
