package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// Default sort order for assets
const defaultSortOrder = "created_at DESC"

// AssetRepository implements asset.Repository using PostgreSQL.
type AssetRepository struct {
	db *DB
}

// NewAssetRepository creates a new AssetRepository.
func NewAssetRepository(db *DB) *AssetRepository {
	return &AssetRepository{db: db}
}

// Create persists a new asset.
func (r *AssetRepository) Create(ctx context.Context, a *asset.Asset) error {
	metadata, err := json.Marshal(a.Metadata())
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	properties, err := json.Marshal(a.Properties())
	if err != nil {
		return fmt.Errorf("failed to marshal properties: %w", err)
	}

	query := `
		INSERT INTO assets (
			id, tenant_id, parent_id, owner_id, name, asset_type, criticality, status,
			scope, exposure, risk_score,
			description, tags, metadata, properties,
			provider, external_id, classification, sync_status, last_synced_at, sync_error,
			discovery_source, discovery_tool, discovered_at,
			compliance_scope, data_classification, pii_data_exposed, phi_data_exposed, regulatory_owner_id,
			is_internet_accessible, exposure_changed_at, last_exposure_level,
			first_seen, last_seen, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36)
	`

	_, err = r.db.ExecContext(ctx, query,
		a.ID().String(),
		nullIDValue(a.TenantID()),
		nullIDPtr(a.ParentID()),
		nullIDPtr(a.OwnerID()),
		a.Name(),
		a.Type().String(),
		a.Criticality().String(),
		a.Status().String(),
		a.Scope().String(),
		a.Exposure().String(),
		a.RiskScore(),
		a.Description(),
		pq.Array(a.Tags()),
		metadata,
		properties,
		a.Provider().String(),
		nullString(a.ExternalID()),
		nullString(a.Classification()),
		a.SyncStatus().String(),
		nullTime(a.LastSyncedAt()),
		nullString(a.SyncError()),
		nullString(a.DiscoverySource()),
		nullString(a.DiscoveryTool()),
		nullTime(a.DiscoveredAt()),
		pq.Array(a.ComplianceScope()),
		nullString(string(a.DataClassification())),
		a.PIIDataExposed(),
		a.PHIDataExposed(),
		nullIDPtr(a.RegulatoryOwnerID()),
		a.IsInternetAccessible(),
		nullTime(a.ExposureChangedAt()),
		nullString(string(a.LastExposureLevel())),
		a.FirstSeen(),
		a.LastSeen(),
		a.CreatedAt(),
		a.UpdatedAt(),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return asset.AlreadyExistsError(a.Name())
		}
		return fmt.Errorf("failed to create asset: %w", err)
	}

	return nil
}

// GetByID retrieves an asset by its ID within a tenant.
// Security: Requires tenantID to prevent cross-tenant data access.
func (r *AssetRepository) GetByID(ctx context.Context, tenantID, assetID shared.ID) (*asset.Asset, error) {
	query := r.selectQuery() + " WHERE a.tenant_id = $1 AND a.id = $2"

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), assetID.String())
	return r.scanAsset(row, assetID)
}

// GetByExternalID retrieves an asset by external ID and provider.
func (r *AssetRepository) GetByExternalID(ctx context.Context, tenantID shared.ID, provider asset.Provider, externalID string) (*asset.Asset, error) {
	query := r.selectQuery() + " WHERE a.tenant_id = $1 AND a.provider = $2 AND a.external_id = $3"

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), provider.String(), externalID)
	return r.scanAsset(row, shared.ID{})
}

// GetByName retrieves an asset by name within a tenant.
func (r *AssetRepository) GetByName(ctx context.Context, tenantID shared.ID, name string) (*asset.Asset, error) {
	query := r.selectQuery() + " WHERE a.tenant_id = $1 AND a.name = $2"

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), name)
	return r.scanAsset(row, shared.ID{})
}

// FindRepositoryByRepoName finds a repository asset whose name ends with the given repo name.
// This handles matching agent-created assets like "github.com-org/suborg/repo" with repo name "repo".
// NOTE: This only matches by repo name, use FindRepositoryByFullName for more precise matching.
func (r *AssetRepository) FindRepositoryByRepoName(ctx context.Context, tenantID shared.ID, repoName string) (*asset.Asset, error) {
	// Search for repository assets where:
	// 1. Name ends with "/repoName" (e.g., "github.com-org/suborg/repo" matches "repo")
	// 2. Or name ends with "-repoName" for some formats
	// 3. Or exact match
	query := r.selectQuery() + `
		WHERE a.tenant_id = $1
		AND a.asset_type IN ('repository', 'code_repo')
		AND (
			a.name = $2
			OR a.name LIKE $3
			OR a.name LIKE $4
		)
		ORDER BY a.created_at DESC
		LIMIT 1
	`

	suffixSlash := "%/" + repoName // matches "org/repo" or "github.com-org/repo"
	suffixDash := "%-" + repoName  // matches "something-repo"

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), repoName, suffixSlash, suffixDash)
	return r.scanAsset(row, shared.ID{})
}

// FindRepositoryByFullName finds a repository asset that matches the given full name (org/repo format).
// It searches for assets whose name or external_id ends with the full org/repo pattern.
// This is more precise than FindRepositoryByRepoName as it considers the organization.
func (r *AssetRepository) FindRepositoryByFullName(ctx context.Context, tenantID shared.ID, fullName string) (*asset.Asset, error) {
	// Search for repository assets where name or external_id contains the full name pattern
	// e.g., "github.com/openctemio/sdk-go" should match fullName "openctemio/sdk"
	query := r.selectQuery() + `
		WHERE a.tenant_id = $1
		AND a.asset_type IN ('repository', 'code_repo')
		AND (
			a.name LIKE $2
			OR a.external_id = $3
			OR a.external_id LIKE $4
		)
		ORDER BY a.created_at DESC
		LIMIT 1
	`

	// Match names that end with the fullName pattern
	namePattern := "%/" + fullName // matches "github.com/openctemio/sdk-go" for "openctemio/sdk"
	externalIdPattern := "%/" + fullName

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), namePattern, fullName, externalIdPattern)
	return r.scanAsset(row, shared.ID{})
}

func (r *AssetRepository) selectQuery() string {
	return `
		SELECT a.id, a.tenant_id, a.parent_id, a.owner_id, a.name, a.asset_type, a.criticality, a.status,
			   a.scope, a.exposure, a.risk_score,
			   COALESCE((SELECT COUNT(*) FROM findings f WHERE f.asset_id = a.id), 0) as finding_count,
			   a.description, a.tags, a.metadata, a.properties,
			   a.provider, a.external_id, a.classification, a.sync_status, a.last_synced_at, a.sync_error,
			   a.discovery_source, a.discovery_tool, a.discovered_at,
			   a.compliance_scope, a.data_classification, a.pii_data_exposed, a.phi_data_exposed, a.regulatory_owner_id,
			   a.is_internet_accessible, a.exposure_changed_at, a.last_exposure_level,
			   a.first_seen, a.last_seen, a.created_at, a.updated_at
		FROM assets a
	`
}

// Update updates an existing asset.
func (r *AssetRepository) Update(ctx context.Context, a *asset.Asset) error {
	metadata, err := json.Marshal(a.Metadata())
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	properties, err := json.Marshal(a.Properties())
	if err != nil {
		return fmt.Errorf("failed to marshal properties: %w", err)
	}

	query := `
		UPDATE assets
		SET parent_id = $2, owner_id = $3, name = $4, asset_type = $5, criticality = $6, status = $7,
		    scope = $8, exposure = $9, risk_score = $10,
		    description = $11, tags = $12, metadata = $13, properties = $14,
		    provider = $15, external_id = $16, classification = $17, sync_status = $18, last_synced_at = $19, sync_error = $20,
		    discovery_source = $21, discovery_tool = $22, discovered_at = $23,
		    compliance_scope = $24, data_classification = $25, pii_data_exposed = $26, phi_data_exposed = $27, regulatory_owner_id = $28,
		    is_internet_accessible = $29, exposure_changed_at = $30, last_exposure_level = $31,
		    last_seen = $32, updated_at = $33
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		a.ID().String(),
		nullIDPtr(a.ParentID()),
		nullIDPtr(a.OwnerID()),
		a.Name(),
		a.Type().String(),
		a.Criticality().String(),
		a.Status().String(),
		a.Scope().String(),
		a.Exposure().String(),
		a.RiskScore(),
		a.Description(),
		pq.Array(a.Tags()),
		metadata,
		properties,
		a.Provider().String(),
		nullString(a.ExternalID()),
		nullString(a.Classification()),
		a.SyncStatus().String(),
		nullTime(a.LastSyncedAt()),
		nullString(a.SyncError()),
		nullString(a.DiscoverySource()),
		nullString(a.DiscoveryTool()),
		nullTime(a.DiscoveredAt()),
		pq.Array(a.ComplianceScope()),
		nullString(string(a.DataClassification())),
		a.PIIDataExposed(),
		a.PHIDataExposed(),
		nullIDPtr(a.RegulatoryOwnerID()),
		a.IsInternetAccessible(),
		nullTime(a.ExposureChangedAt()),
		nullString(string(a.LastExposureLevel())),
		a.LastSeen(),
		a.UpdatedAt(),
	)

	if err != nil {
		return fmt.Errorf("failed to update asset: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return asset.NotFoundError(a.ID())
	}

	return nil
}

// Delete removes an asset by its ID within a tenant.
// Security: Requires tenantID to prevent cross-tenant deletion.
func (r *AssetRepository) Delete(ctx context.Context, tenantID, assetID shared.ID) error {
	query := `DELETE FROM assets WHERE tenant_id = $1 AND id = $2`

	result, err := r.db.ExecContext(ctx, query, tenantID.String(), assetID.String())
	if err != nil {
		return fmt.Errorf("failed to delete asset: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return asset.NotFoundError(assetID)
	}

	return nil
}

// List retrieves assets with filtering, sorting, and pagination.
func (r *AssetRepository) List(
	ctx context.Context,
	filter asset.Filter,
	opts asset.ListOptions,
	page pagination.Pagination,
) (pagination.Result[*asset.Asset], error) {
	baseQuery := r.selectQuery()
	countQuery := `SELECT COUNT(*) FROM assets a`

	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Apply sorting (default to created_at DESC)
	orderBy := defaultSortOrder
	if opts.Sort != nil && !opts.Sort.IsEmpty() {
		orderBy = opts.Sort.SQLWithDefault(defaultSortOrder)
	}
	baseQuery += " ORDER BY " + orderBy
	baseQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", page.Limit(), page.Offset())

	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return pagination.Result[*asset.Asset]{}, fmt.Errorf("failed to count assets: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return pagination.Result[*asset.Asset]{}, fmt.Errorf("failed to query assets: %w", err)
	}
	defer rows.Close()

	var assets []*asset.Asset
	for rows.Next() {
		a, err := r.scanAssetFromRows(rows)
		if err != nil {
			return pagination.Result[*asset.Asset]{}, err
		}
		assets = append(assets, a)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*asset.Asset]{}, fmt.Errorf("failed to iterate assets: %w", err)
	}

	return pagination.NewResult(assets, total, page), nil
}

// Count returns the total number of assets matching the filter.
func (r *AssetRepository) Count(ctx context.Context, filter asset.Filter) (int64, error) {
	query := `SELECT COUNT(*) FROM assets a`

	whereClause, args := r.buildWhereClause(filter)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count assets: %w", err)
	}

	return count, nil
}

// ExistsByName checks if an asset with the given name exists within a tenant.
// Security: Requires tenantID to prevent cross-tenant enumeration.
func (r *AssetRepository) ExistsByName(ctx context.Context, tenantID shared.ID, name string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM assets WHERE tenant_id = $1 AND name = $2)`

	var exists bool
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), name).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check asset existence: %w", err)
	}

	return exists, nil
}

// Helper methods

func (r *AssetRepository) scanAsset(row *sql.Row, assetID shared.ID) (*asset.Asset, error) {
	a, err := r.doScan(row.Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, asset.NotFoundError(assetID)
		}
		return nil, fmt.Errorf("failed to scan asset: %w", err)
	}
	return a, nil
}

func (r *AssetRepository) scanAssetFromRows(rows *sql.Rows) (*asset.Asset, error) {
	return r.doScan(rows.Scan)
}

func (r *AssetRepository) doScan(scan func(dest ...any) error) (*asset.Asset, error) {
	var (
		idStr           string
		tenantIDStr     sql.NullString
		parentIDStr     sql.NullString
		ownerIDStr      sql.NullString
		name            string
		assetType       string
		criticality     string
		status          string
		scope           string
		exposure        string
		riskScore       int
		findingCount    int
		description     sql.NullString
		tags            pq.StringArray
		metadata        []byte
		properties      []byte
		provider        sql.NullString
		externalID      sql.NullString
		classification  sql.NullString
		syncStatus      sql.NullString
		lastSyncedAt    sql.NullTime
		syncError       sql.NullString
		discoverySource sql.NullString
		discoveryTool   sql.NullString
		discoveredAt    sql.NullTime
		// CTEM fields
		complianceScope      pq.StringArray
		dataClassification   sql.NullString
		piiDataExposed       bool
		phiDataExposed       bool
		regulatoryOwnerIDStr sql.NullString
		isInternetAccessible bool
		exposureChangedAt    sql.NullTime
		lastExposureLevel    sql.NullString
		// Timestamps
		firstSeen time.Time
		lastSeen  time.Time
		createdAt time.Time
		updatedAt time.Time
	)

	err := scan(
		&idStr, &tenantIDStr, &parentIDStr, &ownerIDStr, &name, &assetType, &criticality, &status,
		&scope, &exposure, &riskScore, &findingCount,
		&description, &tags, &metadata, &properties,
		&provider, &externalID, &classification, &syncStatus, &lastSyncedAt, &syncError,
		&discoverySource, &discoveryTool, &discoveredAt,
		&complianceScope, &dataClassification, &piiDataExposed, &phiDataExposed, &regulatoryOwnerIDStr,
		&isInternetAccessible, &exposureChangedAt, &lastExposureLevel,
		&firstSeen, &lastSeen, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	return r.reconstructAsset(
		idStr, tenantIDStr, parentIDStr, ownerIDStr, name, assetType, criticality, status,
		scope, exposure, riskScore, findingCount,
		description, tags, metadata, properties,
		provider, externalID, classification, syncStatus, lastSyncedAt, syncError,
		discoverySource, discoveryTool, discoveredAt,
		complianceScope, dataClassification, piiDataExposed, phiDataExposed, regulatoryOwnerIDStr,
		isInternetAccessible, exposureChangedAt, lastExposureLevel,
		firstSeen, lastSeen, createdAt, updatedAt,
	)
}

func (r *AssetRepository) reconstructAsset(
	idStr string,
	tenantIDStr, parentIDStr, ownerIDStr sql.NullString,
	name, assetTypeStr, criticalityStr, statusStr string,
	scopeStr, exposureStr string,
	riskScore, findingCount int,
	description sql.NullString,
	tags pq.StringArray,
	metadataBytes, propertiesBytes []byte,
	provider sql.NullString,
	externalID, classification sql.NullString,
	syncStatus sql.NullString,
	lastSyncedAt sql.NullTime,
	syncError sql.NullString,
	discoverySource, discoveryTool sql.NullString,
	discoveredAt sql.NullTime,
	// CTEM fields
	complianceScope pq.StringArray,
	dataClassification sql.NullString,
	piiDataExposed, phiDataExposed bool,
	regulatoryOwnerIDStr sql.NullString,
	isInternetAccessible bool,
	exposureChangedAt sql.NullTime,
	lastExposureLevelStr sql.NullString,
	// Timestamps
	firstSeen, lastSeen, createdAt, updatedAt time.Time,
) (*asset.Asset, error) {
	parsedID, err := shared.IDFromString(idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse id: %w", err)
	}

	var tenantID shared.ID
	if tenantIDStr.Valid {
		tenantID, _ = shared.IDFromString(tenantIDStr.String)
	}

	var parentID *shared.ID
	if parentIDStr.Valid {
		id, _ := shared.IDFromString(parentIDStr.String)
		parentID = &id
	}

	var ownerID *shared.ID
	if ownerIDStr.Valid {
		id, _ := shared.IDFromString(ownerIDStr.String)
		ownerID = &id
	}

	assetType, _ := asset.ParseAssetType(assetTypeStr)
	criticality, _ := asset.ParseCriticality(criticalityStr)
	status, _ := asset.ParseStatus(statusStr)
	scope, _ := asset.ParseScope(scopeStr)
	exposure, _ := asset.ParseExposure(exposureStr)
	parsedProvider := asset.ParseProvider(nullStringValue(provider))
	parsedSyncStatus := asset.ParseSyncStatus(nullStringValue(syncStatus))

	var metadata map[string]any
	if len(metadataBytes) > 0 {
		if err := json.Unmarshal(metadataBytes, &metadata); err != nil {
			metadata = make(map[string]any)
		}
	}

	var properties map[string]any
	if len(propertiesBytes) > 0 {
		if err := json.Unmarshal(propertiesBytes, &properties); err != nil {
			properties = make(map[string]any)
		}
	}

	desc := ""
	if description.Valid {
		desc = description.String
	}

	var lastSynced *time.Time
	if lastSyncedAt.Valid {
		lastSynced = &lastSyncedAt.Time
	}

	var discovered *time.Time
	if discoveredAt.Valid {
		discovered = &discoveredAt.Time
	}

	// CTEM fields
	var regulatoryOwnerID *shared.ID
	if regulatoryOwnerIDStr.Valid {
		id, _ := shared.IDFromString(regulatoryOwnerIDStr.String)
		regulatoryOwnerID = &id
	}

	parsedDataClassification, _ := asset.ParseDataClassification(nullStringValue(dataClassification))

	var expChanged *time.Time
	if exposureChangedAt.Valid {
		expChanged = &exposureChangedAt.Time
	}

	lastExpLevel, _ := asset.ParseExposure(nullStringValue(lastExposureLevelStr))

	return asset.Reconstitute(
		parsedID,
		tenantID,
		parentID,
		ownerID,
		name,
		assetType,
		criticality,
		status,
		scope,
		exposure,
		riskScore,
		findingCount,
		desc,
		[]string(tags),
		metadata,
		properties,
		parsedProvider,
		nullStringValue(externalID),
		nullStringValue(classification),
		parsedSyncStatus,
		lastSynced,
		nullStringValue(syncError),
		nullStringValue(discoverySource),
		nullStringValue(discoveryTool),
		discovered,
		// CTEM fields
		[]string(complianceScope),
		parsedDataClassification,
		piiDataExposed,
		phiDataExposed,
		regulatoryOwnerID,
		isInternetAccessible,
		expChanged,
		lastExpLevel,
		// Timestamps
		firstSeen,
		lastSeen,
		createdAt,
		updatedAt,
	), nil
}

func (r *AssetRepository) buildWhereClause(filter asset.Filter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	// Tenant ID filter
	if filter.TenantID != nil && *filter.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("a.tenant_id = $%d", argIndex))
		args = append(args, *filter.TenantID)
		argIndex++
	}

	// Name filter (partial match)
	if filter.Name != nil && *filter.Name != "" {
		conditions = append(conditions, fmt.Sprintf("a.name ILIKE $%d", argIndex))
		args = append(args, wrapLikePattern(*filter.Name))
		argIndex++
	}

	// Asset types filter
	if len(filter.Types) > 0 {
		placeholders := make([]string, len(filter.Types))
		for i, t := range filter.Types {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, t.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("a.asset_type IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Criticalities filter
	if len(filter.Criticalities) > 0 {
		placeholders := make([]string, len(filter.Criticalities))
		for i, c := range filter.Criticalities {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, c.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("a.criticality IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Statuses filter
	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, s := range filter.Statuses {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, s.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("a.status IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Scopes filter
	if len(filter.Scopes) > 0 {
		placeholders := make([]string, len(filter.Scopes))
		for i, s := range filter.Scopes {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, s.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("a.scope IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Exposures filter
	if len(filter.Exposures) > 0 {
		placeholders := make([]string, len(filter.Exposures))
		for i, e := range filter.Exposures {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, e.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("a.exposure IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Tags filter
	if len(filter.Tags) > 0 {
		conditions = append(conditions, fmt.Sprintf("a.tags && $%d", argIndex))
		args = append(args, pq.Array(filter.Tags))
		argIndex++
	}

	// Full-text search across name and description
	if filter.Search != nil && *filter.Search != "" {
		searchPattern := wrapLikePattern(*filter.Search)
		conditions = append(conditions, fmt.Sprintf("(a.name ILIKE $%d OR a.description ILIKE $%d)", argIndex, argIndex+1))
		args = append(args, searchPattern, searchPattern)
		argIndex += 2
	}

	// Risk score range filters
	if filter.MinRiskScore != nil {
		conditions = append(conditions, fmt.Sprintf("a.risk_score >= $%d", argIndex))
		args = append(args, *filter.MinRiskScore)
		argIndex++
	}

	if filter.MaxRiskScore != nil {
		conditions = append(conditions, fmt.Sprintf("a.risk_score <= $%d", argIndex))
		args = append(args, *filter.MaxRiskScore)
		argIndex++
	}

	// Has findings filter - use EXISTS subquery for real-time count
	if filter.HasFindings != nil {
		if *filter.HasFindings {
			conditions = append(conditions, "EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = a.id)")
		} else {
			conditions = append(conditions, "NOT EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = a.id)")
		}
	}

	// Providers filter
	if len(filter.Providers) > 0 {
		placeholders := make([]string, len(filter.Providers))
		for i, p := range filter.Providers {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, p.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("a.provider IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Sync statuses filter
	if len(filter.SyncStatuses) > 0 {
		placeholders := make([]string, len(filter.SyncStatuses))
		for i, s := range filter.SyncStatuses {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, s.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("a.sync_status IN (%s)", strings.Join(placeholders, ", ")))
	}

	// Parent ID filter
	if filter.ParentID != nil && *filter.ParentID != "" {
		conditions = append(conditions, fmt.Sprintf("a.parent_id = $%d", argIndex))
		args = append(args, *filter.ParentID)
		argIndex++
	}

	return strings.Join(conditions, " AND "), args
}

// =============================================================================
// Batch Operations
// =============================================================================

// GetByNames retrieves multiple assets by their names within a tenant.
// Returns a map of name -> Asset for found assets.
func (r *AssetRepository) GetByNames(ctx context.Context, tenantID shared.ID, names []string) (map[string]*asset.Asset, error) {
	if len(names) == 0 {
		return make(map[string]*asset.Asset), nil
	}

	// Build query with ANY for efficient lookup
	query := r.selectQuery() + " WHERE a.tenant_id = $1 AND a.name = ANY($2)"

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(names))
	if err != nil {
		return nil, fmt.Errorf("failed to query assets by names: %w", err)
	}
	defer rows.Close()

	result := make(map[string]*asset.Asset)
	for rows.Next() {
		a, err := r.scanAssetFromRows(rows)
		if err != nil {
			return nil, err
		}
		result[a.Name()] = a
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate assets: %w", err)
	}

	return result, nil
}

// UpsertBatch creates or updates multiple assets in a single operation.
// Uses PostgreSQL ON CONFLICT for atomic upsert behavior.
// Conflict is detected on (tenant_id, name) unique constraint.
func (r *AssetRepository) UpsertBatch(ctx context.Context, assets []*asset.Asset) (created int, updated int, err error) {
	if len(assets) == 0 {
		return 0, 0, nil
	}

	// Use a transaction for consistency
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Prepare the upsert statement
	// ON CONFLICT updates: properties (merged via merge_jsonb_deep), tags, last_seen, updated_at
	// Also updates discovery fields only if they were previously null
	query := `
		INSERT INTO assets (
			id, tenant_id, parent_id, owner_id, name, asset_type, criticality, status,
			scope, exposure, risk_score,
			description, tags, metadata, properties,
			provider, external_id, classification, sync_status, last_synced_at, sync_error,
			discovery_source, discovery_tool, discovered_at,
			first_seen, last_seen, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)
		ON CONFLICT (tenant_id, name) DO UPDATE SET
			tags = (
				SELECT array_agg(DISTINCT t)
				FROM unnest(assets.tags || EXCLUDED.tags) AS t
			),
			properties = merge_jsonb_deep(assets.properties, EXCLUDED.properties),
			last_seen = GREATEST(assets.last_seen, EXCLUDED.last_seen),
			updated_at = NOW(),
			discovery_source = COALESCE(assets.discovery_source, EXCLUDED.discovery_source),
			discovery_tool = COALESCE(assets.discovery_tool, EXCLUDED.discovery_tool),
			discovered_at = COALESCE(assets.discovered_at, EXCLUDED.discovered_at)
		RETURNING (xmax = 0) AS inserted
	`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, a := range assets {
		metadata, err := json.Marshal(a.Metadata())
		if err != nil {
			return created, updated, fmt.Errorf("failed to marshal metadata: %w", err)
		}

		properties, err := json.Marshal(a.Properties())
		if err != nil {
			return created, updated, fmt.Errorf("failed to marshal properties: %w", err)
		}

		var inserted bool
		err = stmt.QueryRowContext(ctx,
			a.ID().String(),
			nullIDValue(a.TenantID()),
			nullIDPtr(a.ParentID()),
			nullIDPtr(a.OwnerID()),
			a.Name(),
			a.Type().String(),
			a.Criticality().String(),
			a.Status().String(),
			a.Scope().String(),
			a.Exposure().String(),
			a.RiskScore(),
			a.Description(),
			pq.Array(a.Tags()),
			metadata,
			properties,
			a.Provider().String(),
			nullString(a.ExternalID()),
			nullString(a.Classification()),
			a.SyncStatus().String(),
			nullTime(a.LastSyncedAt()),
			nullString(a.SyncError()),
			nullString(a.DiscoverySource()),
			nullString(a.DiscoveryTool()),
			nullTime(a.DiscoveredAt()),
			a.FirstSeen(),
			a.LastSeen(),
			a.CreatedAt(),
			a.UpdatedAt(),
		).Scan(&inserted)

		if err != nil {
			return created, updated, fmt.Errorf("failed to upsert asset %s: %w", a.Name(), err)
		}

		if inserted {
			created++
		} else {
			updated++
		}

		// For repository-type assets, ensure asset_repositories entry exists
		// This is required for FK constraint on repository_branches table
		// We do this for BOTH insert and update to handle legacy assets without extension
		if a.Type().IsRepository() {
			repoQuery := `
				INSERT INTO asset_repositories (asset_id, full_name, default_branch, visibility)
				VALUES ($1, $2, 'main', 'private')
				ON CONFLICT (asset_id) DO NOTHING
			`
			if _, err := tx.ExecContext(ctx, repoQuery, a.ID().String(), a.Name()); err != nil {
				return created, updated, fmt.Errorf("failed to ensure repository extension for %s: %w", a.Name(), err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return created, updated, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return created, updated, nil
}

// UpdateFindingCounts updates finding counts for multiple assets in batch.
// This recalculates the finding_count from the findings table.
func (r *AssetRepository) UpdateFindingCounts(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) error {
	if len(assetIDs) == 0 {
		return nil
	}

	// Convert IDs to strings for the query
	idStrings := make([]string, len(assetIDs))
	for i, id := range assetIDs {
		idStrings[i] = id.String()
	}

	// Update finding_count using a subquery
	// Note: finding_count is a computed field in our SELECT, but we might want to
	// cache it for performance. This query updates a physical column if it exists.
	// If finding_count is always computed via subquery (current implementation),
	// this is a no-op but we keep it for future optimization.
	query := `
		UPDATE assets a
		SET updated_at = NOW()
		WHERE a.tenant_id = $1 AND a.id = ANY($2)
	`

	_, err := r.db.ExecContext(ctx, query, tenantID.String(), pq.Array(idStrings))
	if err != nil {
		return fmt.Errorf("failed to update finding counts: %w", err)
	}

	return nil
}
