package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
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
	properties, err := json.Marshal(a.Properties())
	if err != nil {
		return fmt.Errorf("failed to marshal properties: %w", err)
	}

	query := `
		INSERT INTO assets (
			id, tenant_id, parent_id, owner_id, owner_ref, name, asset_type, sub_type, criticality, status,
			scope, exposure, risk_score,
			description, tags, properties,
			provider, external_id, classification, sync_status, last_synced_at, sync_error,
			discovery_source, discovery_tool, discovered_at,
			compliance_scope, data_classification, pii_data_exposed, phi_data_exposed, regulatory_owner_id,
			is_internet_accessible, exposure_changed_at, last_exposure_level,
			first_seen, last_seen, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, $36, $37)
	`

	ownerRefVal := sql.NullString{String: a.OwnerRef(), Valid: a.OwnerRef() != ""}
	_, err = r.db.ExecContext(ctx, query,
		a.ID().String(),
		nullIDValue(a.TenantID()),
		nullIDPtr(a.ParentID()),
		nullIDPtr(a.OwnerID()),
		ownerRefVal,
		a.Name(),
		a.Type().String(),
		sql.NullString{String: a.SubType(), Valid: a.SubType() != ""},
		a.Criticality().String(),
		a.Status().String(),
		a.Scope().String(),
		a.Exposure().String(),
		a.RiskScore(),
		a.Description(),
		pq.Array(a.Tags()),
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

// FindByExternalID finds an asset by external_id across all providers.
// Used for correlation (RFC-001) when provider is unknown.
// Returns nil (no error) if not found.
func (r *AssetRepository) FindByExternalID(ctx context.Context, tenantID shared.ID, externalID string) (*asset.Asset, error) {
	if externalID == "" {
		return nil, nil
	}
	query := r.selectQuery() + " WHERE a.tenant_id = $1 AND a.external_id = $2 LIMIT 1"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), externalID)
	a, err := r.scanAsset(row, shared.ID{})
	if err != nil {
		if errors.Is(err, asset.ErrAssetNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("find by external_id: %w", err)
	}
	return a, nil
}

// FindByPropertyValue finds an asset by a specific top-level property value.
// Used for correlation (RFC-001) — e.g., certificate fingerprint.
// Only allows pre-defined safe keys to prevent injection.
// Returns nil (no error) if not found.
func (r *AssetRepository) FindByPropertyValue(ctx context.Context, tenantID shared.ID, key, value string) (*asset.Asset, error) {
	if key == "" || value == "" {
		return nil, nil
	}
	// Whitelist safe property keys for correlation
	safeKeys := map[string]bool{
		"fingerprint":   true,
		"serial_number": true,
		"account_id":    true,
		"arn":           true,
		"bundle_id":     true,
	}
	if !safeKeys[key] {
		return nil, fmt.Errorf("unsupported property key for correlation: %s", key)
	}

	query := r.selectQuery() + " WHERE a.tenant_id = $1 AND a.properties->>'" + key + "' = $2 LIMIT 1"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), value)
	a, err := r.scanAsset(row, shared.ID{})
	if err != nil {
		if errors.Is(err, asset.ErrAssetNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("find by property %s: %w", key, err)
	}
	return a, nil
}

// GetByName retrieves an asset by name within a tenant.
func (r *AssetRepository) GetByName(ctx context.Context, tenantID shared.ID, name string) (*asset.Asset, error) {
	query := r.selectQuery() + " WHERE a.tenant_id = $1 AND a.name = $2"

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), name)
	return r.scanAsset(row, shared.ID{})
}

// FindByIP finds an existing asset that matches the given IP address.
// Searches: name, properties->>'ip', properties->'ip_address'->>'address',
// and properties->'ip_addresses' array (host with multiple IPs).
// Returns nil (no error) if no match found.
func (r *AssetRepository) FindByIP(ctx context.Context, tenantID shared.ID, ip string) (*asset.Asset, error) {
	query := r.selectQuery() + ` WHERE a.tenant_id = $1 AND (
		a.name = $2
		OR a.properties->>'ip' = $2
		OR a.properties->'ip_address'->>'address' = $2
		OR a.properties->'ip_addresses' ? $2
	) LIMIT 1`

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), ip)
	a, err := r.scanAsset(row, shared.ID{})
	if err != nil {
		if errors.Is(err, asset.ErrAssetNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find asset by IP: %w", err)
	}
	return a, nil
}

// FindByHostname finds an existing asset that matches the given hostname.
// Searches: name (exact), properties->>'hostname', properties->'ip_address'->>'hostname'.
// Returns nil (no error) if no match found.
func (r *AssetRepository) FindByHostname(ctx context.Context, tenantID shared.ID, hostname string) (*asset.Asset, error) {
	query := r.selectQuery() + ` WHERE a.tenant_id = $1 AND (
		a.name = $2
		OR a.properties->>'hostname' = $2
		OR a.properties->'ip_address'->>'hostname' = $2
	) LIMIT 1`

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), hostname)
	a, err := r.scanAsset(row, shared.ID{})
	if err != nil {
		if errors.Is(err, asset.ErrAssetNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to find asset by hostname: %w", err)
	}
	return a, nil
}

// FindByIPs finds all assets that have ANY of the given IPs.
// Returns map[ip][]Asset — an IP can match multiple assets.
// Uses GIN index on properties->'ip_addresses' for performance.
// Part of RFC-001: Asset Identity Resolution.
func (r *AssetRepository) FindByIPs(ctx context.Context, tenantID shared.ID, ips []string) (map[string][]*asset.Asset, error) {
	if len(ips) == 0 {
		return make(map[string][]*asset.Asset), nil
	}

	query := r.selectQuery() + ` WHERE a.tenant_id = $1
		AND a.asset_type IN ('host', 'ip_address')
		AND (
			a.name = ANY($2)
			OR a.properties->>'ip' = ANY($2)
			OR a.properties->'ip_address'->>'address' = ANY($2)
			OR a.properties->'ip_addresses' ?| $2
		)`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), pq.Array(ips))
	if err != nil {
		return nil, fmt.Errorf("failed to find assets by IPs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	result := make(map[string][]*asset.Asset)
	for rows.Next() {
		a, scanErr := r.scanAssetFromRows(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		// Map this asset to each IP it matches
		for _, ip := range ips {
			if assetMatchesIP(a, ip) {
				result[ip] = append(result[ip], a)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate assets by IPs: %w", err)
	}
	return result, nil
}

// assetMatchesIP checks if an asset contains the given IP.
func assetMatchesIP(a *asset.Asset, ip string) bool {
	if a.Name() == ip {
		return true
	}
	props := a.Properties()
	if props == nil {
		return false
	}
	if v, ok := props["ip"].(string); ok && v == ip {
		return true
	}
	if ipAddr, ok := props["ip_address"].(map[string]any); ok {
		if addr, ok := ipAddr["address"].(string); ok && addr == ip {
			return true
		}
	}
	if ips, ok := props["ip_addresses"].([]any); ok {
		for _, v := range ips {
			if s, ok := v.(string); ok && s == ip {
				return true
			}
		}
	}
	if ips, ok := props["ip_addresses"].([]string); ok {
		for _, s := range ips {
			if s == ip {
				return true
			}
		}
	}
	return false
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

	escaped := escapeLikePattern(repoName)
	suffixSlash := "%/" + escaped // matches "org/repo" or "github.com-org/repo"
	suffixDash := "%-" + escaped  // matches "something-repo"

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
	escaped := escapeLikePattern(fullName)
	namePattern := "%/" + escaped // matches "github.com/openctemio/sdk-go" for "openctemio/sdk"
	externalIdPattern := "%/" + escaped

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), namePattern, fullName, externalIdPattern)
	return r.scanAsset(row, shared.ID{})
}

func (r *AssetRepository) selectQuery() string {
	return `
		SELECT a.id, a.tenant_id, a.parent_id, a.owner_id, a.owner_ref, a.name, a.asset_type, a.sub_type, a.criticality, a.status,
			   a.scope, a.exposure, a.risk_score,
			   COALESCE(fc.finding_count, 0) as finding_count,
			   COALESCE(fc.finding_critical, 0) as finding_critical,
			   COALESCE(fc.finding_high, 0) as finding_high,
			   COALESCE(fc.finding_medium, 0) as finding_medium,
			   COALESCE(fc.finding_low, 0) as finding_low,
			   COALESCE(fc.finding_info, 0) as finding_info,
			   a.description, a.tags, a.properties,
			   a.provider, a.external_id, a.classification, a.sync_status, a.last_synced_at, a.sync_error,
			   a.discovery_source, a.discovery_tool, a.discovered_at,
			   a.compliance_scope, a.data_classification, a.pii_data_exposed, a.phi_data_exposed, a.regulatory_owner_id,
			   a.is_internet_accessible, a.exposure_changed_at, a.last_exposure_level,
			   a.first_seen, a.last_seen, a.created_at, a.updated_at
		FROM assets a
		LEFT JOIN (
			SELECT asset_id,
				COUNT(*) as finding_count,
				SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) as finding_critical,
				SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as finding_high,
				SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as finding_medium,
				SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as finding_low,
				SUM(CASE WHEN severity = 'info' THEN 1 ELSE 0 END) as finding_info
			FROM findings
			WHERE status != 'resolved'
			GROUP BY asset_id
		) fc ON fc.asset_id = a.id
	`
}

// Update updates an existing asset.
func (r *AssetRepository) Update(ctx context.Context, a *asset.Asset) error {
	properties, err := json.Marshal(a.Properties())
	if err != nil {
		return fmt.Errorf("failed to marshal properties: %w", err)
	}

	query := `
		UPDATE assets
		SET parent_id = $2, owner_id = $3, owner_ref = $4, name = $5, asset_type = $6, sub_type = $7, criticality = $8, status = $9,
		    scope = $10, exposure = $11, risk_score = $12,
		    description = $13, tags = $14, properties = $15,
		    provider = $16, external_id = $17, classification = $18, sync_status = $19, last_synced_at = $20, sync_error = $21,
		    discovery_source = $22, discovery_tool = $23, discovered_at = $24,
		    compliance_scope = $25, data_classification = $26, pii_data_exposed = $27, phi_data_exposed = $28, regulatory_owner_id = $29,
		    is_internet_accessible = $30, exposure_changed_at = $31, last_exposure_level = $32,
		    last_seen = $33, updated_at = $34
		WHERE id = $1 AND tenant_id = $35
	`

	updateOwnerRef := sql.NullString{String: a.OwnerRef(), Valid: a.OwnerRef() != ""}
	result, err := r.db.ExecContext(ctx, query,
		a.ID().String(),
		nullIDPtr(a.ParentID()),
		nullIDPtr(a.OwnerID()),
		updateOwnerRef,
		a.Name(),
		a.Type().String(),
		sql.NullString{String: a.SubType(), Valid: a.SubType() != ""},
		a.Criticality().String(),
		a.Status().String(),
		a.Scope().String(),
		a.Exposure().String(),
		a.RiskScore(),
		a.Description(),
		pq.Array(a.Tags()),
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
		a.TenantID().String(),
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
		ownerRef        sql.NullString
		name            string
		assetType       string
		subType         sql.NullString
		criticality     string
		status          string
		scope           string
		exposure        string
		riskScore       int
		findingCount    int
		findingCritical int
		findingHigh     int
		findingMedium   int
		findingLow      int
		findingInfo     int
		description     sql.NullString
		tags            pq.StringArray
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
		&idStr, &tenantIDStr, &parentIDStr, &ownerIDStr, &ownerRef, &name, &assetType, &subType, &criticality, &status,
		&scope, &exposure, &riskScore, &findingCount,
		&findingCritical, &findingHigh, &findingMedium, &findingLow, &findingInfo,
		&description, &tags, &properties,
		&provider, &externalID, &classification, &syncStatus, &lastSyncedAt, &syncError,
		&discoverySource, &discoveryTool, &discoveredAt,
		&complianceScope, &dataClassification, &piiDataExposed, &phiDataExposed, &regulatoryOwnerIDStr,
		&isInternetAccessible, &exposureChangedAt, &lastExposureLevel,
		&firstSeen, &lastSeen, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	a, err := r.reconstructAsset(
		idStr, tenantIDStr, parentIDStr, ownerIDStr, ownerRef, name, assetType, subType.String, criticality, status,
		scope, exposure, riskScore, findingCount,
		description, tags, properties,
		provider, externalID, classification, syncStatus, lastSyncedAt, syncError,
		discoverySource, discoveryTool, discoveredAt,
		complianceScope, dataClassification, piiDataExposed, phiDataExposed, regulatoryOwnerIDStr,
		isInternetAccessible, exposureChangedAt, lastExposureLevel,
		firstSeen, lastSeen, createdAt, updatedAt,
	)
	if err != nil {
		return nil, err
	}

	a.SetFindingSeverityCounts(&asset.FindingSeverityCounts{
		Critical: findingCritical,
		High:     findingHigh,
		Medium:   findingMedium,
		Low:      findingLow,
		Info:     findingInfo,
	})

	return a, nil
}

func (r *AssetRepository) reconstructAsset(
	idStr string,
	tenantIDStr, parentIDStr, ownerIDStr, ownerRefStr sql.NullString,
	name, assetTypeStr, subTypeStr, criticalityStr, statusStr string,
	scopeStr, exposureStr string,
	riskScore, findingCount int,
	description sql.NullString,
	tags pq.StringArray,
	propertiesBytes []byte,
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

	result := asset.Reconstitute(
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
	)

	if ownerRefStr.Valid {
		result.SetOwnerRef(ownerRefStr.String)
	}
	if subTypeStr != "" {
		result.SetSubType(subTypeStr)
	}

	return result, nil
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

	// Full-text search across name, description, and aliases (RFC-001)
	if filter.Search != nil && *filter.Search != "" {
		searchPattern := wrapLikePattern(*filter.Search)
		conditions = append(conditions, fmt.Sprintf(
			"(a.name ILIKE $%d OR a.description ILIKE $%d OR a.properties->'aliases' ? $%d)",
			argIndex, argIndex+1, argIndex+2,
		))
		args = append(args, searchPattern, searchPattern, *filter.Search)
		argIndex += 3
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

	// Has findings filter - use EXISTS subquery (finding_count is a computed JOIN alias, not a column)
	if filter.HasFindings != nil {
		if *filter.HasFindings {
			conditions = append(conditions, "EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = a.id AND f.status != 'resolved')")
		} else {
			conditions = append(conditions, "NOT EXISTS (SELECT 1 FROM findings f WHERE f.asset_id = a.id AND f.status != 'resolved')")
		}
	}

	// Crown jewel filter
	if filter.IsCrownJewel != nil {
		conditions = append(conditions, fmt.Sprintf("a.is_crown_jewel = $%d", argIndex))
		args = append(args, *filter.IsCrownJewel)
		argIndex++
	}

	// Sub-type filter
	if filter.SubType != nil {
		conditions = append(conditions, fmt.Sprintf("a.sub_type = $%d", argIndex))
		args = append(args, *filter.SubType)
		argIndex++
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

	// Properties filter — AND across keys, OR within values per key.
	// Uses ->> text comparison for consistent matching across all value types.
	// For array JSONB values, also checks if the array contains the value.
	for key, vals := range filter.PropertiesFilter {
		if len(vals) == 1 {
			// Single value: simple equality or array containment
			conditions = append(conditions, fmt.Sprintf(
				"(a.properties ->> $%d = $%d OR a.properties -> $%d @> to_jsonb($%d::text))",
				argIndex, argIndex+1, argIndex, argIndex+1))
			args = append(args, key, vals[0])
			argIndex += 2
		} else if len(vals) > 0 {
			// Multiple values: OR within this key
			orParts := make([]string, 0, len(vals))
			keyIdx := argIndex
			args = append(args, key)
			argIndex++
			for _, v := range vals {
				orParts = append(orParts, fmt.Sprintf(
					"(a.properties ->> $%d = $%d OR a.properties -> $%d @> to_jsonb($%d::text))",
					keyIdx, argIndex, keyIdx, argIndex))
				args = append(args, v)
				argIndex++
			}
			conditions = append(conditions, "("+strings.Join(orParts, " OR ")+")")
		}
	}

	// Layer 2: Data Scope - filter by user's group membership
	// Backward compat: if user has no rows in user_accessible_assets, show all (NOT EXISTS bypasses)
	if filter.DataScopeUserID != nil && filter.TenantID != nil {
		userIDIdx := argIndex
		tenantIDIdx := argIndex + 1
		args = append(args, filter.DataScopeUserID.String(), *filter.TenantID)
		conditions = append(conditions, fmt.Sprintf(`(
			NOT EXISTS (SELECT 1 FROM user_accessible_assets WHERE user_id = $%d AND tenant_id = $%d)
			OR a.id IN (SELECT asset_id FROM user_accessible_assets WHERE user_id = $%d AND tenant_id = $%d)
		)`, userIDIdx, tenantIDIdx, userIDIdx, tenantIDIdx))
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
			description, tags, properties,
			provider, external_id, classification, sync_status, last_synced_at, sync_error,
			discovery_source, discovery_tool, discovered_at,
			first_seen, last_seen, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)
		ON CONFLICT (tenant_id, name) DO UPDATE SET
			tags = (
				SELECT array_agg(DISTINCT t)
				FROM unnest(assets.tags || EXCLUDED.tags) AS t
			),
			-- Freshness-aware merge: newer data wins, stale data only fills gaps
			properties = CASE
				WHEN EXCLUDED.last_seen >= COALESCE(assets.last_seen, '1970-01-01'::timestamptz)
				THEN merge_jsonb_deep(assets.properties, EXCLUDED.properties)
				ELSE merge_jsonb_deep(EXCLUDED.properties, assets.properties)
			END,
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

// ListDistinctTags returns distinct tags across all assets for a tenant.
// Supports prefix filtering for autocomplete and a limit for result size.
func (r *AssetRepository) ListDistinctTags(ctx context.Context, tenantID shared.ID, prefix string, types []string, limit int) ([]string, error) {
	query := `SELECT DISTINCT tag FROM assets, unnest(tags) AS tag WHERE tenant_id = $1`
	args := []any{tenantID.String()}
	argIdx := 2

	if len(types) > 0 {
		query += fmt.Sprintf(` AND asset_type = ANY($%d)`, argIdx)
		args = append(args, pq.Array(types))
		argIdx++
	}

	if prefix != "" {
		query += fmt.Sprintf(` AND tag ILIKE $%d`, argIdx)
		args = append(args, escapeLikePattern(prefix)+"%")
	}

	query += fmt.Sprintf(` ORDER BY tag LIMIT %d`, limit)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list distinct tags: %w", err)
	}
	defer rows.Close()

	tags := make([]string, 0)
	for rows.Next() {
		var tag string
		if err := rows.Scan(&tag); err != nil {
			return nil, fmt.Errorf("failed to scan tag: %w", err)
		}
		tags = append(tags, tag)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate tags: %w", err)
	}

	return tags, nil
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

// BatchUpdateRiskScores updates risk_score for multiple assets in a single query.
func (r *AssetRepository) BatchUpdateRiskScores(ctx context.Context, tenantID shared.ID, assets []*asset.Asset) error {
	if len(assets) == 0 {
		return nil
	}

	query := `
		UPDATE assets SET risk_score = data.score, updated_at = NOW()
		FROM (SELECT unnest($1::uuid[]) AS id, unnest($2::int[]) AS score) AS data
		WHERE assets.id = data.id AND assets.tenant_id = $3
	`

	ids := make([]string, 0, len(assets))
	scores := make([]int, 0, len(assets))
	for _, a := range assets {
		ids = append(ids, a.ID().String())
		scores = append(scores, a.RiskScore())
	}

	_, err := r.db.ExecContext(ctx, query, pq.Array(ids), pq.Array(scores), tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to batch update risk scores: %w", err)
	}

	return nil
}

// BulkUpdateStatus atomically updates the status of multiple assets in a single SQL statement.
func (r *AssetRepository) BulkUpdateStatus(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID, status asset.Status) (int64, error) {
	if len(assetIDs) == 0 {
		return 0, nil
	}

	ids := make([]string, 0, len(assetIDs))
	for _, id := range assetIDs {
		ids = append(ids, id.String())
	}

	query := `
		UPDATE assets
		SET status = $1, updated_at = NOW()
		WHERE tenant_id = $2 AND id = ANY($3::uuid[])
	`

	result, err := r.db.ExecContext(ctx, query, status.String(), tenantID.String(), pq.Array(ids))
	if err != nil {
		return 0, fmt.Errorf("bulk update status: %w", err)
	}

	return result.RowsAffected()
}

// GetAssetTypeBreakdown returns total and exposed counts per asset_type in a single query.
func (r *AssetRepository) GetAssetTypeBreakdown(ctx context.Context, tenantID shared.ID) (map[string]asset.AssetTypeStats, error) {
	query := `
		SELECT
			asset_type,
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE exposure = 'public') AS exposed
		FROM assets
		WHERE tenant_id = $1
		GROUP BY asset_type
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get asset type breakdown: %w", err)
	}
	defer rows.Close()

	result := make(map[string]asset.AssetTypeStats)
	for rows.Next() {
		var assetType string
		var total, exposed int
		if err := rows.Scan(&assetType, &total, &exposed); err != nil {
			return nil, fmt.Errorf("failed to scan asset type breakdown: %w", err)
		}
		result[assetType] = asset.AssetTypeStats{Total: total, Exposed: exposed}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate asset type breakdown: %w", err)
	}

	return result, nil
}

// GetAverageRiskScore returns the average risk_score for all assets in a tenant.
func (r *AssetRepository) GetAverageRiskScore(ctx context.Context, tenantID shared.ID) (float64, error) {
	var avg float64
	err := r.db.QueryRowContext(ctx,
		`SELECT COALESCE(AVG(risk_score), 0) FROM assets WHERE tenant_id = $1`,
		tenantID.String(),
	).Scan(&avg)
	if err != nil {
		return 0, fmt.Errorf("failed to get average risk score: %w", err)
	}
	return avg, nil
}

// GetAggregateStats computes all asset statistics in a SINGLE round-trip.
// Filters: types (asset_type ANY), tags (tags && — overlap, matches List semantics).
//
// The previous implementation issued 6 queries (1 totals + 5 GROUP BY breakdowns).
// This version collapses everything into one query using a CTE + UNION ALL,
// trading slightly more complex SQL for an 83% reduction in DB round-trips.
// PostgreSQL plans a single scan of the filtered CTE for all aggregates.
func (r *AssetRepository) GetAggregateStats(ctx context.Context, tenantID shared.ID, types []string, tags []string, subType string, countByFields ...string) (*asset.AggregateStats, error) {
	stats := &asset.AggregateStats{
		ByType:         make(map[string]int),
		BySubType:      make(map[string]int),
		ByStatus:       make(map[string]int),
		ByCriticality:  make(map[string]int),
		ByScope:        make(map[string]int),
		ByExposure:     make(map[string]int),
		MetadataCounts: make(map[string]map[string]int),
	}

	// Build the WHERE clause once.
	filterClause := " WHERE a.tenant_id = $1"
	args := []any{tenantID.String()}
	idx := 2
	if len(types) > 0 {
		filterClause += fmt.Sprintf(" AND a.asset_type = ANY($%d::text[])", idx)
		args = append(args, pq.Array(types))
		idx++
	}
	if len(tags) > 0 {
		filterClause += fmt.Sprintf(" AND a.tags && $%d", idx)
		args = append(args, pq.Array(tags))
		idx++
	}
	if subType != "" {
		filterClause += fmt.Sprintf(" AND a.sub_type = $%d", idx)
		args = append(args, subType)
		// idx++ if more conditions are added
	}

	// One query, three columns:
	//   category — which aggregate this row belongs to
	//   key      — the breakdown key (empty for scalar aggregates)
	//   value    — float8 so it carries both COUNT(*) and AVG(risk_score)
	//
	// Postgres will plan a single scan of `filtered` for all the inline
	// SELECTs that follow. The findings CTE is restricted to the filtered
	// asset id set so we never touch findings rows for assets we filtered out.
	query := fmt.Sprintf(`
WITH filtered AS (
  SELECT a.id, a.asset_type, a.sub_type, a.status, a.criticality, a.scope, a.exposure, a.risk_score, a.properties
  FROM assets a
  %s
),
finding_counts AS (
  SELECT f.asset_id, COUNT(*)::bigint AS cnt
  FROM findings f
  WHERE f.asset_id IN (SELECT id FROM filtered)
  GROUP BY f.asset_id
)
SELECT category, key, value FROM (
  SELECT 'total'::text          AS category, ''::text          AS key, COUNT(*)::float8 AS value FROM filtered
  UNION ALL
  SELECT 'risk_avg',              '',                                  COALESCE(AVG(risk_score), 0)::float8 FROM filtered
  UNION ALL
  SELECT 'with_findings',         '',                                  (SELECT COUNT(*)::float8 FROM finding_counts)
  UNION ALL
  SELECT 'findings_total',        '',                                  (SELECT COALESCE(SUM(cnt), 0)::float8 FROM finding_counts)
  UNION ALL
  SELECT 'high_risk',             '',                                  COUNT(*)::float8 FROM filtered WHERE risk_score >= 70
  UNION ALL
  SELECT 'asset_type',            asset_type,                          COUNT(*)::float8 FROM filtered GROUP BY asset_type
  UNION ALL
  SELECT 'sub_type',              sub_type,                            COUNT(*)::float8 FROM filtered WHERE sub_type IS NOT NULL AND sub_type != '' GROUP BY sub_type
  UNION ALL
  SELECT 'status',                status,                              COUNT(*)::float8 FROM filtered GROUP BY status
  UNION ALL
  SELECT 'criticality',           criticality,                         COUNT(*)::float8 FROM filtered GROUP BY criticality
  UNION ALL
  SELECT 'scope',                 scope,                               COUNT(*)::float8 FROM filtered GROUP BY scope
  UNION ALL
  SELECT 'exposure',              exposure,                            COUNT(*)::float8 FROM filtered GROUP BY exposure
) sub
`, filterClause)

	// Append metadata count queries for requested JSONB property fields.
	// Each field adds a UNION ALL that groups by the property value.
	// Only alphanumeric + underscore field names are allowed (SQL injection safe).
	validField := regexp.MustCompile(`^[a-z][a-z0-9_]{0,49}$`)
	for _, field := range countByFields {
		if !validField.MatchString(field) {
			continue
		}
		// Insert before the closing ") sub" by replacing it
		query = strings.TrimSuffix(strings.TrimSpace(query), ") sub")
		query += fmt.Sprintf(`
  UNION ALL
  SELECT 'meta:%s', COALESCE(a.properties->>'%s', 'null'), COUNT(*)::float8
  FROM filtered a
  WHERE a.properties ? '%s'
  GROUP BY a.properties->>'%s'
) sub
`, field, field, field, field)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get aggregate stats: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var category, key string
		var value float64
		if err := rows.Scan(&category, &key, &value); err != nil {
			return nil, fmt.Errorf("failed to scan aggregate stats row: %w", err)
		}
		switch category {
		case "total":
			stats.Total = int(value)
		case "risk_avg":
			stats.RiskScoreAvg = value
		case "with_findings":
			stats.WithFindings = int(value)
		case "findings_total":
			stats.FindingsTotal = int(value)
		case "high_risk":
			stats.HighRiskCount = int(value)
		case "asset_type":
			stats.ByType[key] = int(value)
		case "sub_type":
			stats.BySubType[key] = int(value)
		case "status":
			stats.ByStatus[key] = int(value)
		case "criticality":
			stats.ByCriticality[key] = int(value)
		case "scope":
			stats.ByScope[key] = int(value)
		case "exposure":
			stats.ByExposure[key] = int(value)
		default:
			// Handle dynamic metadata counts: "meta:field_name"
			if strings.HasPrefix(category, "meta:") {
				field := strings.TrimPrefix(category, "meta:")
				if stats.MetadataCounts[field] == nil {
					stats.MetadataCounts[field] = make(map[string]int)
				}
				stats.MetadataCounts[field][key] = int(value)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating aggregate stats: %w", err)
	}

	return stats, nil
}

// GetPropertyFacets returns distinct JSONB property keys and their top values.
// Uses a single query that expands JSONB keys and values together, then groups
// in Go — replacing the previous 1+N query pattern.
func (r *AssetRepository) GetPropertyFacets(ctx context.Context, tenantID shared.ID, types []string, subType string) ([]asset.PropertyFacet, error) {
	// Build optional extra filter clauses (applied inside the sub-select).
	extraWhere := ""
	args := []any{tenantID.String()}
	idx := 2

	if len(types) > 0 {
		extraWhere += fmt.Sprintf(" AND a.asset_type = ANY($%d::text[])", idx)
		args = append(args, pq.Array(types))
		idx++
	}
	if subType != "" {
		extraWhere += fmt.Sprintf(" AND a.sub_type = $%d", idx)
		args = append(args, subType)
		// idx++ — not needed after the last param
	}

	// Single query: expand every JSONB key/value pair per asset, then aggregate.
	// For scalar values: extract via ->> (returns text).
	// For array values: unwrap via jsonb_array_elements_text (returns individual elements).
	// This prevents arrays like ["ns1.cloudflare.com","ns2.cloudflare.com"] appearing
	// as a single facet value.
	query := fmt.Sprintf(`
		SELECT key, val, COUNT(*) AS cnt
		FROM (
			-- Scalar values (strings, numbers, booleans)
			SELECT k AS key, a.properties ->> k AS val
			FROM assets a, jsonb_object_keys(a.properties) AS k
			WHERE a.tenant_id = $1
			  AND a.properties IS NOT NULL
			  AND a.properties != '{}'::jsonb
			  AND jsonb_typeof(a.properties -> k) != 'array'
			  AND jsonb_typeof(a.properties -> k) != 'object'
			  %[1]s
			UNION ALL
			-- Array values: unwrap each element
			SELECT k AS key, jsonb_array_elements_text(a.properties -> k) AS val
			FROM assets a, jsonb_object_keys(a.properties) AS k
			WHERE a.tenant_id = $1
			  AND a.properties IS NOT NULL
			  AND a.properties != '{}'::jsonb
			  AND jsonb_typeof(a.properties -> k) = 'array'
			  %[1]s
		) sub
		WHERE key NOT IN ('dns_records', 'ports', 'interfaces', 'tags')
		  AND val IS NOT NULL
		  AND val != ''
		GROUP BY key, val
		ORDER BY key, cnt DESC
	`, extraWhere)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get property facets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Group results by key in insertion order; track per-key asset count.
	type facetAccum struct {
		values     []string
		totalCount int // sum of per-value counts (≈ asset count for this key)
	}
	order := make([]string, 0, 15)
	accum := make(map[string]*facetAccum)

	for rows.Next() {
		var key, val string
		var cnt int
		if err := rows.Scan(&key, &val, &cnt); err != nil {
			return nil, fmt.Errorf("failed to scan facet row: %w", err)
		}

		if _, seen := accum[key]; !seen {
			accum[key] = &facetAccum{}
			order = append(order, key)
		}
		fa := accum[key]
		fa.totalCount += cnt
		// Keep only the top 20 values per key (rows are ordered by cnt DESC within each key).
		if len(fa.values) < 20 {
			fa.values = append(fa.values, val)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating facet rows: %w", err)
	}

	// Build facets: skip keys with total_count < 2, limit to top 15 keys by count.
	const maxKeys = 15
	const minCount = 2

	facets := make([]asset.PropertyFacet, 0, len(order))
	for _, key := range order {
		fa := accum[key]
		if fa.totalCount < minCount {
			continue
		}
		facets = append(facets, asset.PropertyFacet{
			Key:    key,
			Label:  formatPropertyLabel(key),
			Values: fa.values,
			Count:  fa.totalCount,
		})
		if len(facets) == maxKeys {
			break
		}
	}

	return facets, nil
}

// formatPropertyLabel converts snake_case or camelCase key to Title Case label.
// Handles: snake_case, camelCase, PascalCase, ALLCAPS, and mixtures.
func formatPropertyLabel(key string) string {
	// Step 1: insert space before uppercase letters in camelCase/PascalCase
	// but NOT between consecutive uppercase (e.g., "BIOS" stays "BIOS")
	var b strings.Builder
	for i, r := range key {
		if i > 0 && r >= 'A' && r <= 'Z' {
			prev := rune(key[i-1])
			// Insert space if prev is lowercase, OR prev is uppercase but next (if exists) is lowercase
			// This handles: "camelCase" -> "camel Case", "BIOSUuid" -> "BIOS Uuid"
			if prev >= 'a' && prev <= 'z' {
				b.WriteRune(' ')
			} else if prev >= 'A' && prev <= 'Z' && i+1 < len(key) && key[i+1] >= 'a' && key[i+1] <= 'z' {
				b.WriteRune(' ')
			}
		}
		b.WriteRune(r)
	}
	result := b.String()

	// Step 2: replace underscores with spaces
	result = strings.ReplaceAll(result, "_", " ")

	// Step 3: title case each word
	words := strings.Fields(result) // splits on any whitespace
	for i, w := range words {
		if len(w) > 0 {
			// Keep ALL_CAPS words as-is (acronyms like BIOS, UUID, IP)
			allUpper := true
			for _, c := range w {
				if c < 'A' || c > 'Z' {
					allUpper = false
					break
				}
			}
			if !allUpper {
				words[i] = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
			}
		}
	}
	return strings.Join(words, " ")
}

// ListAllNodes fetches every asset for the tenant as lightweight graph nodes.
// Used by attack path scoring to build the full in-memory directed graph.
// Only the columns needed for scoring are fetched.
func (r *AssetRepository) ListAllNodes(ctx context.Context, tenantID shared.ID) ([]asset.AssetNode, error) {
	const query = `
		SELECT
			a.id,
			a.name,
			a.asset_type,
			a.exposure,
			a.criticality,
			a.risk_score,
			COALESCE(a.is_crown_jewel, FALSE),
			COALESCE(fc.finding_count, 0)
		FROM assets a
		LEFT JOIN (
			SELECT asset_id, COUNT(*) AS finding_count
			FROM findings
			GROUP BY asset_id
		) fc ON fc.asset_id = a.id
		WHERE a.tenant_id = $1
		ORDER BY a.created_at
	`
	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("list all nodes: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var nodes []asset.AssetNode
	for rows.Next() {
		var n asset.AssetNode
		if scanErr := rows.Scan(
			&n.ID, &n.Name, &n.AssetType, &n.Exposure,
			&n.Criticality, &n.RiskScore, &n.IsCrownJewel, &n.FindingCount,
		); scanErr != nil {
			return nil, fmt.Errorf("scan node: %w", scanErr)
		}
		nodes = append(nodes, n)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate nodes: %w", err)
	}
	return nodes, nil
}
