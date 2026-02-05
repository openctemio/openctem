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

	"github.com/openctemio/api/pkg/domain/component"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

const (
	// MaxLicensesPerComponent limits the number of licenses that can be linked to a single component
	MaxLicensesPerComponent = 50
	// MaxLicenseNameLength limits the length of a license name
	MaxLicenseNameLength = 255
)

// validLicensePattern matches valid SPDX-like license identifiers
// Allows: alphanumeric, dash, underscore, dot, plus, parentheses
var validLicensePattern = regexp.MustCompile(`^[a-zA-Z0-9\-_.+()]+$`)

// ComponentRepository implements component.Repository using PostgreSQL.
type ComponentRepository struct {
	db *DB
}

// NewComponentRepository creates a new ComponentRepository.
func NewComponentRepository(db *DB) *ComponentRepository {
	return &ComponentRepository{db: db}
}

// Upsert persists a global component.
func (r *ComponentRepository) Upsert(ctx context.Context, comp *component.Component) (shared.ID, error) {
	metadata, err := json.Marshal(comp.Metadata())
	if err != nil {
		return shared.ID{}, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO components (
			id, purl, name, version, ecosystem, description, homepage,
			vulnerability_count, metadata, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (purl) DO UPDATE SET
			description = EXCLUDED.description,
			homepage = EXCLUDED.homepage,
			-- Note: vulnerability_count is NOT updated from agent data.
			-- It should only be updated by background jobs that count findings.
			-- This prevents agents from accidentally resetting the count to 0.
			metadata = components.metadata || EXCLUDED.metadata,
			updated_at = NOW()
		RETURNING id, created_at, updated_at
	`

	var idStr string
	var createdAt, updatedAt time.Time

	err = r.db.QueryRowContext(ctx, query,
		comp.ID().String(),
		comp.PURL(),
		comp.Name(),
		comp.Version(),
		comp.Ecosystem().String(),
		nullString(comp.Description()),
		nullString(comp.Homepage()),
		comp.VulnerabilityCount(),
		metadata,
		comp.CreatedAt(),
		comp.UpdatedAt(),
	).Scan(&idStr, &createdAt, &updatedAt)

	if err != nil {
		return shared.ID{}, fmt.Errorf("failed to upsert component: %w", err)
	}

	parsedID, err := shared.IDFromString(idStr)
	if err != nil {
		return shared.ID{}, err
	}
	return parsedID, nil
}

// GetByPURL retrieves a global component by PURL.
func (r *ComponentRepository) GetByPURL(ctx context.Context, purl string) (*component.Component, error) {
	query := `
		SELECT id, name, version, ecosystem, purl, description, homepage,
			vulnerability_count, metadata, created_at, updated_at
		FROM components
		WHERE purl = $1
	`
	row := r.db.QueryRowContext(ctx, query, purl)
	return r.scanComponent(row)
}

// GetByID retrieves a component by ID.
func (r *ComponentRepository) GetByID(ctx context.Context, id shared.ID) (*component.Component, error) {
	query := `
		SELECT id, name, version, ecosystem, purl, description, homepage,
			vulnerability_count, metadata, created_at, updated_at
		FROM components
		WHERE id = $1
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanComponent(row)
}

// LinkLicenses links licenses to a component.
// It upserts licenses into the licenses table and creates links in component_licenses.
// Returns the count of successfully linked licenses.
// Security: Validates license names and limits the number of licenses per component.
func (r *ComponentRepository) LinkLicenses(ctx context.Context, componentID shared.ID, licenses []string) (int, error) {
	if len(licenses) == 0 {
		return 0, nil
	}

	// Security: Limit number of licenses to prevent DoS
	if len(licenses) > MaxLicensesPerComponent {
		return 0, fmt.Errorf("too many licenses: %d exceeds maximum of %d", len(licenses), MaxLicensesPerComponent)
	}

	linkedCount := 0
	for _, lic := range licenses {
		lic = strings.TrimSpace(lic)
		if lic == "" {
			continue
		}

		// Security: Validate license name length
		if len(lic) > MaxLicenseNameLength {
			// Skip invalid license instead of failing entire batch
			continue
		}

		// Security: Validate license name format (SPDX-like identifiers)
		if !validLicensePattern.MatchString(lic) {
			// Skip invalid license instead of failing entire batch
			continue
		}

		// Upsert license (use SPDX ID as both id and spdx_id for simplicity)
		// In the future, we could normalize to proper SPDX identifiers
		licenseQuery := `
			INSERT INTO licenses (id, spdx_id, name, category, risk)
			VALUES ($1, $1, $1, 'unknown', 'unknown')
			ON CONFLICT (spdx_id) DO NOTHING
		`
		if _, err := r.db.ExecContext(ctx, licenseQuery, lic); err != nil {
			return linkedCount, fmt.Errorf("failed to upsert license %s: %w", lic, err)
		}

		// Link component to license
		linkQuery := `
			INSERT INTO component_licenses (component_id, license_id)
			VALUES ($1, $2)
			ON CONFLICT (component_id, license_id) DO NOTHING
		`
		if _, err := r.db.ExecContext(ctx, linkQuery, componentID.String(), lic); err != nil {
			return linkedCount, fmt.Errorf("failed to link license %s to component: %w", lic, err)
		}
		linkedCount++
	}

	return linkedCount, nil
}

// LinkAsset creates a record in asset_components table.
func (r *ComponentRepository) LinkAsset(ctx context.Context, dep *component.AssetDependency) error {
	query := `
		INSERT INTO asset_components (
			id, tenant_id, asset_id, component_id, path, dependency_type, manifest_file, parent_component_id, depth, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (asset_id, component_id, path) DO UPDATE SET
			dependency_type = EXCLUDED.dependency_type,
			parent_component_id = EXCLUDED.parent_component_id,
			depth = EXCLUDED.depth,
			updated_at = NOW()
	`

	// Convert parent component ID to nullable string
	var parentID *string
	if dep.ParentComponentID() != nil {
		pid := dep.ParentComponentID().String()
		parentID = &pid
	}

	// Note: We use getters that we added to AssetDependency
	_, err := r.db.ExecContext(ctx, query,
		dep.ID().String(),
		dep.TenantID().String(),
		dep.AssetID().String(),
		dep.ComponentID().String(),
		dep.Path(),
		dep.DependencyType().String(),
		nullString(dep.ManifestFile()),
		parentID,
		dep.Depth(),
		dep.CreatedAt(),
		time.Now().UTC(),
	)

	if err != nil {
		return fmt.Errorf("failed to link asset dependency: %w", err)
	}
	return nil
}

// GetDependency retrieves a dependency by ID.
func (r *ComponentRepository) GetDependency(ctx context.Context, id shared.ID) (*component.AssetDependency, error) {
	// We need to join with components to get full details
	query := `
		SELECT
			ac.id, ac.tenant_id, ac.asset_id, ac.component_id, ac.path, ac.dependency_type, ac.manifest_file, ac.parent_component_id, ac.depth, ac.created_at, ac.updated_at,
			c.id, c.name, c.version, c.ecosystem, c.purl, c.description, c.homepage, c.vulnerability_count, c.metadata, c.created_at, c.updated_at
		FROM asset_components ac
		JOIN components c ON ac.component_id = c.id
		WHERE ac.id = $1
	`
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanDependency(row)
}

// UpdateDependency updates a dependency (e.g. type or path).
func (r *ComponentRepository) UpdateDependency(ctx context.Context, dep *component.AssetDependency) error {
	query := `
		UPDATE asset_components SET
			dependency_type = $2,
			path = $3,
			manifest_file = $4,
			updated_at = NOW()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query,
		dep.ID().String(),
		dep.DependencyType().String(),
		dep.Path(),
		nullString(dep.ManifestFile()),
	)
	if err != nil {
		return fmt.Errorf("failed to update dependency: %w", err)
	}
	return nil
}

// DeleteDependency removes a specific dependency link.
func (r *ComponentRepository) DeleteDependency(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM asset_components WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete dependency: %w", err)
	}
	return nil
}

// DeleteByAssetID removes all dependencies for an asset.
func (r *ComponentRepository) DeleteByAssetID(ctx context.Context, assetID shared.ID) error {
	query := `DELETE FROM asset_components WHERE asset_id = $1`
	_, err := r.db.ExecContext(ctx, query, assetID.String())
	if err != nil {
		return fmt.Errorf("failed to delete asset dependencies: %w", err)
	}
	return nil
}

// GetExistingDependencyByPURL retrieves an existing asset_component by asset and component PURL.
// Used for parent lookup during rescan when parent component exists from previous scan.
// Returns nil, nil if not found.
func (r *ComponentRepository) GetExistingDependencyByPURL(ctx context.Context, assetID shared.ID, purl string) (*component.AssetDependency, error) {
	query := `
		SELECT
			ac.id, ac.tenant_id, ac.asset_id, ac.component_id, ac.path, ac.dependency_type, ac.manifest_file, ac.parent_component_id, ac.depth, ac.created_at, ac.updated_at,
			c.id, c.name, c.version, c.ecosystem, c.purl, c.description, c.homepage, c.vulnerability_count, c.metadata, c.created_at, c.updated_at
		FROM asset_components ac
		JOIN components c ON ac.component_id = c.id
		WHERE ac.asset_id = $1 AND c.purl = $2
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, query, assetID.String(), purl)
	dep, err := r.scanDependency(row)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get dependency by PURL: %w", err)
	}
	return dep, nil
}

// GetExistingDependencyByComponentID retrieves an existing asset_component by asset, component ID, and path.
func (r *ComponentRepository) GetExistingDependencyByComponentID(ctx context.Context, assetID shared.ID, componentID shared.ID, path string) (*component.AssetDependency, error) {
	query := `
		SELECT
			ac.id, ac.tenant_id, ac.asset_id, ac.component_id, ac.path, ac.dependency_type, ac.manifest_file, ac.parent_component_id, ac.depth, ac.created_at, ac.updated_at,
			c.id, c.name, c.version, c.ecosystem, c.purl, c.description, c.homepage, c.vulnerability_count, c.metadata, c.created_at, c.updated_at
		FROM asset_components ac
		JOIN components c ON ac.component_id = c.id
		WHERE ac.asset_id = $1 AND ac.component_id = $2 AND ac.path = $3
		LIMIT 1
	`
	row := r.db.QueryRowContext(ctx, query, assetID.String(), componentID.String(), path)
	dep, err := r.scanDependency(row)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get dependency by component ID: %w", err)
	}
	return dep, nil
}

// UpdateAssetDependencyParent updates the parent_component_id and depth of an asset_component.
func (r *ComponentRepository) UpdateAssetDependencyParent(ctx context.Context, id shared.ID, parentID shared.ID, depth int) error {
	query := `
		UPDATE asset_components
		SET parent_component_id = $1, depth = $2, updated_at = NOW()
		WHERE id = $3
	`
	result, err := r.db.ExecContext(ctx, query, parentID.String(), depth, id.String())
	if err != nil {
		return fmt.Errorf("failed to update dependency parent: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return component.ErrDependencyNotFound
	}
	return nil
}

// ListComponents retrieves global components.
func (r *ComponentRepository) ListComponents(ctx context.Context, filter component.Filter, page pagination.Pagination) (pagination.Result[*component.Component], error) {
	baseQuery := `
		SELECT id, name, version, ecosystem, purl, description, homepage,
			vulnerability_count, metadata, created_at, updated_at
		FROM components
	`
	countQuery := `SELECT COUNT(*) FROM components`

	whereClause, args := r.buildWhereClause(filter)
	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	baseQuery += orderByCreatedAtDesc
	baseQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", page.Limit(), page.Offset())

	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return pagination.Result[*component.Component]{}, fmt.Errorf("failed to count components: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return pagination.Result[*component.Component]{}, fmt.Errorf("failed to list components: %w", err)
	}
	defer rows.Close()

	var comps []*component.Component
	for rows.Next() {
		comp, err := r.scanComponentFromRows(rows)
		if err != nil {
			return pagination.Result[*component.Component]{}, err
		}
		comps = append(comps, comp)
	}

	return pagination.NewResult(comps, total, page), nil
}

// ListDependencies retrieves dependencies for an asset.
func (r *ComponentRepository) ListDependencies(ctx context.Context, assetID shared.ID, page pagination.Pagination) (pagination.Result[*component.AssetDependency], error) {
	baseQuery := `
		SELECT
			ac.id, ac.tenant_id, ac.asset_id, ac.component_id, ac.path, ac.dependency_type, ac.manifest_file, ac.parent_component_id, ac.depth, ac.created_at, ac.updated_at,
			c.id, c.name, c.version, c.ecosystem, c.purl, c.description, c.homepage, c.vulnerability_count, c.metadata, c.created_at, c.updated_at
		FROM asset_components ac
		JOIN components c ON ac.component_id = c.id
		WHERE ac.asset_id = $1
	`
	countQuery := `SELECT COUNT(*) FROM asset_components WHERE asset_id = $1`

	baseQuery += " ORDER BY ac.depth ASC, ac.created_at DESC" // Order by depth first (direct deps first)
	baseQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", page.Limit(), page.Offset())

	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, assetID.String()).Scan(&total)
	if err != nil {
		return pagination.Result[*component.AssetDependency]{}, fmt.Errorf("failed to count dependencies: %w", err)
	}

	rows, err := r.db.QueryContext(ctx, baseQuery, assetID.String())
	if err != nil {
		return pagination.Result[*component.AssetDependency]{}, fmt.Errorf("failed to list dependencies: %w", err)
	}
	defer rows.Close()

	var deps []*component.AssetDependency
	for rows.Next() {
		var (
			adID, adTenant, adAsset, adCompID, adPath, adType string
			adManifest, adParentID                            sql.NullString
			adDepth                                           int
			adCreated, adUpdated                              time.Time

			cID, cName, cVer, cEco, cPurl string
			cDesc, cHome                  sql.NullString
			cVuln                         int
			cMeta                         []byte
			cCreated, cUpdated            time.Time
		)

		err := rows.Scan(
			&adID, &adTenant, &adAsset, &adCompID, &adPath, &adType, &adManifest, &adParentID, &adDepth, &adCreated, &adUpdated,
			&cID, &cName, &cVer, &cEco, &cPurl, &cDesc, &cHome, &cVuln, &cMeta, &cCreated, &cUpdated,
		)
		if err != nil {
			return pagination.Result[*component.AssetDependency]{}, err
		}

		cIDObj, _ := shared.IDFromString(cID)
		eco, _ := component.ParseEcosystem(cEco)
		var meta map[string]any
		if len(cMeta) > 0 {
			if err := json.Unmarshal(cMeta, &meta); err != nil {
				return pagination.Result[*component.AssetDependency]{}, fmt.Errorf("failed to unmarshal component metadata: %w", err)
			}
		}

		// License is now stored in component_licenses table, pass empty string
		comp := component.Reconstitute(
			cIDObj, cName, cVer, eco, cPurl,
			"", cDesc.String, cHome.String,
			cVuln, meta, cCreated, cUpdated,
		)

		adIDObj, _ := shared.IDFromString(adID)
		tIDObj, _ := shared.IDFromString(adTenant)
		aIDObj, _ := shared.IDFromString(adAsset)
		compIDObj, _ := shared.IDFromString(adCompID)
		depType, _ := component.ParseDependencyType(adType)

		var parentID *shared.ID
		if adParentID.Valid {
			pid, _ := shared.IDFromString(adParentID.String)
			parentID = &pid
		}

		dep := component.ReconstituteAssetDependency(
			adIDObj, tIDObj, aIDObj, compIDObj,
			adPath, depType, nullStringValue(adManifest),
			parentID, adDepth, adCreated, adUpdated,
		)
		dep.SetComponent(comp)
		deps = append(deps, dep)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*component.AssetDependency]{}, fmt.Errorf("rows iteration error: %w", err)
	}

	return pagination.NewResult(deps, total, page), nil
}

func (r *ComponentRepository) scanComponent(row *sql.Row) (*component.Component, error) {
	var (
		id, name, ver, eco, purl string
		desc, home               sql.NullString
		vuln                     int
		meta                     []byte
		cr, up                   time.Time
	)
	if err := row.Scan(&id, &name, &ver, &eco, &purl, &desc, &home, &vuln, &meta, &cr, &up); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	parsedID, _ := shared.IDFromString(id)
	parsedEco, _ := component.ParseEcosystem(eco)
	var parsedMeta map[string]any
	if len(meta) > 0 {
		if err := json.Unmarshal(meta, &parsedMeta); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	// License is now stored in component_licenses table, pass empty string
	return component.Reconstitute(parsedID, name, ver, parsedEco, purl, "", desc.String, home.String, vuln, parsedMeta, cr, up), nil
}

func (r *ComponentRepository) scanComponentFromRows(rows *sql.Rows) (*component.Component, error) {
	var (
		id, name, ver, eco, purl string
		desc, home               sql.NullString
		vuln                     int
		meta                     []byte
		cr, up                   time.Time
	)
	if err := rows.Scan(&id, &name, &ver, &eco, &purl, &desc, &home, &vuln, &meta, &cr, &up); err != nil {
		return nil, err
	}

	parsedID, _ := shared.IDFromString(id)
	parsedEco, _ := component.ParseEcosystem(eco)
	var parsedMeta map[string]any
	if len(meta) > 0 {
		if err := json.Unmarshal(meta, &parsedMeta); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	// License is now stored in component_licenses table, pass empty string
	return component.Reconstitute(parsedID, name, ver, parsedEco, purl, "", desc.String, home.String, vuln, parsedMeta, cr, up), nil
}

// Helper to scan dependency with joined component
func (r *ComponentRepository) scanDependency(row *sql.Row) (*component.AssetDependency, error) {
	var (
		adID, adTenant, adAsset, adCompID, adPath, adType string
		adManifest, adParentID                            sql.NullString
		adDepth                                           int
		adCreated, adUpdated                              time.Time

		cID, cName, cVer, cEco, cPurl string
		cDesc, cHome                  sql.NullString
		cVuln                         int
		cMeta                         []byte
		cCreated, cUpdated            time.Time
	)

	err := row.Scan(
		&adID, &adTenant, &adAsset, &adCompID, &adPath, &adType, &adManifest, &adParentID, &adDepth, &adCreated, &adUpdated,
		&cID, &cName, &cVer, &cEco, &cPurl, &cDesc, &cHome, &cVuln, &cMeta, &cCreated, &cUpdated,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, err
	}

	// Reconstitute Component
	cIDObj, _ := shared.IDFromString(cID)
	eco, _ := component.ParseEcosystem(cEco)
	var meta map[string]any
	if len(cMeta) > 0 {
		if err := json.Unmarshal(cMeta, &meta); err != nil {
			return nil, fmt.Errorf("failed to unmarshal component metadata: %w", err)
		}
	}

	// License is now stored in component_licenses table, pass empty string
	comp := component.Reconstitute(
		cIDObj, cName, cVer, eco, cPurl,
		"", cDesc.String, cHome.String,
		cVuln, meta, cCreated, cUpdated,
	)

	// Reconstitute AssetDependency
	adIDObj, _ := shared.IDFromString(adID)
	tIDObj, _ := shared.IDFromString(adTenant)
	aIDObj, _ := shared.IDFromString(adAsset)
	compIDObj, _ := shared.IDFromString(adCompID)
	depType, _ := component.ParseDependencyType(adType)

	var parentID *shared.ID
	if adParentID.Valid {
		pid, _ := shared.IDFromString(adParentID.String)
		parentID = &pid
	}

	dep := component.ReconstituteAssetDependency(
		adIDObj, tIDObj, aIDObj, compIDObj,
		adPath, depType, nullStringValue(adManifest),
		parentID, adDepth, adCreated, adUpdated,
	)

	dep.SetComponent(comp)
	return dep, nil
}

func (r *ComponentRepository) buildWhereClause(filter component.Filter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.Name != nil && *filter.Name != "" {
		conditions = append(conditions, fmt.Sprintf("name ILIKE $%d", argIndex))
		args = append(args, wrapLikePattern(*filter.Name))
		argIndex++
	}

	if filter.PURL != nil && *filter.PURL != "" {
		conditions = append(conditions, fmt.Sprintf("purl = $%d", argIndex))
		args = append(args, *filter.PURL)
		argIndex++
	}

	if len(filter.Ecosystems) > 0 {
		placeholders := make([]string, len(filter.Ecosystems))
		for i, eco := range filter.Ecosystems {
			placeholders[i] = fmt.Sprintf("$%d", argIndex)
			args = append(args, eco.String())
			argIndex++
		}
		conditions = append(conditions, fmt.Sprintf("ecosystem IN (%s)", strings.Join(placeholders, ", ")))
	}

	return strings.Join(conditions, " AND "), args
}

// GetStats returns aggregated component statistics for a tenant.
func (r *ComponentRepository) GetStats(ctx context.Context, tenantID shared.ID) (*component.ComponentStats, error) {
	// Main stats query - uses subqueries for tenant-isolated vulnerability counts
	// Note: vulnerable_components and total_vulnerabilities must be counted from findings table
	// because components.vulnerability_count is a global cache (not tenant-scoped)
	query := `
		SELECT
			COUNT(DISTINCT ac.component_id) as total_components,
			COUNT(DISTINCT ac.component_id) FILTER (WHERE ac.dependency_type = 'direct') as direct_dependencies,
			COUNT(DISTINCT ac.component_id) FILTER (WHERE ac.dependency_type = 'transitive') as transitive_dependencies,
			(
				SELECT COUNT(DISTINCT f.component_id)
				FROM findings f
				WHERE f.tenant_id = $1
				  AND f.component_id IS NOT NULL
				  AND f.status NOT IN ('resolved', 'false_positive')
			) as vulnerable_components,
			(
				SELECT COUNT(*)
				FROM findings f
				WHERE f.tenant_id = $1
				  AND f.component_id IS NOT NULL
				  AND f.status NOT IN ('resolved', 'false_positive')
			) as total_vulnerabilities,
			COUNT(DISTINCT ac.component_id) FILTER (WHERE ac.dependency_type IN ('deprecated', 'end_of_life')) as outdated_components
		FROM asset_components ac
		JOIN components c ON ac.component_id = c.id
		WHERE ac.tenant_id = $1
	`

	stats := &component.ComponentStats{
		VulnBySeverity: make(map[string]int),
		LicenseRisks:   make(map[string]int),
	}

	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(
		&stats.TotalComponents,
		&stats.DirectDependencies,
		&stats.TransitiveDependencies,
		&stats.VulnerableComponents,
		&stats.TotalVulnerabilities,
		&stats.OutdatedComponents,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get component stats: %w", err)
	}

	// Get vulnerability severity breakdown from findings
	// Note: findings.component_id now references components.id directly (not asset_components.id)
	severityQuery := `
		SELECT
			COALESCE(f.severity, 'unknown') as severity,
			COUNT(*) as count
		FROM findings f
		WHERE f.tenant_id = $1
		  AND f.status NOT IN ('resolved', 'false_positive')
		  AND f.component_id IS NOT NULL
		GROUP BY f.severity
	`
	severityRows, err := r.db.QueryContext(ctx, severityQuery, tenantID.String())
	if err != nil {
		// Non-critical, continue with zero values
		return stats, nil
	}
	defer severityRows.Close()

	for severityRows.Next() {
		var severity string
		var count int
		if err := severityRows.Scan(&severity, &count); err != nil {
			continue
		}
		stats.VulnBySeverity[severity] = count
	}

	if err := severityRows.Err(); err != nil {
		// Non-critical, continue with partial results
		_ = err
	}

	// Get CISA KEV component count
	// Note: cisa_kev_date_added IS NOT NULL indicates the vulnerability is in CISA KEV catalog
	// Note: findings.component_id now references components.id directly
	kevQuery := `
		SELECT COUNT(DISTINCT f.component_id)
		FROM findings f
		JOIN vulnerabilities v ON f.vulnerability_id = v.id
		WHERE f.tenant_id = $1
		  AND f.component_id IS NOT NULL
		  AND v.cisa_kev_date_added IS NOT NULL
		  AND f.status NOT IN ('resolved', 'false_positive')
	`
	_ = r.db.QueryRowContext(ctx, kevQuery, tenantID.String()).Scan(&stats.CisaKevComponents)

	// License risk breakdown from component_licenses → licenses
	licenseRiskQuery := `
		SELECT
			COALESCE(l.risk, 'unknown') as risk,
			COUNT(DISTINCT c.id) as count
		FROM asset_components ac
		JOIN components c ON ac.component_id = c.id
		LEFT JOIN component_licenses cl ON c.id = cl.component_id
		LEFT JOIN licenses l ON cl.license_id = l.id
		WHERE ac.tenant_id = $1
		GROUP BY l.risk
	`
	riskRows, err := r.db.QueryContext(ctx, licenseRiskQuery, tenantID.String())
	if err != nil {
		// Non-critical, return with zero values
		return stats, nil
	}
	defer riskRows.Close()

	for riskRows.Next() {
		var risk string
		var count int
		if err := riskRows.Scan(&risk, &count); err != nil {
			continue
		}
		stats.LicenseRisks[risk] = count
	}

	return stats, nil
}

// GetEcosystemStats returns per-ecosystem statistics for a tenant.
func (r *ComponentRepository) GetEcosystemStats(ctx context.Context, tenantID shared.ID) ([]component.EcosystemStats, error) {
	// Note: "outdated" is calculated based on dependency_type being deprecated/end_of_life
	// In a real scenario, this would check against latest available versions
	query := `
		SELECT
			c.ecosystem,
			COUNT(DISTINCT c.id) as total,
			COUNT(DISTINCT c.id) FILTER (WHERE c.vulnerability_count > 0) as vulnerable,
			COUNT(DISTINCT c.id) FILTER (WHERE ac.dependency_type IN ('deprecated', 'end_of_life')) as outdated
		FROM asset_components ac
		JOIN components c ON ac.component_id = c.id
		WHERE ac.tenant_id = $1
		GROUP BY c.ecosystem
		ORDER BY total DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get ecosystem stats: %w", err)
	}
	defer rows.Close()

	var stats []component.EcosystemStats
	for rows.Next() {
		var s component.EcosystemStats
		if err := rows.Scan(&s.Ecosystem, &s.Total, &s.Vulnerable, &s.Outdated); err != nil {
			return nil, fmt.Errorf("failed to scan ecosystem stats: %w", err)
		}
		// Add manifest file based on ecosystem
		eco, _ := component.ParseEcosystem(s.Ecosystem)
		s.ManifestFile = eco.ManifestFile()
		stats = append(stats, s)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return stats, nil
}

// GetVulnerableComponents returns components with vulnerability details for a tenant.
func (r *ComponentRepository) GetVulnerableComponents(ctx context.Context, tenantID shared.ID, limit int) ([]component.VulnerableComponent, error) {
	if limit <= 0 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	// Query to get vulnerable components with severity breakdown
	// Note: cisa_kev_date_added IS NOT NULL indicates the vulnerability is in CISA KEV catalog
	// Note: license is not stored in components table, return empty string
	// Note: findings.component_id now references components.id directly (not asset_components.id)
	query := `
		WITH component_findings AS (
			SELECT
				f.component_id,
				f.severity,
				(v.cisa_kev_date_added IS NOT NULL) as in_kev
			FROM findings f
			LEFT JOIN vulnerabilities v ON f.vulnerability_id = v.id
			WHERE f.tenant_id = $1
			  AND f.status NOT IN ('resolved', 'false_positive')
			  AND f.component_id IS NOT NULL
		)
		SELECT
			c.id,
			c.name,
			c.version,
			c.ecosystem,
			c.purl,
			'' as license,
			COUNT(*) FILTER (WHERE cf.severity = 'critical') as critical_count,
			COUNT(*) FILTER (WHERE cf.severity = 'high') as high_count,
			COUNT(*) FILTER (WHERE cf.severity = 'medium') as medium_count,
			COUNT(*) FILTER (WHERE cf.severity = 'low') as low_count,
			COUNT(*) as total_count,
			BOOL_OR(COALESCE(cf.in_kev, false)) as in_cisa_kev
		FROM components c
		JOIN component_findings cf ON c.id = cf.component_id
		GROUP BY c.id, c.name, c.version, c.ecosystem, c.purl
		ORDER BY
			COUNT(*) FILTER (WHERE cf.severity = 'critical') DESC,
			COUNT(*) FILTER (WHERE cf.severity = 'high') DESC,
			COUNT(*) DESC
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get vulnerable components: %w", err)
	}
	defer rows.Close()

	var components []component.VulnerableComponent
	for rows.Next() {
		var vc component.VulnerableComponent
		if err := rows.Scan(
			&vc.ID,
			&vc.Name,
			&vc.Version,
			&vc.Ecosystem,
			&vc.PURL,
			&vc.License,
			&vc.CriticalCount,
			&vc.HighCount,
			&vc.MediumCount,
			&vc.LowCount,
			&vc.TotalCount,
			&vc.InCisaKev,
		); err != nil {
			return nil, fmt.Errorf("failed to scan vulnerable component: %w", err)
		}
		components = append(components, vc)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return components, nil
}

// GetLicenseStats returns license statistics for a tenant.
func (r *ComponentRepository) GetLicenseStats(ctx context.Context, tenantID shared.ID) ([]component.LicenseStats, error) {
	// Query to get license distribution for tenant's components
	// Joins: asset_components -> components -> component_licenses -> licenses
	query := `
		SELECT
			l.spdx_id as license_id,
			l.name,
			COALESCE(l.category, 'unknown') as category,
			COALESCE(l.risk, 'unknown') as risk,
			l.url,
			COUNT(DISTINCT c.id) as count
		FROM asset_components ac
		JOIN components c ON ac.component_id = c.id
		JOIN component_licenses cl ON c.id = cl.component_id
		JOIN licenses l ON cl.license_id = l.id
		WHERE ac.tenant_id = $1
		GROUP BY l.spdx_id, l.name, l.category, l.risk, l.url
		ORDER BY count DESC, l.spdx_id
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get license stats: %w", err)
	}
	defer rows.Close()

	var stats []component.LicenseStats
	for rows.Next() {
		var s component.LicenseStats
		if err := rows.Scan(&s.LicenseID, &s.Name, &s.Category, &s.Risk, &s.URL, &s.Count); err != nil {
			return nil, fmt.Errorf("failed to scan license stats: %w", err)
		}
		stats = append(stats, s)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows iteration error: %w", err)
	}

	return stats, nil
}
