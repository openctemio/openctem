package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// Security constants
const (
	// maxSearchLimit prevents DoS via expensive search queries
	maxSearchLimit = 500
)

// AssetServiceRepository implements asset.AssetServiceRepository using PostgreSQL.
type AssetServiceRepository struct {
	db *DB
}

// NewAssetServiceRepository creates a new AssetServiceRepository.
func NewAssetServiceRepository(db *DB) *AssetServiceRepository {
	return &AssetServiceRepository{db: db}
}

// =============================================================================
// Basic CRUD Operations
// =============================================================================

// Create persists a new asset service.
func (r *AssetServiceRepository) Create(ctx context.Context, service *asset.AssetService) error {
	query := `
		INSERT INTO asset_services (
			id, tenant_id, asset_id, name, protocol, port, service_type,
			product, version, banner, cpe,
			is_public, exposure, tls_enabled, tls_version,
			discovery_source, discovered_at, last_seen_at,
			finding_count, risk_score, state, state_changed_at,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
	`

	_, err := r.db.ExecContext(ctx, query,
		service.ID().String(),
		service.TenantID().String(),
		service.AssetID().String(),
		nullString(service.Name()),
		service.Protocol().String(),
		service.Port(),
		service.ServiceType().String(),
		nullString(service.Product()),
		nullString(service.Version()),
		nullString(service.Banner()),
		nullString(service.CPE()),
		service.IsPublic(),
		service.Exposure().String(),
		service.TLSEnabled(),
		nullString(service.TLSVersion()),
		nullString(service.DiscoverySource()),
		nullTime(service.DiscoveredAt()),
		nullTime(service.LastSeenAt()),
		service.FindingCount(),
		service.RiskScore(),
		service.State().String(),
		nullTime(service.StateChangedAt()),
		service.CreatedAt(),
		service.UpdatedAt(),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("service already exists for asset %s port %d/%s",
				service.AssetID(), service.Port(), service.Protocol())
		}
		return fmt.Errorf("failed to create asset service: %w", err)
	}

	return nil
}

// GetByID retrieves an asset service by its ID.
func (r *AssetServiceRepository) GetByID(ctx context.Context, tenantID, id shared.ID) (*asset.AssetService, error) {
	query := r.selectQuery() + " WHERE s.tenant_id = $1 AND s.id = $2"

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanService(row)
}

// Update updates an existing asset service.
func (r *AssetServiceRepository) Update(ctx context.Context, service *asset.AssetService) error {
	query := `
		UPDATE asset_services
		SET name = $3, product = $4, version = $5, banner = $6, cpe = $7,
		    is_public = $8, exposure = $9, tls_enabled = $10, tls_version = $11,
		    discovery_source = $12, discovered_at = $13, last_seen_at = $14,
		    finding_count = $15, risk_score = $16, state = $17, state_changed_at = $18,
		    updated_at = $19
		WHERE tenant_id = $1 AND id = $2
	`

	result, err := r.db.ExecContext(ctx, query,
		service.TenantID().String(),
		service.ID().String(),
		nullString(service.Name()),
		nullString(service.Product()),
		nullString(service.Version()),
		nullString(service.Banner()),
		nullString(service.CPE()),
		service.IsPublic(),
		service.Exposure().String(),
		service.TLSEnabled(),
		nullString(service.TLSVersion()),
		nullString(service.DiscoverySource()),
		nullTime(service.DiscoveredAt()),
		nullTime(service.LastSeenAt()),
		service.FindingCount(),
		service.RiskScore(),
		service.State().String(),
		nullTime(service.StateChangedAt()),
		service.UpdatedAt(),
	)

	if err != nil {
		return fmt.Errorf("failed to update asset service: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete removes an asset service by its ID.
func (r *AssetServiceRepository) Delete(ctx context.Context, tenantID, id shared.ID) error {
	query := `DELETE FROM asset_services WHERE tenant_id = $1 AND id = $2`

	result, err := r.db.ExecContext(ctx, query, tenantID.String(), id.String())
	if err != nil {
		return fmt.Errorf("failed to delete asset service: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// =============================================================================
// Query Operations
// =============================================================================

// GetByAssetID retrieves all services for an asset.
func (r *AssetServiceRepository) GetByAssetID(ctx context.Context, tenantID, assetID shared.ID) ([]*asset.AssetService, error) {
	query := r.selectQuery() + " WHERE s.tenant_id = $1 AND s.asset_id = $2 ORDER BY s.port ASC"

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), assetID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query services by asset: %w", err)
	}
	defer rows.Close()

	return r.scanServices(rows)
}

// GetByAssetAndPort retrieves a service by asset ID and port.
func (r *AssetServiceRepository) GetByAssetAndPort(ctx context.Context, tenantID, assetID shared.ID, port int, protocol asset.Protocol) (*asset.AssetService, error) {
	query := r.selectQuery() + " WHERE s.tenant_id = $1 AND s.asset_id = $2 AND s.port = $3 AND s.protocol = $4"

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), assetID.String(), port, protocol.String())
	return r.scanService(row)
}

// List retrieves services with filtering and pagination.
func (r *AssetServiceRepository) List(ctx context.Context, tenantID shared.ID, opts asset.ListAssetServicesOptions) ([]*asset.AssetService, int, error) {
	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM asset_services s"

	var conditions []string
	var args []interface{}
	argIdx := 1

	// Always filter by tenant
	conditions = append(conditions, fmt.Sprintf("s.tenant_id = $%d", argIdx))
	args = append(args, tenantID.String())
	argIdx++

	// Optional filters
	if opts.AssetID != nil {
		conditions = append(conditions, fmt.Sprintf("s.asset_id = $%d", argIdx))
		args = append(args, opts.AssetID.String())
		argIdx++
	}

	if opts.ServiceType != nil {
		conditions = append(conditions, fmt.Sprintf("s.service_type = $%d", argIdx))
		args = append(args, opts.ServiceType.String())
		argIdx++
	}

	if opts.State != nil {
		conditions = append(conditions, fmt.Sprintf("s.state = $%d", argIdx))
		args = append(args, opts.State.String())
		argIdx++
	}

	if opts.IsPublic != nil {
		conditions = append(conditions, fmt.Sprintf("s.is_public = $%d", argIdx))
		args = append(args, *opts.IsPublic)
		argIdx++
	}

	if opts.Port != nil {
		conditions = append(conditions, fmt.Sprintf("s.port = $%d", argIdx))
		args = append(args, *opts.Port)
		argIdx++
	}

	if opts.Product != nil {
		conditions = append(conditions, fmt.Sprintf("s.product ILIKE $%d", argIdx))
		// Escape LIKE special characters to prevent pattern injection
		args = append(args, "%"+escapeLikePattern(*opts.Product)+"%")
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	var total int
	err := r.db.QueryRowContext(ctx, countQuery+whereClause, args...).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count services: %w", err)
	}

	// Sorting
	sortBy := "port"
	if opts.SortBy != "" {
		allowedSorts := map[string]string{
			"port":         "s.port",
			"service_type": "s.service_type",
			"risk_score":   "s.risk_score",
			"last_seen_at": "s.last_seen_at",
			"created_at":   "s.created_at",
		}
		if col, ok := allowedSorts[opts.SortBy]; ok {
			sortBy = col
		}
	}

	sortOrder := sortOrderASC
	if opts.SortOrder == "desc" {
		sortOrder = sortOrderDESC
	}

	// Build final query
	query := baseQuery + whereClause + fmt.Sprintf(" ORDER BY %s %s", sortBy, sortOrder)

	// Pagination
	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, opts.Limit)
		argIdx++
	}
	if opts.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, opts.Offset)
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query services: %w", err)
	}
	defer rows.Close()

	services, err := r.scanServices(rows)
	if err != nil {
		return nil, 0, err
	}

	return services, total, nil
}

// ListPublic retrieves all public (internet-exposed) services for a tenant.
func (r *AssetServiceRepository) ListPublic(ctx context.Context, tenantID shared.ID, limit, offset int) ([]*asset.AssetService, int, error) {
	isPublic := true
	opts := asset.ListAssetServicesOptions{
		IsPublic:  &isPublic,
		Limit:     limit,
		Offset:    offset,
		SortBy:    "risk_score",
		SortOrder: "desc",
	}
	return r.List(ctx, tenantID, opts)
}

// ListByServiceType retrieves services of a specific type.
func (r *AssetServiceRepository) ListByServiceType(ctx context.Context, tenantID shared.ID, serviceType asset.ServiceType, limit, offset int) ([]*asset.AssetService, int, error) {
	opts := asset.ListAssetServicesOptions{
		ServiceType: &serviceType,
		Limit:       limit,
		Offset:      offset,
		SortBy:      "port",
		SortOrder:   "asc",
	}
	return r.List(ctx, tenantID, opts)
}

// ListHighRisk retrieves services with risk score above threshold.
func (r *AssetServiceRepository) ListHighRisk(ctx context.Context, tenantID shared.ID, minRiskScore int, limit, offset int) ([]*asset.AssetService, int, error) {
	query := r.selectQuery() + " WHERE s.tenant_id = $1 AND s.risk_score >= $2 ORDER BY s.risk_score DESC"
	countQuery := "SELECT COUNT(*) FROM asset_services s WHERE s.tenant_id = $1 AND s.risk_score >= $2"

	var total int
	err := r.db.QueryRowContext(ctx, countQuery, tenantID.String(), minRiskScore).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count high risk services: %w", err)
	}

	finalQuery := query
	args := []interface{}{tenantID.String(), minRiskScore}
	if limit > 0 {
		finalQuery += " LIMIT $3"
		args = append(args, limit)
	}
	if offset > 0 {
		finalQuery += " OFFSET $4"
		args = append(args, offset)
	}

	rows, err := r.db.QueryContext(ctx, finalQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query high risk services: %w", err)
	}
	defer rows.Close()

	services, err := r.scanServices(rows)
	if err != nil {
		return nil, 0, err
	}

	return services, total, nil
}

// =============================================================================
// Batch Operations
// =============================================================================

// UpsertBatch creates or updates multiple services in a single operation.
func (r *AssetServiceRepository) UpsertBatch(ctx context.Context, services []*asset.AssetService) (created int, updated int, err error) {
	if len(services) == 0 {
		return 0, 0, nil
	}

	query := `
		INSERT INTO asset_services (
			id, tenant_id, asset_id, name, protocol, port, service_type,
			product, version, banner, cpe,
			is_public, exposure, tls_enabled, tls_version,
			discovery_source, discovered_at, last_seen_at,
			finding_count, risk_score, state, state_changed_at,
			created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
		ON CONFLICT (tenant_id, asset_id, port, protocol)
		DO UPDATE SET
			name = EXCLUDED.name,
			service_type = EXCLUDED.service_type,
			product = EXCLUDED.product,
			version = EXCLUDED.version,
			banner = EXCLUDED.banner,
			cpe = EXCLUDED.cpe,
			is_public = EXCLUDED.is_public,
			exposure = EXCLUDED.exposure,
			tls_enabled = EXCLUDED.tls_enabled,
			tls_version = EXCLUDED.tls_version,
			last_seen_at = EXCLUDED.last_seen_at,
			state = EXCLUDED.state,
			state_changed_at = EXCLUDED.state_changed_at,
			updated_at = EXCLUDED.updated_at
		RETURNING (xmax = 0) AS inserted
	`

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, service := range services {
		var inserted bool
		err := stmt.QueryRowContext(ctx,
			service.ID().String(),
			service.TenantID().String(),
			service.AssetID().String(),
			nullString(service.Name()),
			service.Protocol().String(),
			service.Port(),
			service.ServiceType().String(),
			nullString(service.Product()),
			nullString(service.Version()),
			nullString(service.Banner()),
			nullString(service.CPE()),
			service.IsPublic(),
			service.Exposure().String(),
			service.TLSEnabled(),
			nullString(service.TLSVersion()),
			nullString(service.DiscoverySource()),
			nullTime(service.DiscoveredAt()),
			nullTime(service.LastSeenAt()),
			service.FindingCount(),
			service.RiskScore(),
			service.State().String(),
			nullTime(service.StateChangedAt()),
			service.CreatedAt(),
			service.UpdatedAt(),
		).Scan(&inserted)

		if err != nil {
			return created, updated, fmt.Errorf("failed to upsert service: %w", err)
		}

		if inserted {
			created++
		} else {
			updated++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return created, updated, nil
}

// DeleteByAssetID removes all services for an asset.
func (r *AssetServiceRepository) DeleteByAssetID(ctx context.Context, tenantID, assetID shared.ID) error {
	query := `DELETE FROM asset_services WHERE tenant_id = $1 AND asset_id = $2`

	_, err := r.db.ExecContext(ctx, query, tenantID.String(), assetID.String())
	if err != nil {
		return fmt.Errorf("failed to delete services by asset: %w", err)
	}

	return nil
}

// UpdateFindingCounts updates finding counts for multiple services.
func (r *AssetServiceRepository) UpdateFindingCounts(ctx context.Context, counts map[shared.ID]int) error {
	if len(counts) == 0 {
		return nil
	}

	query := `UPDATE asset_services SET finding_count = $2, updated_at = NOW() WHERE id = $1`

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for id, count := range counts {
		_, err := stmt.ExecContext(ctx, id.String(), count)
		if err != nil {
			return fmt.Errorf("failed to update finding count for service %s: %w", id, err)
		}
	}

	return tx.Commit()
}

// =============================================================================
// Statistics & Aggregations
// =============================================================================

// CountByTenant returns the total number of services for a tenant.
func (r *AssetServiceRepository) CountByTenant(ctx context.Context, tenantID shared.ID) (int64, error) {
	query := `SELECT COUNT(*) FROM asset_services WHERE tenant_id = $1`

	var count int64
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count services: %w", err)
	}

	return count, nil
}

// CountByAsset returns the number of services for an asset.
func (r *AssetServiceRepository) CountByAsset(ctx context.Context, tenantID, assetID shared.ID) (int, error) {
	query := `SELECT COUNT(*) FROM asset_services WHERE tenant_id = $1 AND asset_id = $2`

	var count int
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), assetID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count services for asset: %w", err)
	}

	return count, nil
}

// CountPublic returns the number of public services for a tenant.
func (r *AssetServiceRepository) CountPublic(ctx context.Context, tenantID shared.ID) (int64, error) {
	query := `SELECT COUNT(*) FROM asset_services WHERE tenant_id = $1 AND is_public = true`

	var count int64
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count public services: %w", err)
	}

	return count, nil
}

// GetServiceTypeCounts returns count of services grouped by service type.
func (r *AssetServiceRepository) GetServiceTypeCounts(ctx context.Context, tenantID shared.ID) (map[asset.ServiceType]int, error) {
	query := `
		SELECT service_type, COUNT(*) as count
		FROM asset_services
		WHERE tenant_id = $1
		GROUP BY service_type
		ORDER BY count DESC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get service type counts: %w", err)
	}
	defer rows.Close()

	result := make(map[asset.ServiceType]int)
	for rows.Next() {
		var serviceType string
		var count int
		if err := rows.Scan(&serviceType, &count); err != nil {
			return nil, fmt.Errorf("failed to scan service type count: %w", err)
		}
		result[asset.ServiceType(serviceType)] = count
	}

	return result, rows.Err()
}

// GetPortCounts returns count of services grouped by port (top N).
func (r *AssetServiceRepository) GetPortCounts(ctx context.Context, tenantID shared.ID, topN int) (map[int]int, error) {
	query := `
		SELECT port, COUNT(*) as count
		FROM asset_services
		WHERE tenant_id = $1
		GROUP BY port
		ORDER BY count DESC
		LIMIT $2
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), topN)
	if err != nil {
		return nil, fmt.Errorf("failed to get port counts: %w", err)
	}
	defer rows.Close()

	result := make(map[int]int)
	for rows.Next() {
		var port, count int
		if err := rows.Scan(&port, &count); err != nil {
			return nil, fmt.Errorf("failed to scan port count: %w", err)
		}
		result[port] = count
	}

	return result, rows.Err()
}

// =============================================================================
// Search Operations
// =============================================================================

// SearchByProduct searches services by product name (partial match).
func (r *AssetServiceRepository) SearchByProduct(ctx context.Context, tenantID shared.ID, product string, limit int) ([]*asset.AssetService, error) {
	// Enforce max limit to prevent DoS
	if limit <= 0 || limit > maxSearchLimit {
		limit = maxSearchLimit
	}

	query := r.selectQuery() + " WHERE s.tenant_id = $1 AND s.product ILIKE $2 ORDER BY s.product LIMIT $3"

	// Escape LIKE special characters to prevent pattern injection
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), "%"+escapeLikePattern(product)+"%", limit)
	if err != nil {
		return nil, fmt.Errorf("failed to search by product: %w", err)
	}
	defer rows.Close()

	return r.scanServices(rows)
}

// SearchByVersion searches services by version (partial match).
func (r *AssetServiceRepository) SearchByVersion(ctx context.Context, tenantID shared.ID, version string, limit int) ([]*asset.AssetService, error) {
	// Enforce max limit to prevent DoS
	if limit <= 0 || limit > maxSearchLimit {
		limit = maxSearchLimit
	}

	query := r.selectQuery() + " WHERE s.tenant_id = $1 AND s.version ILIKE $2 ORDER BY s.version LIMIT $3"

	// Escape LIKE special characters to prevent pattern injection
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), "%"+escapeLikePattern(version)+"%", limit)
	if err != nil {
		return nil, fmt.Errorf("failed to search by version: %w", err)
	}
	defer rows.Close()

	return r.scanServices(rows)
}

// SearchByCPE searches services by CPE (partial match).
func (r *AssetServiceRepository) SearchByCPE(ctx context.Context, tenantID shared.ID, cpe string, limit int) ([]*asset.AssetService, error) {
	// Enforce max limit to prevent DoS
	if limit <= 0 || limit > maxSearchLimit {
		limit = maxSearchLimit
	}

	query := r.selectQuery() + " WHERE s.tenant_id = $1 AND s.cpe ILIKE $2 ORDER BY s.cpe LIMIT $3"

	// Escape LIKE special characters to prevent pattern injection
	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), "%"+escapeLikePattern(cpe)+"%", limit)
	if err != nil {
		return nil, fmt.Errorf("failed to search by CPE: %w", err)
	}
	defer rows.Close()

	return r.scanServices(rows)
}

// =============================================================================
// Helper Methods
// =============================================================================

func (r *AssetServiceRepository) selectQuery() string {
	return `
		SELECT
			s.id, s.tenant_id, s.asset_id,
			s.name, s.protocol, s.port, s.service_type,
			s.product, s.version, s.banner, s.cpe,
			s.is_public, s.exposure, s.tls_enabled, s.tls_version,
			s.discovery_source, s.discovered_at, s.last_seen_at,
			s.finding_count, s.risk_score, s.state, s.state_changed_at,
			s.created_at, s.updated_at
		FROM asset_services s
	`
}

func (r *AssetServiceRepository) scanService(row *sql.Row) (*asset.AssetService, error) {
	var (
		id, tenantID, assetID         string
		name, protocol, serviceType   string
		port                          int
		product, version, banner, cpe sql.NullString
		isPublic                      bool
		exposure                      string
		tlsEnabled                    bool
		tlsVersion                    sql.NullString
		discoverySource               sql.NullString
		discoveredAt, lastSeenAt      sql.NullTime
		findingCount, riskScore       int
		state                         string
		stateChangedAt                sql.NullTime
		createdAt, updatedAt          time.Time
	)

	err := row.Scan(
		&id, &tenantID, &assetID,
		&name, &protocol, &port, &serviceType,
		&product, &version, &banner, &cpe,
		&isPublic, &exposure, &tlsEnabled, &tlsVersion,
		&discoverySource, &discoveredAt, &lastSeenAt,
		&findingCount, &riskScore, &state, &stateChangedAt,
		&createdAt, &updatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan service: %w", err)
	}

	return r.reconstituteService(
		id, tenantID, assetID,
		name, protocol, port, serviceType,
		product, version, banner, cpe,
		isPublic, exposure, tlsEnabled, tlsVersion,
		discoverySource, discoveredAt, lastSeenAt,
		findingCount, riskScore, state, stateChangedAt,
		createdAt, updatedAt,
	), nil
}

func (r *AssetServiceRepository) scanServices(rows *sql.Rows) ([]*asset.AssetService, error) {
	var services []*asset.AssetService

	for rows.Next() {
		var (
			id, tenantID, assetID         string
			name, protocol, serviceType   string
			port                          int
			product, version, banner, cpe sql.NullString
			isPublic                      bool
			exposure                      string
			tlsEnabled                    bool
			tlsVersion                    sql.NullString
			discoverySource               sql.NullString
			discoveredAt, lastSeenAt      sql.NullTime
			findingCount, riskScore       int
			state                         string
			stateChangedAt                sql.NullTime
			createdAt, updatedAt          time.Time
		)

		err := rows.Scan(
			&id, &tenantID, &assetID,
			&name, &protocol, &port, &serviceType,
			&product, &version, &banner, &cpe,
			&isPublic, &exposure, &tlsEnabled, &tlsVersion,
			&discoverySource, &discoveredAt, &lastSeenAt,
			&findingCount, &riskScore, &state, &stateChangedAt,
			&createdAt, &updatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan service row: %w", err)
		}

		service := r.reconstituteService(
			id, tenantID, assetID,
			name, protocol, port, serviceType,
			product, version, banner, cpe,
			isPublic, exposure, tlsEnabled, tlsVersion,
			discoverySource, discoveredAt, lastSeenAt,
			findingCount, riskScore, state, stateChangedAt,
			createdAt, updatedAt,
		)
		services = append(services, service)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating service rows: %w", err)
	}

	return services, nil
}

func (r *AssetServiceRepository) reconstituteService(
	id, tenantID, assetID string,
	name, protocol string, port int, serviceType string,
	product, version, banner, cpe sql.NullString,
	isPublic bool, exposure string, tlsEnabled bool, tlsVersion sql.NullString,
	discoverySource sql.NullString, discoveredAt, lastSeenAt sql.NullTime,
	findingCount, riskScore int, state string, stateChangedAt sql.NullTime,
	createdAt, updatedAt time.Time,
) *asset.AssetService {
	var discoveredAtPtr, lastSeenAtPtr, stateChangedAtPtr *time.Time
	if discoveredAt.Valid {
		discoveredAtPtr = &discoveredAt.Time
	}
	if lastSeenAt.Valid {
		lastSeenAtPtr = &lastSeenAt.Time
	}
	if stateChangedAt.Valid {
		stateChangedAtPtr = &stateChangedAt.Time
	}

	parsedID, _ := shared.IDFromString(id)
	parsedTenantID, _ := shared.IDFromString(tenantID)
	parsedAssetID, _ := shared.IDFromString(assetID)

	return asset.ReconstituteAssetService(
		parsedID,
		parsedTenantID,
		parsedAssetID,
		name,
		asset.Protocol(protocol),
		port,
		asset.ServiceType(serviceType),
		nullStringValue(product),
		nullStringValue(version),
		nullStringValue(banner),
		nullStringValue(cpe),
		isPublic,
		asset.Exposure(exposure),
		tlsEnabled,
		nullStringValue(tlsVersion),
		nullStringValue(discoverySource),
		discoveredAtPtr,
		lastSeenAtPtr,
		findingCount,
		riskScore,
		asset.ServiceState(state),
		stateChangedAtPtr,
		createdAt,
		updatedAt,
	)
}
