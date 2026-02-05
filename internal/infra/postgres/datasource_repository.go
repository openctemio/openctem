package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/datasource"
	"github.com/openctemio/api/pkg/domain/shared"
)

// DataSourceRepository implements datasource.Repository using PostgreSQL.
type DataSourceRepository struct {
	db *DB
}

// NewDataSourceRepository creates a new DataSourceRepository.
func NewDataSourceRepository(db *DB) *DataSourceRepository {
	return &DataSourceRepository{db: db}
}

// Ensure DataSourceRepository implements datasource.Repository
var _ datasource.Repository = (*DataSourceRepository)(nil)

// Create creates a new data source.
func (r *DataSourceRepository) Create(ctx context.Context, ds *datasource.DataSource) error {
	capabilities, err := json.Marshal(ds.Capabilities().Strings())
	if err != nil {
		return fmt.Errorf("marshal capabilities: %w", err)
	}

	config, err := json.Marshal(ds.Config())
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	metadata, err := json.Marshal(ds.Metadata())
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	var ipAddrStr sql.NullString
	if ds.IPAddress() != nil {
		ipAddrStr = sql.NullString{String: ds.IPAddress().String(), Valid: true}
	}

	query := `
		INSERT INTO data_sources (
			id, tenant_id, name, type, description,
			version, hostname, ip_address,
			api_key_hash, api_key_prefix, api_key_last_used_at,
			status, last_seen_at, last_error, error_count,
			capabilities, config, metadata,
			assets_collected, findings_reported,
			last_sync_at, last_sync_duration_ms, last_sync_assets_count, last_sync_findings_count,
			created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8,
			$9, $10, $11,
			$12, $13, $14, $15,
			$16, $17, $18,
			$19, $20,
			$21, $22, $23, $24,
			$25, $26
		)
	`

	_, err = r.db.ExecContext(ctx, query,
		ds.ID().String(),
		ds.TenantID().String(),
		ds.Name(),
		ds.Type().String(),
		nullString(ds.Description()),
		nullString(ds.Version()),
		nullString(ds.Hostname()),
		ipAddrStr,
		nullString(ds.APIKeyHash()),
		nullString(ds.APIKeyPrefix()),
		nullTime(ds.APIKeyLastUsedAt()),
		ds.Status().String(),
		nullTime(ds.LastSeenAt()),
		nullString(ds.LastError()),
		ds.ErrorCount(),
		capabilities,
		config,
		metadata,
		ds.AssetsCollected(),
		ds.FindingsReported(),
		nullTime(ds.LastSyncAt()),
		ds.LastSyncDurationMs(),
		ds.LastSyncAssets(),
		ds.LastSyncFindings(),
		ds.CreatedAt(),
		ds.UpdatedAt(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return datasource.AlreadyExistsError(ds.Name())
		}
		return fmt.Errorf("create data source: %w", err)
	}

	return nil
}

// GetByID retrieves a data source by ID.
func (r *DataSourceRepository) GetByID(ctx context.Context, id shared.ID) (*datasource.DataSource, error) {
	query := `
		SELECT id, tenant_id, name, type, description,
			   version, hostname, ip_address,
			   api_key_hash, api_key_prefix, api_key_last_used_at,
			   status, last_seen_at, last_error, error_count,
			   capabilities, config, metadata,
			   assets_collected, findings_reported,
			   last_sync_at, last_sync_duration_ms, last_sync_assets_count, last_sync_findings_count,
			   created_at, updated_at
		FROM data_sources
		WHERE id = $1
	`

	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanDataSource(row)
}

// GetByTenantAndName retrieves a data source by tenant ID and name.
func (r *DataSourceRepository) GetByTenantAndName(ctx context.Context, tenantID shared.ID, name string) (*datasource.DataSource, error) {
	query := `
		SELECT id, tenant_id, name, type, description,
			   version, hostname, ip_address,
			   api_key_hash, api_key_prefix, api_key_last_used_at,
			   status, last_seen_at, last_error, error_count,
			   capabilities, config, metadata,
			   assets_collected, findings_reported,
			   last_sync_at, last_sync_duration_ms, last_sync_assets_count, last_sync_findings_count,
			   created_at, updated_at
		FROM data_sources
		WHERE tenant_id = $1 AND name = $2
	`

	row := r.db.QueryRowContext(ctx, query, tenantID.String(), name)
	return r.scanDataSource(row)
}

// GetByAPIKeyPrefix retrieves a data source by API key prefix.
func (r *DataSourceRepository) GetByAPIKeyPrefix(ctx context.Context, prefix string) (*datasource.DataSource, error) {
	query := `
		SELECT id, tenant_id, name, type, description,
			   version, hostname, ip_address,
			   api_key_hash, api_key_prefix, api_key_last_used_at,
			   status, last_seen_at, last_error, error_count,
			   capabilities, config, metadata,
			   assets_collected, findings_reported,
			   last_sync_at, last_sync_duration_ms, last_sync_assets_count, last_sync_findings_count,
			   created_at, updated_at
		FROM data_sources
		WHERE api_key_prefix = $1
	`

	row := r.db.QueryRowContext(ctx, query, prefix)
	return r.scanDataSource(row)
}

// Update updates an existing data source.
func (r *DataSourceRepository) Update(ctx context.Context, ds *datasource.DataSource) error {
	capabilities, err := json.Marshal(ds.Capabilities().Strings())
	if err != nil {
		return fmt.Errorf("marshal capabilities: %w", err)
	}

	config, err := json.Marshal(ds.Config())
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	metadata, err := json.Marshal(ds.Metadata())
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}

	var ipAddrStr sql.NullString
	if ds.IPAddress() != nil {
		ipAddrStr = sql.NullString{String: ds.IPAddress().String(), Valid: true}
	}

	query := `
		UPDATE data_sources SET
			name = $2,
			description = $3,
			version = $4,
			hostname = $5,
			ip_address = $6,
			api_key_hash = $7,
			api_key_prefix = $8,
			api_key_last_used_at = $9,
			status = $10,
			last_seen_at = $11,
			last_error = $12,
			error_count = $13,
			capabilities = $14,
			config = $15,
			metadata = $16,
			assets_collected = $17,
			findings_reported = $18,
			last_sync_at = $19,
			last_sync_duration_ms = $20,
			last_sync_assets_count = $21,
			last_sync_findings_count = $22,
			updated_at = $23
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		ds.ID().String(),
		ds.Name(),
		nullString(ds.Description()),
		nullString(ds.Version()),
		nullString(ds.Hostname()),
		ipAddrStr,
		nullString(ds.APIKeyHash()),
		nullString(ds.APIKeyPrefix()),
		nullTime(ds.APIKeyLastUsedAt()),
		ds.Status().String(),
		nullTime(ds.LastSeenAt()),
		nullString(ds.LastError()),
		ds.ErrorCount(),
		capabilities,
		config,
		metadata,
		ds.AssetsCollected(),
		ds.FindingsReported(),
		nullTime(ds.LastSyncAt()),
		ds.LastSyncDurationMs(),
		ds.LastSyncAssets(),
		ds.LastSyncFindings(),
		ds.UpdatedAt(),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return datasource.AlreadyExistsError(ds.Name())
		}
		return fmt.Errorf("update data source: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return datasource.ErrDataSourceNotFound
	}

	return nil
}

// Delete deletes a data source by ID.
func (r *DataSourceRepository) Delete(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM data_sources WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("delete data source: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return datasource.ErrDataSourceNotFound
	}

	return nil
}

// List lists data sources with filtering and pagination.
func (r *DataSourceRepository) List(ctx context.Context, filter datasource.Filter, opts datasource.ListOptions) (datasource.ListResult, error) {
	result := datasource.ListResult{
		Data:    make([]*datasource.DataSource, 0),
		Page:    opts.Page,
		PerPage: opts.PerPage,
	}

	if opts.Page < 1 {
		opts.Page = 1
	}
	if opts.PerPage < 1 {
		opts.PerPage = 20
	}

	// Build query
	var conditions []string
	var args []any
	argIdx := 1

	if filter.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIdx))
		args = append(args, filter.TenantID)
		argIdx++
	}

	if filter.Type != "" {
		conditions = append(conditions, fmt.Sprintf("type = $%d", argIdx))
		args = append(args, filter.Type.String())
		argIdx++
	}

	if len(filter.Types) > 0 {
		placeholders := make([]string, len(filter.Types))
		for i, t := range filter.Types {
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			args = append(args, t.String())
			argIdx++
		}
		conditions = append(conditions, fmt.Sprintf("type IN (%s)", strings.Join(placeholders, ",")))
	}

	if filter.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, filter.Status.String())
		argIdx++
	}

	if len(filter.Statuses) > 0 {
		placeholders := make([]string, len(filter.Statuses))
		for i, s := range filter.Statuses {
			placeholders[i] = fmt.Sprintf("$%d", argIdx)
			args = append(args, s.String())
			argIdx++
		}
		conditions = append(conditions, fmt.Sprintf("status IN (%s)", strings.Join(placeholders, ",")))
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIdx, argIdx))
		args = append(args, wrapLikePattern(filter.Search))
		argIdx++
	}

	if len(filter.Capabilities) > 0 {
		// Check if capabilities array contains any of the specified capabilities
		for _, cap := range filter.Capabilities {
			conditions = append(conditions, fmt.Sprintf("capabilities @> $%d::jsonb", argIdx))
			capJSON, _ := json.Marshal([]string{cap.String()})
			args = append(args, string(capJSON))
			argIdx++
		}
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Get total count
	countQuery := "SELECT COUNT(*) FROM data_sources " + whereClause
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&result.Total)
	if err != nil {
		return result, fmt.Errorf("count data sources: %w", err)
	}

	// Calculate pagination
	result.TotalPages = int((result.Total + int64(opts.PerPage) - 1) / int64(opts.PerPage))

	// Build order clause
	orderBy := "created_at DESC"
	if opts.SortBy != "" {
		validSortFields := map[string]bool{
			"name":         true,
			"type":         true,
			"status":       true,
			"created_at":   true,
			"updated_at":   true,
			"last_seen_at": true,
		}
		if validSortFields[opts.SortBy] {
			order := sortOrderASC
			if opts.SortOrder == sortOrderDescLower {
				order = sortOrderDESC
			}
			orderBy = opts.SortBy + " " + order
		}
	}

	// Get data with pagination
	offset := (opts.Page - 1) * opts.PerPage
	args = append(args, opts.PerPage, offset)

	query := fmt.Sprintf(`
		SELECT id, tenant_id, name, type, description,
			   version, hostname, ip_address,
			   api_key_hash, api_key_prefix, api_key_last_used_at,
			   status, last_seen_at, last_error, error_count,
			   capabilities, config, metadata,
			   assets_collected, findings_reported,
			   last_sync_at, last_sync_duration_ms, last_sync_assets_count, last_sync_findings_count,
			   created_at, updated_at
		FROM data_sources
		%s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, whereClause, orderBy, argIdx, argIdx+1)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return result, fmt.Errorf("list data sources: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		ds, err := r.scanDataSourceRow(rows)
		if err != nil {
			return result, err
		}
		result.Data = append(result.Data, ds)
	}

	if err := rows.Err(); err != nil {
		return result, fmt.Errorf("iterate rows: %w", err)
	}

	return result, nil
}

// Count returns the total number of data sources matching the filter.
func (r *DataSourceRepository) Count(ctx context.Context, filter datasource.Filter) (int64, error) {
	var conditions []string
	var args []any
	argIdx := 1

	if filter.TenantID != "" {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIdx))
		args = append(args, filter.TenantID)
		argIdx++
	}

	if filter.Type != "" {
		conditions = append(conditions, fmt.Sprintf("type = $%d", argIdx))
		args = append(args, filter.Type.String())
		argIdx++
	}

	if filter.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, filter.Status.String())
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + strings.Join(conditions, " AND ")
	}

	query := "SELECT COUNT(*) FROM data_sources " + whereClause

	var count int64
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count data sources: %w", err)
	}

	return count, nil
}

// MarkStaleAsInactive marks data sources that haven't been seen recently as inactive.
func (r *DataSourceRepository) MarkStaleAsInactive(ctx context.Context, tenantID shared.ID, staleThresholdMinutes int) (int, error) {
	query := `
		UPDATE data_sources
		SET status = 'inactive', updated_at = NOW()
		WHERE tenant_id = $1
		  AND status = 'active'
		  AND last_seen_at < NOW() - ($2 || ' minutes')::INTERVAL
	`

	result, err := r.db.ExecContext(ctx, query, tenantID.String(), staleThresholdMinutes)
	if err != nil {
		return 0, fmt.Errorf("mark stale sources inactive: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected: %w", err)
	}

	return int(rowsAffected), nil
}

// GetActiveByTenant retrieves all active data sources for a tenant.
func (r *DataSourceRepository) GetActiveByTenant(ctx context.Context, tenantID shared.ID) ([]*datasource.DataSource, error) {
	query := `
		SELECT id, tenant_id, name, type, description,
			   version, hostname, ip_address,
			   api_key_hash, api_key_prefix, api_key_last_used_at,
			   status, last_seen_at, last_error, error_count,
			   capabilities, config, metadata,
			   assets_collected, findings_reported,
			   last_sync_at, last_sync_duration_ms, last_sync_assets_count, last_sync_findings_count,
			   created_at, updated_at
		FROM data_sources
		WHERE tenant_id = $1 AND status = 'active'
		ORDER BY name
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("get active data sources: %w", err)
	}
	defer rows.Close()

	var sources []*datasource.DataSource
	for rows.Next() {
		ds, err := r.scanDataSourceRow(rows)
		if err != nil {
			return nil, err
		}
		sources = append(sources, ds)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	return sources, nil
}

// scanDataSource scans a single row into a DataSource.
func (r *DataSourceRepository) scanDataSource(row *sql.Row) (*datasource.DataSource, error) {
	var (
		id                    string
		tenantID              string
		name                  string
		typ                   string
		description           sql.NullString
		version               sql.NullString
		hostname              sql.NullString
		ipAddress             sql.NullString
		apiKeyHash            sql.NullString
		apiKeyPrefix          sql.NullString
		apiKeyLastUsedAt      sql.NullTime
		status                string
		lastSeenAt            sql.NullTime
		lastError             sql.NullString
		errorCount            int
		capabilitiesJSON      []byte
		configJSON            []byte
		metadataJSON          []byte
		assetsCollected       int64
		findingsReported      int64
		lastSyncAt            sql.NullTime
		lastSyncDurationMs    int
		lastSyncAssetsCount   int
		lastSyncFindingsCount int
		createdAt             time.Time
		updatedAt             time.Time
	)

	err := row.Scan(
		&id, &tenantID, &name, &typ, &description,
		&version, &hostname, &ipAddress,
		&apiKeyHash, &apiKeyPrefix, &apiKeyLastUsedAt,
		&status, &lastSeenAt, &lastError, &errorCount,
		&capabilitiesJSON, &configJSON, &metadataJSON,
		&assetsCollected, &findingsReported,
		&lastSyncAt, &lastSyncDurationMs, &lastSyncAssetsCount, &lastSyncFindingsCount,
		&createdAt, &updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, datasource.ErrDataSourceNotFound
		}
		return nil, fmt.Errorf("scan data source: %w", err)
	}

	return r.reconstructDataSource(
		id, tenantID, name, typ, description,
		version, hostname, ipAddress,
		apiKeyHash, apiKeyPrefix, apiKeyLastUsedAt,
		status, lastSeenAt, lastError, errorCount,
		capabilitiesJSON, configJSON, metadataJSON,
		assetsCollected, findingsReported,
		lastSyncAt, lastSyncDurationMs, lastSyncAssetsCount, lastSyncFindingsCount,
		createdAt, updatedAt,
	)
}

// scanDataSourceRow scans a row from sql.Rows into a DataSource.
func (r *DataSourceRepository) scanDataSourceRow(rows *sql.Rows) (*datasource.DataSource, error) {
	var (
		id                    string
		tenantID              string
		name                  string
		typ                   string
		description           sql.NullString
		version               sql.NullString
		hostname              sql.NullString
		ipAddress             sql.NullString
		apiKeyHash            sql.NullString
		apiKeyPrefix          sql.NullString
		apiKeyLastUsedAt      sql.NullTime
		status                string
		lastSeenAt            sql.NullTime
		lastError             sql.NullString
		errorCount            int
		capabilitiesJSON      []byte
		configJSON            []byte
		metadataJSON          []byte
		assetsCollected       int64
		findingsReported      int64
		lastSyncAt            sql.NullTime
		lastSyncDurationMs    int
		lastSyncAssetsCount   int
		lastSyncFindingsCount int
		createdAt             time.Time
		updatedAt             time.Time
	)

	err := rows.Scan(
		&id, &tenantID, &name, &typ, &description,
		&version, &hostname, &ipAddress,
		&apiKeyHash, &apiKeyPrefix, &apiKeyLastUsedAt,
		&status, &lastSeenAt, &lastError, &errorCount,
		&capabilitiesJSON, &configJSON, &metadataJSON,
		&assetsCollected, &findingsReported,
		&lastSyncAt, &lastSyncDurationMs, &lastSyncAssetsCount, &lastSyncFindingsCount,
		&createdAt, &updatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("scan data source row: %w", err)
	}

	return r.reconstructDataSource(
		id, tenantID, name, typ, description,
		version, hostname, ipAddress,
		apiKeyHash, apiKeyPrefix, apiKeyLastUsedAt,
		status, lastSeenAt, lastError, errorCount,
		capabilitiesJSON, configJSON, metadataJSON,
		assetsCollected, findingsReported,
		lastSyncAt, lastSyncDurationMs, lastSyncAssetsCount, lastSyncFindingsCount,
		createdAt, updatedAt,
	)
}

// reconstructDataSource reconstructs a DataSource from scanned values.
func (r *DataSourceRepository) reconstructDataSource(
	id, tenantID, name, typ string,
	description, version, hostname, ipAddress sql.NullString,
	apiKeyHash, apiKeyPrefix sql.NullString,
	apiKeyLastUsedAt sql.NullTime,
	status string,
	lastSeenAt sql.NullTime,
	lastError sql.NullString,
	errorCount int,
	capabilitiesJSON, configJSON, metadataJSON []byte,
	assetsCollected, findingsReported int64,
	lastSyncAt sql.NullTime,
	lastSyncDurationMs, lastSyncAssetsCount, lastSyncFindingsCount int,
	createdAt, updatedAt time.Time,
) (*datasource.DataSource, error) {
	// Parse capabilities
	var capStrings []string
	if len(capabilitiesJSON) > 0 {
		if err := json.Unmarshal(capabilitiesJSON, &capStrings); err != nil {
			return nil, fmt.Errorf("unmarshal capabilities: %w", err)
		}
	}
	capabilities := datasource.ParseCapabilities(capStrings)

	// Parse config
	var config map[string]any
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &config); err != nil {
			return nil, fmt.Errorf("unmarshal config: %w", err)
		}
	}

	// Parse metadata
	var metadata map[string]any
	if len(metadataJSON) > 0 {
		if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
			return nil, fmt.Errorf("unmarshal metadata: %w", err)
		}
	}

	// Parse IP address
	var ip net.IP
	if ipAddress.Valid && ipAddress.String != "" {
		ip = net.ParseIP(ipAddress.String)
	}

	// Parse nullable times
	var lastSeen *time.Time
	if lastSeenAt.Valid {
		lastSeen = &lastSeenAt.Time
	}

	var apiKeyUsed *time.Time
	if apiKeyLastUsedAt.Valid {
		apiKeyUsed = &apiKeyLastUsedAt.Time
	}

	var lastSync *time.Time
	if lastSyncAt.Valid {
		lastSync = &lastSyncAt.Time
	}

	dsID, _ := shared.IDFromString(id)
	dsTenantID, _ := shared.IDFromString(tenantID)

	return datasource.Reconstruct(
		dsID,
		dsTenantID,
		name,
		datasource.SourceType(typ),
		description.String,
		version.String,
		hostname.String,
		ip,
		apiKeyHash.String,
		apiKeyPrefix.String,
		datasource.SourceStatus(status),
		lastSeen,
		lastError.String,
		errorCount,
		apiKeyUsed,
		capabilities,
		config,
		metadata,
		assetsCollected,
		findingsReported,
		lastSync,
		lastSyncDurationMs,
		lastSyncAssetsCount,
		lastSyncFindingsCount,
		createdAt,
		updatedAt,
	), nil
}
