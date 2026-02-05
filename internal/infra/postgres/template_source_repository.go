package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/scannertemplate"
	"github.com/openctemio/api/pkg/domain/shared"
	ts "github.com/openctemio/api/pkg/domain/templatesource"
	"github.com/openctemio/api/pkg/pagination"
)

// jsonNull is the string representation of JSON null value.
const jsonNull = "null"

// TemplateSourceRepository implements template_source.Repository using PostgreSQL.
type TemplateSourceRepository struct {
	db *DB
}

// NewTemplateSourceRepository creates a new TemplateSourceRepository.
func NewTemplateSourceRepository(db *DB) *TemplateSourceRepository {
	return &TemplateSourceRepository{db: db}
}

// Create persists a new template source.
func (r *TemplateSourceRepository) Create(ctx context.Context, s *ts.TemplateSource) error {
	gitConfig, err := json.Marshal(s.GitConfig)
	if err != nil && s.GitConfig != nil {
		return fmt.Errorf("failed to marshal git config: %w", err)
	}
	s3Config, err := json.Marshal(s.S3Config)
	if err != nil && s.S3Config != nil {
		return fmt.Errorf("failed to marshal s3 config: %w", err)
	}
	httpConfig, err := json.Marshal(s.HTTPConfig)
	if err != nil && s.HTTPConfig != nil {
		return fmt.Errorf("failed to marshal http config: %w", err)
	}

	query := `
		INSERT INTO template_sources (
			id, tenant_id, name, source_type, template_type, description, enabled,
			git_config, s3_config, http_config,
			auto_sync_on_scan, cache_ttl_minutes,
			last_sync_at, last_sync_hash, last_sync_status, last_sync_error,
			total_templates, last_sync_count,
			credential_id, created_by, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22)
	`

	var credentialID, createdBy, lastSyncError sql.NullString
	var lastSyncAt sql.NullTime

	if s.CredentialID != nil {
		credentialID = sql.NullString{String: s.CredentialID.String(), Valid: true}
	}
	if s.CreatedBy != nil {
		createdBy = sql.NullString{String: s.CreatedBy.String(), Valid: true}
	}
	if s.LastSyncError != nil {
		lastSyncError = sql.NullString{String: *s.LastSyncError, Valid: true}
	}
	if s.LastSyncAt != nil {
		lastSyncAt = sql.NullTime{Time: *s.LastSyncAt, Valid: true}
	}

	// Handle nil configs
	var gitConfigJSON, s3ConfigJSON, httpConfigJSON []byte
	if s.GitConfig != nil {
		gitConfigJSON = gitConfig
	}
	if s.S3Config != nil {
		s3ConfigJSON = s3Config
	}
	if s.HTTPConfig != nil {
		httpConfigJSON = httpConfig
	}

	_, err = r.db.ExecContext(ctx, query,
		s.ID.String(),
		s.TenantID.String(),
		s.Name,
		string(s.SourceType),
		string(s.TemplateType),
		s.Description,
		s.Enabled,
		nullBytes(gitConfigJSON),
		nullBytes(s3ConfigJSON),
		nullBytes(httpConfigJSON),
		s.AutoSyncOnScan,
		s.CacheTTLMinutes,
		lastSyncAt,
		s.LastSyncHash,
		string(s.LastSyncStatus),
		lastSyncError,
		s.TotalTemplates,
		s.LastSyncCount,
		credentialID,
		createdBy,
		s.CreatedAt,
		s.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "template source with this name already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create template source: %w", err)
	}

	return nil
}

// GetByID retrieves a template source by ID.
func (r *TemplateSourceRepository) GetByID(ctx context.Context, id shared.ID) (*ts.TemplateSource, error) {
	query := `
		SELECT id, tenant_id, name, source_type, template_type, description, enabled,
			git_config, s3_config, http_config,
			auto_sync_on_scan, cache_ttl_minutes,
			last_sync_at, last_sync_hash, last_sync_status, last_sync_error,
			total_templates, last_sync_count,
			credential_id, created_by, created_at, updated_at
		FROM template_sources
		WHERE id = $1
	`

	source, err := r.scanSource(r.db.QueryRowContext(ctx, query, id.String()))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.NewDomainError("NOT_FOUND", "template source not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get template source: %w", err)
	}

	return source, nil
}

// GetByTenantAndName retrieves a template source by tenant and name.
func (r *TemplateSourceRepository) GetByTenantAndName(ctx context.Context, tenantID shared.ID, name string) (*ts.TemplateSource, error) {
	query := `
		SELECT id, tenant_id, name, source_type, template_type, description, enabled,
			git_config, s3_config, http_config,
			auto_sync_on_scan, cache_ttl_minutes,
			last_sync_at, last_sync_hash, last_sync_status, last_sync_error,
			total_templates, last_sync_count,
			credential_id, created_by, created_at, updated_at
		FROM template_sources
		WHERE tenant_id = $1 AND name = $2
	`

	source, err := r.scanSource(r.db.QueryRowContext(ctx, query, tenantID.String(), name))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.NewDomainError("NOT_FOUND", "template source not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get template source: %w", err)
	}

	return source, nil
}

// List lists template sources with pagination and filtering.
func (r *TemplateSourceRepository) List(ctx context.Context, input ts.ListInput) (*ts.ListOutput, error) {
	baseQuery := `
		SELECT id, tenant_id, name, source_type, template_type, description, enabled,
			git_config, s3_config, http_config,
			auto_sync_on_scan, cache_ttl_minutes,
			last_sync_at, last_sync_hash, last_sync_status, last_sync_error,
			total_templates, last_sync_count,
			credential_id, created_by, created_at, updated_at
		FROM template_sources
	`
	countQuery := `SELECT COUNT(*) FROM template_sources`

	var conditions []string
	var args []any
	argIdx := 1

	// Tenant filter (required)
	conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIdx))
	args = append(args, input.TenantID.String())
	argIdx++

	// Source type filter
	if input.SourceType != nil {
		conditions = append(conditions, fmt.Sprintf("source_type = $%d", argIdx))
		args = append(args, string(*input.SourceType))
		argIdx++
	}

	// Template type filter
	if input.TemplateType != nil {
		conditions = append(conditions, fmt.Sprintf("template_type = $%d", argIdx))
		args = append(args, string(*input.TemplateType))
		argIdx++
	}

	// Enabled filter
	if input.Enabled != nil {
		conditions = append(conditions, fmt.Sprintf("enabled = $%d", argIdx))
		args = append(args, *input.Enabled)
		argIdx++
	}

	whereClause := " WHERE " + strings.Join(conditions, " AND ")
	baseQuery += whereClause
	countQuery += whereClause

	// Get total count
	var totalCount int
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&totalCount); err != nil {
		return nil, fmt.Errorf("failed to count template sources: %w", err)
	}

	// Sorting
	sortBy := "created_at"
	if input.SortBy != "" {
		switch input.SortBy {
		case "name", "source_type", "template_type", "created_at", "updated_at", "last_sync_at":
			sortBy = input.SortBy
		}
	}
	sortOrder := sortOrderDESC
	if input.SortOrder == sortOrderAscLower {
		sortOrder = sortOrderASC
	}
	baseQuery += fmt.Sprintf(" ORDER BY %s %s", sortBy, sortOrder)

	// Pagination
	p := pagination.New(input.Page, input.PageSize)
	baseQuery += fmt.Sprintf(" LIMIT %d OFFSET %d", p.Limit(), p.Offset())

	// Execute query
	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list template sources: %w", err)
	}
	defer rows.Close()

	var sources []*ts.TemplateSource
	for rows.Next() {
		source, err := r.scanSourceRow(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan template source: %w", err)
		}
		sources = append(sources, source)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate template sources: %w", err)
	}

	return &ts.ListOutput{
		Items:      sources,
		TotalCount: totalCount,
	}, nil
}

// ListByTenantAndTemplateType lists sources for a tenant and template type.
func (r *TemplateSourceRepository) ListByTenantAndTemplateType(ctx context.Context, tenantID shared.ID, templateType scannertemplate.TemplateType) ([]*ts.TemplateSource, error) {
	query := `
		SELECT id, tenant_id, name, source_type, template_type, description, enabled,
			git_config, s3_config, http_config,
			auto_sync_on_scan, cache_ttl_minutes,
			last_sync_at, last_sync_hash, last_sync_status, last_sync_error,
			total_templates, last_sync_count,
			credential_id, created_by, created_at, updated_at
		FROM template_sources
		WHERE tenant_id = $1 AND template_type = $2 AND enabled = true
		ORDER BY name ASC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String(), string(templateType))
	if err != nil {
		return nil, fmt.Errorf("failed to list template sources: %w", err)
	}
	defer rows.Close()

	var sources []*ts.TemplateSource
	for rows.Next() {
		source, err := r.scanSourceRow(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan template source: %w", err)
		}
		sources = append(sources, source)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate template sources: %w", err)
	}

	return sources, nil
}

// ListEnabledForSync lists enabled sources that need syncing for a tenant.
func (r *TemplateSourceRepository) ListEnabledForSync(ctx context.Context, tenantID shared.ID) ([]*ts.TemplateSource, error) {
	query := `
		SELECT id, tenant_id, name, source_type, template_type, description, enabled,
			git_config, s3_config, http_config,
			auto_sync_on_scan, cache_ttl_minutes,
			last_sync_at, last_sync_hash, last_sync_status, last_sync_error,
			total_templates, last_sync_count,
			credential_id, created_by, created_at, updated_at
		FROM template_sources
		WHERE tenant_id = $1 AND enabled = true AND auto_sync_on_scan = true
		ORDER BY name ASC
	`

	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list template sources: %w", err)
	}
	defer rows.Close()

	var sources []*ts.TemplateSource
	for rows.Next() {
		source, err := r.scanSourceRow(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan template source: %w", err)
		}
		sources = append(sources, source)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate template sources: %w", err)
	}

	return sources, nil
}

// ListAllNeedingSync lists all enabled sources across all tenants that need syncing.
// A source needs sync if:
// - It is enabled
// - auto_sync_on_scan is true (background sync enabled)
// - Either never synced OR cache has expired (last_sync_at + cache_ttl_minutes < now)
// - Not currently syncing (last_sync_status != 'in_progress')
func (r *TemplateSourceRepository) ListAllNeedingSync(ctx context.Context) ([]*ts.TemplateSource, error) {
	query := `
		SELECT id, tenant_id, name, source_type, template_type, description, enabled,
			git_config, s3_config, http_config,
			auto_sync_on_scan, cache_ttl_minutes,
			last_sync_at, last_sync_hash, last_sync_status, last_sync_error,
			total_templates, last_sync_count,
			credential_id, created_by, created_at, updated_at
		FROM template_sources
		WHERE enabled = true
			AND auto_sync_on_scan = true
			AND (last_sync_status IS NULL OR last_sync_status != 'in_progress')
			AND (
				last_sync_at IS NULL
				OR (last_sync_at + (cache_ttl_minutes || ' minutes')::interval) < NOW()
			)
		ORDER BY
			CASE WHEN last_sync_at IS NULL THEN 0 ELSE 1 END,
			last_sync_at ASC
		LIMIT 100
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list sources needing sync: %w", err)
	}
	defer rows.Close()

	var sources []*ts.TemplateSource
	for rows.Next() {
		source, err := r.scanSourceRow(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan template source: %w", err)
		}
		sources = append(sources, source)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate template sources: %w", err)
	}

	return sources, nil
}

// GetByTenantAndID retrieves a template source by tenant ID and source ID.
func (r *TemplateSourceRepository) GetByTenantAndID(ctx context.Context, tenantID, sourceID shared.ID) (*ts.TemplateSource, error) {
	query := `
		SELECT id, tenant_id, name, source_type, template_type, description, enabled,
			git_config, s3_config, http_config,
			auto_sync_on_scan, cache_ttl_minutes,
			last_sync_at, last_sync_hash, last_sync_status, last_sync_error,
			total_templates, last_sync_count,
			credential_id, created_by, created_at, updated_at
		FROM template_sources
		WHERE id = $1 AND tenant_id = $2
	`

	source, err := r.scanSource(r.db.QueryRowContext(ctx, query, sourceID.String(), tenantID.String()))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.NewDomainError("NOT_FOUND", "template source not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get template source: %w", err)
	}

	return source, nil
}

// Update updates a template source.
func (r *TemplateSourceRepository) Update(ctx context.Context, s *ts.TemplateSource) error {
	gitConfig, err := json.Marshal(s.GitConfig)
	if err != nil && s.GitConfig != nil {
		return fmt.Errorf("failed to marshal git config: %w", err)
	}
	s3Config, err := json.Marshal(s.S3Config)
	if err != nil && s.S3Config != nil {
		return fmt.Errorf("failed to marshal s3 config: %w", err)
	}
	httpConfig, err := json.Marshal(s.HTTPConfig)
	if err != nil && s.HTTPConfig != nil {
		return fmt.Errorf("failed to marshal http config: %w", err)
	}

	query := `
		UPDATE template_sources SET
			name = $1,
			description = $2,
			enabled = $3,
			git_config = $4,
			s3_config = $5,
			http_config = $6,
			auto_sync_on_scan = $7,
			cache_ttl_minutes = $8,
			last_sync_at = $9,
			last_sync_hash = $10,
			last_sync_status = $11,
			last_sync_error = $12,
			total_templates = $13,
			last_sync_count = $14,
			credential_id = $15,
			updated_at = $16
		WHERE id = $17
	`

	var credentialID, lastSyncError sql.NullString
	var lastSyncAt sql.NullTime

	if s.CredentialID != nil {
		credentialID = sql.NullString{String: s.CredentialID.String(), Valid: true}
	}
	if s.LastSyncError != nil {
		lastSyncError = sql.NullString{String: *s.LastSyncError, Valid: true}
	}
	if s.LastSyncAt != nil {
		lastSyncAt = sql.NullTime{Time: *s.LastSyncAt, Valid: true}
	}

	// Handle nil configs
	var gitConfigJSON, s3ConfigJSON, httpConfigJSON []byte
	if s.GitConfig != nil {
		gitConfigJSON = gitConfig
	}
	if s.S3Config != nil {
		s3ConfigJSON = s3Config
	}
	if s.HTTPConfig != nil {
		httpConfigJSON = httpConfig
	}

	result, err := r.db.ExecContext(ctx, query,
		s.Name,
		s.Description,
		s.Enabled,
		nullBytes(gitConfigJSON),
		nullBytes(s3ConfigJSON),
		nullBytes(httpConfigJSON),
		s.AutoSyncOnScan,
		s.CacheTTLMinutes,
		lastSyncAt,
		s.LastSyncHash,
		string(s.LastSyncStatus),
		lastSyncError,
		s.TotalTemplates,
		s.LastSyncCount,
		credentialID,
		s.UpdatedAt,
		s.ID.String(),
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "template source with this name already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to update template source: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.NewDomainError("NOT_FOUND", "template source not found", shared.ErrNotFound)
	}

	return nil
}

// Delete deletes a template source.
func (r *TemplateSourceRepository) Delete(ctx context.Context, id shared.ID) error {
	query := `DELETE FROM template_sources WHERE id = $1`

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete template source: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.NewDomainError("NOT_FOUND", "template source not found", shared.ErrNotFound)
	}

	return nil
}

// UpdateSyncStatus updates only the sync-related fields.
func (r *TemplateSourceRepository) UpdateSyncStatus(ctx context.Context, s *ts.TemplateSource) error {
	query := `
		UPDATE template_sources SET
			last_sync_at = $1,
			last_sync_hash = $2,
			last_sync_status = $3,
			last_sync_error = $4,
			total_templates = $5,
			last_sync_count = $6,
			updated_at = $7
		WHERE id = $8
	`

	var lastSyncError sql.NullString
	var lastSyncAt sql.NullTime

	if s.LastSyncError != nil {
		lastSyncError = sql.NullString{String: *s.LastSyncError, Valid: true}
	}
	if s.LastSyncAt != nil {
		lastSyncAt = sql.NullTime{Time: *s.LastSyncAt, Valid: true}
	}

	result, err := r.db.ExecContext(ctx, query,
		lastSyncAt,
		s.LastSyncHash,
		string(s.LastSyncStatus),
		lastSyncError,
		s.TotalTemplates,
		s.LastSyncCount,
		s.UpdatedAt,
		s.ID.String(),
	)

	if err != nil {
		return fmt.Errorf("failed to update sync status: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.NewDomainError("NOT_FOUND", "template source not found", shared.ErrNotFound)
	}

	return nil
}

// CountByTenant counts the total sources for a tenant.
func (r *TemplateSourceRepository) CountByTenant(ctx context.Context, tenantID shared.ID) (int, error) {
	query := `SELECT COUNT(*) FROM template_sources WHERE tenant_id = $1`

	var count int
	if err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count); err != nil {
		return 0, fmt.Errorf("failed to count template sources: %w", err)
	}

	return count, nil
}

// scanSource scans a single row into a TemplateSource.
func (r *TemplateSourceRepository) scanSource(row *sql.Row) (*ts.TemplateSource, error) {
	return r.doScanSource(row.Scan)
}

// scanSourceRow scans a rows.Next() row into a TemplateSource.
func (r *TemplateSourceRepository) scanSourceRow(rows *sql.Rows) (*ts.TemplateSource, error) {
	return r.doScanSource(rows.Scan)
}

// doScanSource is the common implementation for scanning a TemplateSource.
func (r *TemplateSourceRepository) doScanSource(scan func(dest ...any) error) (*ts.TemplateSource, error) {
	var s ts.TemplateSource
	var id, tenantID string
	var gitConfig, s3Config, httpConfig []byte
	var credentialID, createdBy, lastSyncError sql.NullString
	var lastSyncAt sql.NullTime

	err := scan(
		&id,
		&tenantID,
		&s.Name,
		&s.SourceType,
		&s.TemplateType,
		&s.Description,
		&s.Enabled,
		&gitConfig,
		&s3Config,
		&httpConfig,
		&s.AutoSyncOnScan,
		&s.CacheTTLMinutes,
		&lastSyncAt,
		&s.LastSyncHash,
		&s.LastSyncStatus,
		&lastSyncError,
		&s.TotalTemplates,
		&s.LastSyncCount,
		&credentialID,
		&createdBy,
		&s.CreatedAt,
		&s.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Parse IDs
	s.ID, _ = shared.IDFromString(id)
	s.TenantID, _ = shared.IDFromString(tenantID)

	// Parse optional fields
	if credentialID.Valid {
		credID, _ := shared.IDFromString(credentialID.String)
		s.CredentialID = &credID
	}
	if createdBy.Valid {
		cbID, _ := shared.IDFromString(createdBy.String)
		s.CreatedBy = &cbID
	}
	if lastSyncAt.Valid {
		s.LastSyncAt = &lastSyncAt.Time
	}
	if lastSyncError.Valid {
		s.LastSyncError = &lastSyncError.String
	}

	// Parse configs
	if len(gitConfig) > 0 && string(gitConfig) != jsonNull {
		s.GitConfig = &ts.GitSourceConfig{}
		_ = json.Unmarshal(gitConfig, s.GitConfig)
	}
	if len(s3Config) > 0 && string(s3Config) != jsonNull {
		s.S3Config = &ts.S3SourceConfig{}
		_ = json.Unmarshal(s3Config, s.S3Config)
	}
	if len(httpConfig) > 0 && string(httpConfig) != jsonNull {
		s.HTTPConfig = &ts.HTTPSourceConfig{}
		_ = json.Unmarshal(httpConfig, s.HTTPConfig)
	}

	return &s, nil
}
