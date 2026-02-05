package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tool"
	"github.com/openctemio/api/pkg/pagination"
)

// ToolRepository implements tool.Repository using PostgreSQL.
type ToolRepository struct {
	db *DB
}

// NewToolRepository creates a new ToolRepository.
func NewToolRepository(db *DB) *ToolRepository {
	return &ToolRepository{db: db}
}

// Create persists a new tool.
func (r *ToolRepository) Create(ctx context.Context, t *tool.Tool) error {
	configSchema, err := json.Marshal(t.ConfigSchema)
	if err != nil {
		return fmt.Errorf("failed to marshal config_schema: %w", err)
	}

	defaultConfig, err := json.Marshal(t.DefaultConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal default_config: %w", err)
	}

	metadata, err := json.Marshal(t.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Handle nullable tenant_id
	var tenantID any
	if t.TenantID != nil {
		tenantID = t.TenantID.String()
	}

	// Handle nullable created_by
	var createdBy any
	if t.CreatedBy != nil {
		createdBy = t.CreatedBy.String()
	}

	// Handle nullable category_id
	var categoryID any
	if t.CategoryID != nil {
		categoryID = t.CategoryID.String()
	}

	query := `
		INSERT INTO tools (
			id, tenant_id, name, display_name, description, logo_url, category_id,
			install_method, install_cmd, update_cmd,
			version_cmd, version_regex, current_version, latest_version,
			config_file_path, config_schema, default_config,
			capabilities, supported_targets, output_formats,
			docs_url, github_url, is_active, is_builtin,
			tags, metadata, created_by, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29)
	`

	_, err = r.db.ExecContext(ctx, query,
		t.ID.String(),
		tenantID,
		t.Name,
		t.DisplayName,
		t.Description,
		t.LogoURL,
		categoryID,
		string(t.InstallMethod),
		t.InstallCmd,
		t.UpdateCmd,
		t.VersionCmd,
		t.VersionRegex,
		t.CurrentVersion,
		t.LatestVersion,
		t.ConfigFilePath,
		configSchema,
		defaultConfig,
		pq.Array(t.Capabilities),
		pq.Array(t.SupportedTargets),
		pq.Array(t.OutputFormats),
		t.DocsURL,
		t.GithubURL,
		t.IsActive,
		t.IsBuiltin,
		pq.Array(t.Tags),
		metadata,
		createdBy,
		t.CreatedAt,
		t.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "tool with this name already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create tool: %w", err)
	}

	return nil
}

// GetByID retrieves a tool by its ID.
func (r *ToolRepository) GetByID(ctx context.Context, id shared.ID) (*tool.Tool, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanTool(row)
}

// GetByName retrieves a tool by its name.
func (r *ToolRepository) GetByName(ctx context.Context, name string) (*tool.Tool, error) {
	query := r.selectQuery() + " WHERE name = $1"
	row := r.db.QueryRowContext(ctx, query, name)
	return r.scanTool(row)
}

// List lists tools with filters and pagination.
func (r *ToolRepository) List(ctx context.Context, filter tool.ToolFilter, page pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	var result pagination.Result[*tool.Tool]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM tools"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count tools: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY display_name LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list tools: %w", err)
	}
	defer rows.Close()

	var tools []*tool.Tool
	for rows.Next() {
		t, err := r.scanToolFromRows(rows)
		if err != nil {
			return result, err
		}
		tools = append(tools, t)
	}

	return pagination.NewResult(tools, total, page), nil
}

// ListByNames retrieves tools by their names.
func (r *ToolRepository) ListByNames(ctx context.Context, names []string) ([]*tool.Tool, error) {
	if len(names) == 0 {
		return []*tool.Tool{}, nil
	}

	query := r.selectQuery() + " WHERE name = ANY($1) ORDER BY display_name"
	rows, err := r.db.QueryContext(ctx, query, pq.Array(names))
	if err != nil {
		return nil, fmt.Errorf("failed to list tools by names: %w", err)
	}
	defer rows.Close()

	var tools []*tool.Tool
	for rows.Next() {
		t, err := r.scanToolFromRows(rows)
		if err != nil {
			return nil, err
		}
		tools = append(tools, t)
	}

	return tools, nil
}

// ListByCategoryID retrieves tools by category_id.
func (r *ToolRepository) ListByCategoryID(ctx context.Context, categoryID shared.ID) ([]*tool.Tool, error) {
	query := r.selectQuery() + " WHERE category_id = $1 AND is_active = true ORDER BY display_name"
	rows, err := r.db.QueryContext(ctx, query, categoryID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list tools by category_id: %w", err)
	}
	defer rows.Close()

	var tools []*tool.Tool
	for rows.Next() {
		t, err := r.scanToolFromRows(rows)
		if err != nil {
			return nil, err
		}
		tools = append(tools, t)
	}

	return tools, nil
}

// ListByCategoryName retrieves tools by category name (via join with tool_categories).
func (r *ToolRepository) ListByCategoryName(ctx context.Context, categoryName string) ([]*tool.Tool, error) {
	query := `
		SELECT t.id, t.tenant_id, t.name, t.display_name, t.description, t.logo_url, t.category_id,
		       t.install_method, t.install_cmd, t.update_cmd,
		       t.version_cmd, t.version_regex, t.current_version, t.latest_version,
		       t.config_file_path, t.config_schema, t.default_config,
		       t.capabilities, t.supported_targets, t.output_formats,
		       t.docs_url, t.github_url, t.is_active, t.is_builtin,
		       t.tags, t.metadata, t.created_by, t.created_at, t.updated_at
		FROM tools t
		JOIN tool_categories tc ON t.category_id = tc.id
		WHERE tc.name = $1 AND t.is_active = true
		ORDER BY t.display_name
	`
	rows, err := r.db.QueryContext(ctx, query, categoryName)
	if err != nil {
		return nil, fmt.Errorf("failed to list tools by category name: %w", err)
	}
	defer rows.Close()

	var tools []*tool.Tool
	for rows.Next() {
		t, err := r.scanToolFromRows(rows)
		if err != nil {
			return nil, err
		}
		tools = append(tools, t)
	}

	return tools, nil
}

// ListByCapability retrieves tools by capability.
func (r *ToolRepository) ListByCapability(ctx context.Context, capability string) ([]*tool.Tool, error) {
	query := r.selectQuery() + " WHERE $1 = ANY(capabilities) AND is_active = true ORDER BY display_name"
	rows, err := r.db.QueryContext(ctx, query, capability)
	if err != nil {
		return nil, fmt.Errorf("failed to list tools by capability: %w", err)
	}
	defer rows.Close()

	var tools []*tool.Tool
	for rows.Next() {
		t, err := r.scanToolFromRows(rows)
		if err != nil {
			return nil, err
		}
		tools = append(tools, t)
	}

	return tools, nil
}

// FindByCapabilities finds an active tool that matches all required capabilities.
// Searches platform tools first, then tenant-specific tools.
// Returns nil if no matching active tool is found.
func (r *ToolRepository) FindByCapabilities(ctx context.Context, tenantID shared.ID, capabilities []string) (*tool.Tool, error) {
	if len(capabilities) == 0 {
		return nil, nil
	}

	// Find an active tool that contains ALL required capabilities
	// Use array containment operator @> to check if capabilities array contains all required values
	// Order by platform tools first (tenant_id IS NULL), then by name for deterministic results
	query := r.selectQuery() + `
		WHERE is_active = true
			AND capabilities @> $1
			AND (tenant_id IS NULL OR tenant_id = $2)
		ORDER BY
			CASE WHEN tenant_id IS NULL THEN 0 ELSE 1 END,
			display_name
		LIMIT 1
	`

	row := r.db.QueryRowContext(ctx, query, pq.Array(capabilities), tenantID.String())

	t, err := r.scanTool(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil // No matching tool found
		}
		return nil, fmt.Errorf("failed to find tool by capabilities: %w", err)
	}

	return t, nil
}

// Update updates a tool.
func (r *ToolRepository) Update(ctx context.Context, t *tool.Tool) error {
	configSchema, err := json.Marshal(t.ConfigSchema)
	if err != nil {
		return fmt.Errorf("failed to marshal config_schema: %w", err)
	}

	defaultConfig, err := json.Marshal(t.DefaultConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal default_config: %w", err)
	}

	metadata, err := json.Marshal(t.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Handle nullable category_id
	var categoryID any
	if t.CategoryID != nil {
		categoryID = t.CategoryID.String()
	}

	query := `
		UPDATE tools
		SET display_name = $2, description = $3, logo_url = $4,
		    install_cmd = $5, update_cmd = $6,
		    version_cmd = $7, version_regex = $8,
		    current_version = $9, latest_version = $10,
		    config_file_path = $11, config_schema = $12, default_config = $13,
		    capabilities = $14, supported_targets = $15, output_formats = $16,
		    docs_url = $17, github_url = $18, is_active = $19,
		    tags = $20, metadata = $21, updated_at = $22, category_id = $23
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		t.ID.String(),
		t.DisplayName,
		t.Description,
		t.LogoURL,
		t.InstallCmd,
		t.UpdateCmd,
		t.VersionCmd,
		t.VersionRegex,
		t.CurrentVersion,
		t.LatestVersion,
		t.ConfigFilePath,
		configSchema,
		defaultConfig,
		pq.Array(t.Capabilities),
		pq.Array(t.SupportedTargets),
		pq.Array(t.OutputFormats),
		t.DocsURL,
		t.GithubURL,
		t.IsActive,
		pq.Array(t.Tags),
		metadata,
		t.UpdatedAt,
		categoryID,
	)

	if err != nil {
		return fmt.Errorf("failed to update tool: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a tool (only non-builtin tools can be deleted).
func (r *ToolRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM tools WHERE id = $1 AND is_builtin = false"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete tool: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// BulkCreate creates multiple tools at once.
func (r *ToolRepository) BulkCreate(ctx context.Context, tools []*tool.Tool) error {
	if len(tools) == 0 {
		return nil
	}

	// Use a transaction for bulk insert
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, t := range tools {
		configSchema, _ := json.Marshal(t.ConfigSchema)
		defaultConfig, _ := json.Marshal(t.DefaultConfig)
		metadata, _ := json.Marshal(t.Metadata)

		// Handle nullable tenant_id
		var tenantID any
		if t.TenantID != nil {
			tenantID = t.TenantID.String()
		}

		// Handle nullable category_id
		var categoryID any
		if t.CategoryID != nil {
			categoryID = t.CategoryID.String()
		}

		query := `
			INSERT INTO tools (
				id, tenant_id, name, display_name, description, logo_url, category_id,
				install_method, install_cmd, update_cmd,
				version_cmd, version_regex, current_version, latest_version,
				config_file_path, config_schema, default_config,
				capabilities, supported_targets, output_formats,
				docs_url, github_url, is_active, is_builtin,
				tags, metadata, created_at, updated_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28)
			ON CONFLICT (tenant_id, name) DO NOTHING
		`

		_, err = tx.ExecContext(ctx, query,
			t.ID.String(),
			tenantID,
			t.Name,
			t.DisplayName,
			t.Description,
			t.LogoURL,
			categoryID,
			string(t.InstallMethod),
			t.InstallCmd,
			t.UpdateCmd,
			t.VersionCmd,
			t.VersionRegex,
			t.CurrentVersion,
			t.LatestVersion,
			t.ConfigFilePath,
			configSchema,
			defaultConfig,
			pq.Array(t.Capabilities),
			pq.Array(t.SupportedTargets),
			pq.Array(t.OutputFormats),
			t.DocsURL,
			t.GithubURL,
			t.IsActive,
			t.IsBuiltin,
			pq.Array(t.Tags),
			metadata,
			t.CreatedAt,
			t.UpdatedAt,
		)

		if err != nil {
			return fmt.Errorf("failed to create tool %s: %w", t.Name, err)
		}
	}

	return tx.Commit()
}

// BulkUpdateVersions updates version information for multiple tools.
func (r *ToolRepository) BulkUpdateVersions(ctx context.Context, versions map[shared.ID]tool.VersionInfo) error {
	if len(versions) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := "UPDATE tools SET current_version = $2, latest_version = $3, updated_at = NOW() WHERE id = $1"

	for id, info := range versions {
		_, err = tx.ExecContext(ctx, query, id.String(), info.CurrentVersion, info.LatestVersion)
		if err != nil {
			return fmt.Errorf("failed to update tool version: %w", err)
		}
	}

	return tx.Commit()
}

// Count counts tools matching the filter.
func (r *ToolRepository) Count(ctx context.Context, filter tool.ToolFilter) (int64, error) {
	countQuery := "SELECT COUNT(*) FROM tools"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		countQuery += " WHERE " + whereClause
	}

	var count int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&count)
	return count, err
}

// GetAllCapabilities returns all unique capabilities from all active tools.
func (r *ToolRepository) GetAllCapabilities(ctx context.Context) ([]string, error) {
	query := `
		SELECT DISTINCT unnest(capabilities) as capability
		FROM tools
		WHERE is_active = true AND capabilities IS NOT NULL
		ORDER BY capability
	`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get capabilities: %w", err)
	}
	defer rows.Close()

	var capabilities []string
	for rows.Next() {
		var cap string
		if err := rows.Scan(&cap); err != nil {
			return nil, fmt.Errorf("failed to scan capability: %w", err)
		}
		capabilities = append(capabilities, cap)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate capabilities: %w", err)
	}

	return capabilities, nil
}

// selectQuery returns the base SELECT query.
func (r *ToolRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, name, display_name, description, logo_url, category_id,
		       install_method, install_cmd, update_cmd,
		       version_cmd, version_regex, current_version, latest_version,
		       config_file_path, config_schema, default_config,
		       capabilities, supported_targets, output_formats,
		       docs_url, github_url, is_active, is_builtin,
		       tags, metadata, created_by, created_at, updated_at
		FROM tools
	`
}

// buildWhereClause builds the WHERE clause from filters.
func (r *ToolRepository) buildWhereClause(filter tool.ToolFilter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	// Tenant filtering
	switch {
	case filter.OnlyPlatform:
		conditions = append(conditions, "tenant_id IS NULL")
	case filter.OnlyCustom:
		conditions = append(conditions, "tenant_id IS NOT NULL")
		if filter.TenantID != nil {
			conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
			args = append(args, filter.TenantID.String())
			argIndex++
		}
	case filter.TenantID != nil:
		if filter.IncludePlatform {
			// Platform tools + tenant's custom tools
			conditions = append(conditions, fmt.Sprintf("(tenant_id IS NULL OR tenant_id = $%d)", argIndex))
			args = append(args, filter.TenantID.String())
			argIndex++
		} else {
			// Only specific tenant's tools
			conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
			args = append(args, filter.TenantID.String())
			argIndex++
		}
	}

	if filter.CategoryID != nil {
		conditions = append(conditions, fmt.Sprintf("category_id = $%d", argIndex))
		args = append(args, filter.CategoryID.String())
		argIndex++
	}

	if filter.CategoryName != nil {
		// Filter by category name via subquery
		conditions = append(conditions, fmt.Sprintf("category_id IN (SELECT id FROM tool_categories WHERE name = $%d)", argIndex))
		args = append(args, *filter.CategoryName)
		argIndex++
	}

	if len(filter.Capabilities) > 0 {
		conditions = append(conditions, fmt.Sprintf("capabilities && $%d", argIndex))
		args = append(args, pq.Array(filter.Capabilities))
		argIndex++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIndex))
		args = append(args, *filter.IsActive)
		argIndex++
	}

	if filter.IsBuiltin != nil {
		conditions = append(conditions, fmt.Sprintf("is_builtin = $%d", argIndex))
		args = append(args, *filter.IsBuiltin)
		argIndex++
	}

	if len(filter.Tags) > 0 {
		conditions = append(conditions, fmt.Sprintf("tags && $%d", argIndex))
		args = append(args, pq.Array(filter.Tags))
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR display_name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex, argIndex))
		args = append(args, wrapLikePattern(filter.Search))
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

// scanTool scans a single row into a Tool.
func (r *ToolRepository) scanTool(row *sql.Row) (*tool.Tool, error) {
	t := &tool.Tool{}
	var (
		id               string
		tenantID         sql.NullString
		categoryID       sql.NullString
		installMethod    string
		capabilities     pq.StringArray
		supportedTargets pq.StringArray
		outputFormats    pq.StringArray
		tags             pq.StringArray
		configSchema     []byte
		defaultConfig    []byte
		metadata         []byte
		// Nullable string fields
		description    sql.NullString
		logoURL        sql.NullString
		installCmd     sql.NullString
		updateCmd      sql.NullString
		versionCmd     sql.NullString
		versionRegex   sql.NullString
		currentVersion sql.NullString
		latestVersion  sql.NullString
		configFilePath sql.NullString
		docsURL        sql.NullString
		githubURL      sql.NullString
		createdBy      sql.NullString
	)

	err := row.Scan(
		&id,
		&tenantID,
		&t.Name,
		&t.DisplayName,
		&description,
		&logoURL,
		&categoryID,
		&installMethod,
		&installCmd,
		&updateCmd,
		&versionCmd,
		&versionRegex,
		&currentVersion,
		&latestVersion,
		&configFilePath,
		&configSchema,
		&defaultConfig,
		&capabilities,
		&supportedTargets,
		&outputFormats,
		&docsURL,
		&githubURL,
		&t.IsActive,
		&t.IsBuiltin,
		&tags,
		&metadata,
		&createdBy,
		&t.CreatedAt,
		&t.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan tool: %w", err)
	}

	t.ID, _ = shared.IDFromString(id)
	if tenantID.Valid {
		tid, _ := shared.IDFromString(tenantID.String)
		t.TenantID = &tid
	}
	if createdBy.Valid {
		cid, _ := shared.IDFromString(createdBy.String)
		t.CreatedBy = &cid
	}
	if categoryID.Valid {
		catID, _ := shared.IDFromString(categoryID.String)
		t.CategoryID = &catID
	}
	t.InstallMethod = tool.InstallMethod(installMethod)
	t.Capabilities = capabilities
	t.SupportedTargets = supportedTargets
	t.OutputFormats = outputFormats
	t.Tags = tags

	// Convert nullable strings
	t.Description = description.String
	t.LogoURL = logoURL.String
	t.InstallCmd = installCmd.String
	t.UpdateCmd = updateCmd.String
	t.VersionCmd = versionCmd.String
	t.VersionRegex = versionRegex.String
	t.CurrentVersion = currentVersion.String
	t.LatestVersion = latestVersion.String
	t.ConfigFilePath = configFilePath.String
	t.DocsURL = docsURL.String
	t.GithubURL = githubURL.String

	if len(configSchema) > 0 {
		_ = json.Unmarshal(configSchema, &t.ConfigSchema)
	} else {
		t.ConfigSchema = make(map[string]any)
	}

	if len(defaultConfig) > 0 {
		_ = json.Unmarshal(defaultConfig, &t.DefaultConfig)
	} else {
		t.DefaultConfig = make(map[string]any)
	}

	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &t.Metadata)
	} else {
		t.Metadata = make(map[string]any)
	}

	return t, nil
}

// scanToolFromRows scans a row from Rows into a Tool.
func (r *ToolRepository) scanToolFromRows(rows *sql.Rows) (*tool.Tool, error) {
	t := &tool.Tool{}
	var (
		id               string
		tenantID         sql.NullString
		categoryID       sql.NullString
		installMethod    string
		capabilities     pq.StringArray
		supportedTargets pq.StringArray
		outputFormats    pq.StringArray
		tags             pq.StringArray
		configSchema     []byte
		defaultConfig    []byte
		metadata         []byte
		// Nullable string fields
		description    sql.NullString
		logoURL        sql.NullString
		installCmd     sql.NullString
		updateCmd      sql.NullString
		versionCmd     sql.NullString
		versionRegex   sql.NullString
		currentVersion sql.NullString
		latestVersion  sql.NullString
		configFilePath sql.NullString
		docsURL        sql.NullString
		githubURL      sql.NullString
		createdBy      sql.NullString
	)

	err := rows.Scan(
		&id,
		&tenantID,
		&t.Name,
		&t.DisplayName,
		&description,
		&logoURL,
		&categoryID,
		&installMethod,
		&installCmd,
		&updateCmd,
		&versionCmd,
		&versionRegex,
		&currentVersion,
		&latestVersion,
		&configFilePath,
		&configSchema,
		&defaultConfig,
		&capabilities,
		&supportedTargets,
		&outputFormats,
		&docsURL,
		&githubURL,
		&t.IsActive,
		&t.IsBuiltin,
		&tags,
		&metadata,
		&createdBy,
		&t.CreatedAt,
		&t.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan tool: %w", err)
	}

	t.ID, _ = shared.IDFromString(id)
	if tenantID.Valid {
		tid, _ := shared.IDFromString(tenantID.String)
		t.TenantID = &tid
	}
	if createdBy.Valid {
		cid, _ := shared.IDFromString(createdBy.String)
		t.CreatedBy = &cid
	}
	if categoryID.Valid {
		catID, _ := shared.IDFromString(categoryID.String)
		t.CategoryID = &catID
	}
	t.InstallMethod = tool.InstallMethod(installMethod)
	t.Capabilities = capabilities
	t.SupportedTargets = supportedTargets
	t.OutputFormats = outputFormats
	t.Tags = tags

	// Convert nullable strings
	t.Description = description.String
	t.LogoURL = logoURL.String
	t.InstallCmd = installCmd.String
	t.UpdateCmd = updateCmd.String
	t.VersionCmd = versionCmd.String
	t.VersionRegex = versionRegex.String
	t.CurrentVersion = currentVersion.String
	t.LatestVersion = latestVersion.String
	t.ConfigFilePath = configFilePath.String
	t.DocsURL = docsURL.String
	t.GithubURL = githubURL.String

	if len(configSchema) > 0 {
		_ = json.Unmarshal(configSchema, &t.ConfigSchema)
	} else {
		t.ConfigSchema = make(map[string]any)
	}

	if len(defaultConfig) > 0 {
		_ = json.Unmarshal(defaultConfig, &t.DefaultConfig)
	} else {
		t.DefaultConfig = make(map[string]any)
	}

	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &t.Metadata)
	} else {
		t.Metadata = make(map[string]any)
	}

	return t, nil
}

// GetByTenantAndID retrieves a tenant custom tool by tenant ID and tool ID.
func (r *ToolRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*tool.Tool, error) {
	query := r.selectQuery() + " WHERE id = $1 AND tenant_id = $2"
	row := r.db.QueryRowContext(ctx, query, id.String(), tenantID.String())
	return r.scanTool(row)
}

// GetByTenantAndName retrieves a tenant custom tool by tenant ID and name.
func (r *ToolRepository) GetByTenantAndName(ctx context.Context, tenantID shared.ID, name string) (*tool.Tool, error) {
	query := r.selectQuery() + " WHERE name = $1 AND tenant_id = $2"
	row := r.db.QueryRowContext(ctx, query, name, tenantID.String())
	return r.scanTool(row)
}

// GetPlatformToolByName retrieves a platform tool by name.
func (r *ToolRepository) GetPlatformToolByName(ctx context.Context, name string) (*tool.Tool, error) {
	query := r.selectQuery() + " WHERE name = $1 AND tenant_id IS NULL"
	row := r.db.QueryRowContext(ctx, query, name)
	return r.scanTool(row)
}

// ListPlatformTools lists all platform tools (tenant_id IS NULL).
func (r *ToolRepository) ListPlatformTools(ctx context.Context, filter tool.ToolFilter, page pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	filter.OnlyPlatform = true
	return r.List(ctx, filter, page)
}

// ListTenantCustomTools lists a tenant's custom tools.
func (r *ToolRepository) ListTenantCustomTools(ctx context.Context, tenantID shared.ID, filter tool.ToolFilter, page pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	filter.OnlyCustom = true
	filter.TenantID = &tenantID
	return r.List(ctx, filter, page)
}

// ListAvailableTools lists all tools available to a tenant (platform + tenant's custom).
func (r *ToolRepository) ListAvailableTools(ctx context.Context, tenantID shared.ID, filter tool.ToolFilter, page pagination.Pagination) (pagination.Result[*tool.Tool], error) {
	filter.TenantID = &tenantID
	filter.IncludePlatform = true
	return r.List(ctx, filter, page)
}

// DeleteTenantTool deletes a tenant's custom tool.
func (r *ToolRepository) DeleteTenantTool(ctx context.Context, tenantID, id shared.ID) error {
	query := "DELETE FROM tools WHERE id = $1 AND tenant_id = $2"
	result, err := r.db.ExecContext(ctx, query, id.String(), tenantID.String())
	if err != nil {
		return fmt.Errorf("failed to delete tenant tool: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}
