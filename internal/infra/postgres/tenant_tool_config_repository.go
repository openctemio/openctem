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

// TenantToolConfigRepository implements tool.TenantToolConfigRepository using PostgreSQL.
type TenantToolConfigRepository struct {
	db *DB
}

// NewTenantToolConfigRepository creates a new TenantToolConfigRepository.
func NewTenantToolConfigRepository(db *DB) *TenantToolConfigRepository {
	return &TenantToolConfigRepository{db: db}
}

// Create persists a new tenant tool configuration.
func (r *TenantToolConfigRepository) Create(ctx context.Context, c *tool.TenantToolConfig) error {
	config, err := json.Marshal(c.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	customTemplates, err := json.Marshal(c.CustomTemplates)
	if err != nil {
		return fmt.Errorf("failed to marshal custom_templates: %w", err)
	}

	customPatterns, err := json.Marshal(c.CustomPatterns)
	if err != nil {
		return fmt.Errorf("failed to marshal custom_patterns: %w", err)
	}

	customWordlists, err := json.Marshal(c.CustomWordlists)
	if err != nil {
		return fmt.Errorf("failed to marshal custom_wordlists: %w", err)
	}

	query := `
		INSERT INTO tenant_tool_configs (
			id, tenant_id, tool_id, config,
			custom_templates, custom_patterns, custom_wordlists,
			is_enabled, updated_by, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	var updatedBy sql.NullString
	if c.UpdatedBy != nil {
		updatedBy = sql.NullString{String: c.UpdatedBy.String(), Valid: true}
	}

	_, err = r.db.ExecContext(ctx, query,
		c.ID.String(),
		c.TenantID.String(),
		c.ToolID.String(),
		config,
		customTemplates,
		customPatterns,
		customWordlists,
		c.IsEnabled,
		updatedBy,
		c.CreatedAt,
		c.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "config for this tool already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create tenant tool config: %w", err)
	}

	return nil
}

// GetByID retrieves a tenant tool config by its ID.
func (r *TenantToolConfigRepository) GetByID(ctx context.Context, id shared.ID) (*tool.TenantToolConfig, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanConfig(row)
}

// GetByTenantAndTool retrieves a tenant tool config by tenant and tool.
func (r *TenantToolConfigRepository) GetByTenantAndTool(ctx context.Context, tenantID, toolID shared.ID) (*tool.TenantToolConfig, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND tool_id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), toolID.String())
	return r.scanConfig(row)
}

// List lists tenant tool configs with filters and pagination.
func (r *TenantToolConfigRepository) List(ctx context.Context, filter tool.TenantToolConfigFilter, page pagination.Pagination) (pagination.Result[*tool.TenantToolConfig], error) {
	var result pagination.Result[*tool.TenantToolConfig]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM tenant_tool_configs"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count tenant tool configs: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list tenant tool configs: %w", err)
	}
	defer rows.Close()

	var configs []*tool.TenantToolConfig
	for rows.Next() {
		c, err := r.scanConfigFromRows(rows)
		if err != nil {
			return result, err
		}
		configs = append(configs, c)
	}

	return pagination.NewResult(configs, total, page), nil
}

// Update updates a tenant tool config.
func (r *TenantToolConfigRepository) Update(ctx context.Context, c *tool.TenantToolConfig) error {
	config, err := json.Marshal(c.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	customTemplates, err := json.Marshal(c.CustomTemplates)
	if err != nil {
		return fmt.Errorf("failed to marshal custom_templates: %w", err)
	}

	customPatterns, err := json.Marshal(c.CustomPatterns)
	if err != nil {
		return fmt.Errorf("failed to marshal custom_patterns: %w", err)
	}

	customWordlists, err := json.Marshal(c.CustomWordlists)
	if err != nil {
		return fmt.Errorf("failed to marshal custom_wordlists: %w", err)
	}

	var updatedBy sql.NullString
	if c.UpdatedBy != nil {
		updatedBy = sql.NullString{String: c.UpdatedBy.String(), Valid: true}
	}

	query := `
		UPDATE tenant_tool_configs
		SET config = $2, custom_templates = $3, custom_patterns = $4,
		    custom_wordlists = $5, is_enabled = $6, updated_by = $7, updated_at = $8
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		c.ID.String(),
		config,
		customTemplates,
		customPatterns,
		customWordlists,
		c.IsEnabled,
		updatedBy,
		c.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update tenant tool config: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a tenant tool config.
func (r *TenantToolConfigRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM tenant_tool_configs WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete tenant tool config: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Upsert creates or updates a tenant tool config.
func (r *TenantToolConfigRepository) Upsert(ctx context.Context, c *tool.TenantToolConfig) error {
	config, err := json.Marshal(c.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	customTemplates, err := json.Marshal(c.CustomTemplates)
	if err != nil {
		return fmt.Errorf("failed to marshal custom_templates: %w", err)
	}

	customPatterns, err := json.Marshal(c.CustomPatterns)
	if err != nil {
		return fmt.Errorf("failed to marshal custom_patterns: %w", err)
	}

	customWordlists, err := json.Marshal(c.CustomWordlists)
	if err != nil {
		return fmt.Errorf("failed to marshal custom_wordlists: %w", err)
	}

	var updatedBy sql.NullString
	if c.UpdatedBy != nil {
		updatedBy = sql.NullString{String: c.UpdatedBy.String(), Valid: true}
	}

	query := `
		INSERT INTO tenant_tool_configs (
			id, tenant_id, tool_id, config,
			custom_templates, custom_patterns, custom_wordlists,
			is_enabled, updated_by, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (tenant_id, tool_id) DO UPDATE SET
			config = EXCLUDED.config,
			custom_templates = EXCLUDED.custom_templates,
			custom_patterns = EXCLUDED.custom_patterns,
			custom_wordlists = EXCLUDED.custom_wordlists,
			is_enabled = EXCLUDED.is_enabled,
			updated_by = EXCLUDED.updated_by,
			updated_at = EXCLUDED.updated_at
	`

	_, err = r.db.ExecContext(ctx, query,
		c.ID.String(),
		c.TenantID.String(),
		c.ToolID.String(),
		config,
		customTemplates,
		customPatterns,
		customWordlists,
		c.IsEnabled,
		updatedBy,
		c.CreatedAt,
		c.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to upsert tenant tool config: %w", err)
	}

	return nil
}

// GetEffectiveConfig returns the merged config (default + tenant override).
func (r *TenantToolConfigRepository) GetEffectiveConfig(ctx context.Context, tenantID, toolID shared.ID) (map[string]any, error) {
	query := `
		SELECT t.default_config, COALESCE(tc.config, '{}'::jsonb) as tenant_config
		FROM tools t
		LEFT JOIN tenant_tool_configs tc ON tc.tool_id = t.id AND tc.tenant_id = $1
		WHERE t.id = $2
	`

	var defaultConfigBytes, tenantConfigBytes []byte
	err := r.db.QueryRowContext(ctx, query, tenantID.String(), toolID.String()).Scan(&defaultConfigBytes, &tenantConfigBytes)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to get effective config: %w", err)
	}

	// Parse configs
	defaultConfig := make(map[string]any)
	tenantConfig := make(map[string]any)

	if len(defaultConfigBytes) > 0 {
		_ = json.Unmarshal(defaultConfigBytes, &defaultConfig)
	}
	if len(tenantConfigBytes) > 0 {
		_ = json.Unmarshal(tenantConfigBytes, &tenantConfig)
	}

	// Merge: tenant config overrides default
	effectiveConfig := make(map[string]any)
	for k, v := range defaultConfig {
		effectiveConfig[k] = v
	}
	for k, v := range tenantConfig {
		effectiveConfig[k] = v
	}

	return effectiveConfig, nil
}

// ListEnabledTools lists all enabled tool configs for a tenant.
func (r *TenantToolConfigRepository) ListEnabledTools(ctx context.Context, tenantID shared.ID) ([]*tool.TenantToolConfig, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND is_enabled = true ORDER BY created_at"
	rows, err := r.db.QueryContext(ctx, query, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to list enabled tools: %w", err)
	}
	defer rows.Close()

	var configs []*tool.TenantToolConfig
	for rows.Next() {
		c, err := r.scanConfigFromRows(rows)
		if err != nil {
			return nil, err
		}
		configs = append(configs, c)
	}

	return configs, nil
}

// BulkEnable enables multiple tools for a tenant.
func (r *TenantToolConfigRepository) BulkEnable(ctx context.Context, tenantID shared.ID, toolIDs []shared.ID) error {
	if len(toolIDs) == 0 {
		return nil
	}

	// Convert to string array
	ids := make([]string, len(toolIDs))
	for i, id := range toolIDs {
		ids[i] = id.String()
	}

	query := `
		UPDATE tenant_tool_configs
		SET is_enabled = true, updated_at = NOW()
		WHERE tenant_id = $1 AND tool_id = ANY($2)
	`

	_, err := r.db.ExecContext(ctx, query, tenantID.String(), pq.Array(ids))
	return err
}

// BulkDisable disables multiple tools for a tenant.
func (r *TenantToolConfigRepository) BulkDisable(ctx context.Context, tenantID shared.ID, toolIDs []shared.ID) error {
	if len(toolIDs) == 0 {
		return nil
	}

	// Convert to string array
	ids := make([]string, len(toolIDs))
	for i, id := range toolIDs {
		ids[i] = id.String()
	}

	query := `
		UPDATE tenant_tool_configs
		SET is_enabled = false, updated_at = NOW()
		WHERE tenant_id = $1 AND tool_id = ANY($2)
	`

	_, err := r.db.ExecContext(ctx, query, tenantID.String(), pq.Array(ids))
	return err
}

// ListToolsWithConfig returns all tools with their tenant-specific enabled status.
// If a tenant config doesn't exist for a tool, is_enabled defaults to true.
// Only returns platform tools (tenant_id IS NULL) and the tenant's own custom tools.
func (r *TenantToolConfigRepository) ListToolsWithConfig(
	ctx context.Context,
	tenantID shared.ID,
	filter tool.ToolFilter,
	page pagination.Pagination,
) (pagination.Result[*tool.ToolWithConfig], error) {
	var result pagination.Result[*tool.ToolWithConfig]

	// Build WHERE clause for tools filter
	var conditions []string
	var args []any
	argIndex := 1

	// Tenant ID for the LEFT JOIN
	args = append(args, tenantID.String())
	argIndex++

	// SECURITY: Only show platform tools (tenant_id IS NULL) and tenant's own custom tools
	// This prevents tenants from seeing other tenants' custom tools
	conditions = append(conditions, fmt.Sprintf("(t.tenant_id IS NULL OR t.tenant_id = $%d)", argIndex))
	args = append(args, tenantID.String())
	argIndex++

	if filter.CategoryID != nil {
		conditions = append(conditions, fmt.Sprintf("t.category_id = $%d", argIndex))
		args = append(args, filter.CategoryID.String())
		argIndex++
	}

	if filter.CategoryName != nil {
		conditions = append(conditions, fmt.Sprintf("t.category_id IN (SELECT id FROM tool_categories WHERE name = $%d)", argIndex))
		args = append(args, *filter.CategoryName)
		argIndex++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("t.is_active = $%d", argIndex))
		args = append(args, *filter.IsActive)
		argIndex++
	}

	if filter.IsBuiltin != nil {
		conditions = append(conditions, fmt.Sprintf("t.is_builtin = $%d", argIndex))
		args = append(args, *filter.IsBuiltin)
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(t.name ILIKE $%d OR t.display_name ILIKE $%d OR t.description ILIKE $%d)",
			argIndex, argIndex, argIndex,
		))
		args = append(args, wrapLikePattern(filter.Search))
		argIndex++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count query
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*)
		FROM tools t
		LEFT JOIN tenant_tool_configs tc ON tc.tool_id = t.id AND tc.tenant_id = $1
		%s
	`, whereClause)

	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return result, fmt.Errorf("failed to count tools with config: %w", err)
	}

	// Main query
	offset := (page.Page - 1) * page.PerPage
	query := fmt.Sprintf(`
		SELECT
			t.id, t.tenant_id, t.name, t.display_name, t.description, t.logo_url,
			t.category_id, t.install_method, t.install_cmd, t.update_cmd,
			t.version_cmd, t.version_regex, t.current_version, t.latest_version,
			t.config_file_path, t.config_schema, t.default_config,
			t.capabilities, t.supported_targets, t.output_formats,
			t.docs_url, t.github_url, t.is_active, t.is_builtin, t.tags, t.metadata,
			t.created_by, t.created_at, t.updated_at,
			tc.id as config_id, tc.config as tenant_config, tc.is_enabled,
			tc.custom_templates, tc.custom_patterns, tc.custom_wordlists,
			tc.updated_by, tc.created_at as config_created_at, tc.updated_at as config_updated_at,
			cat.id as cat_id, cat.name as cat_name, cat.display_name as cat_display_name,
			cat.icon as cat_icon, cat.color as cat_color
		FROM tools t
		LEFT JOIN tenant_tool_configs tc ON tc.tool_id = t.id AND tc.tenant_id = $1
		LEFT JOIN tool_categories cat ON cat.id = t.category_id
		%s
		ORDER BY COALESCE(cat.sort_order, 999), t.display_name ASC
		LIMIT %d OFFSET %d
	`, whereClause, page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list tools with config: %w", err)
	}
	defer rows.Close()

	var items []*tool.ToolWithConfig
	for rows.Next() {
		twc, err := r.scanToolWithConfig(rows)
		if err != nil {
			return result, err
		}
		items = append(items, twc)
	}

	return pagination.NewResult(items, total, page), nil
}

// scanToolWithConfig scans a row into ToolWithConfig.
func (r *TenantToolConfigRepository) scanToolWithConfig(rows *sql.Rows) (*tool.ToolWithConfig, error) {
	t := &tool.Tool{}
	var (
		toolID           string
		toolTenantID     sql.NullString // Tool's tenant_id (NULL for platform tools)
		categoryID       sql.NullString
		installMethod    string
		configSchema     []byte
		defaultConfig    []byte
		capabilities     pq.StringArray // PostgreSQL text[] array
		supportedTargets pq.StringArray // PostgreSQL text[] array
		outputFormats    pq.StringArray // PostgreSQL text[] array
		tags             pq.StringArray // PostgreSQL text[] array
		metadata         []byte
		logoURL          sql.NullString
		description      sql.NullString
		installCmd       sql.NullString
		updateCmd        sql.NullString
		versionCmd       sql.NullString
		versionRegex     sql.NullString
		currentVersion   sql.NullString
		latestVersion    sql.NullString
		configFilePath   sql.NullString
		docsURL          sql.NullString
		githubURL        sql.NullString
		createdBy        sql.NullString
		// Tenant config fields (nullable)
		configID        sql.NullString
		tenantConfig    []byte
		isEnabled       sql.NullBool
		customTemplates []byte
		customPatterns  []byte
		customWordlists []byte
		configUpdatedBy sql.NullString
		configCreatedAt sql.NullTime
		configUpdatedAt sql.NullTime
		// Category fields (nullable - from LEFT JOIN)
		catID          sql.NullString
		catName        sql.NullString
		catDisplayName sql.NullString
		catIcon        sql.NullString
		catColor       sql.NullString
	)

	err := rows.Scan(
		&toolID, &toolTenantID, &t.Name, &t.DisplayName, &description, &logoURL,
		&categoryID, &installMethod, &installCmd, &updateCmd,
		&versionCmd, &versionRegex, &currentVersion, &latestVersion,
		&configFilePath, &configSchema, &defaultConfig,
		&capabilities, &supportedTargets, &outputFormats,
		&docsURL, &githubURL, &t.IsActive, &t.IsBuiltin, &tags, &metadata,
		&createdBy, &t.CreatedAt, &t.UpdatedAt,
		&configID, &tenantConfig, &isEnabled,
		&customTemplates, &customPatterns, &customWordlists,
		&configUpdatedBy, &configCreatedAt, &configUpdatedAt,
		&catID, &catName, &catDisplayName, &catIcon, &catColor,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to scan tool with config: %w", err)
	}

	t.ID, _ = shared.IDFromString(toolID)
	if toolTenantID.Valid {
		tid, _ := shared.IDFromString(toolTenantID.String)
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
	}
	if len(defaultConfig) > 0 {
		_ = json.Unmarshal(defaultConfig, &t.DefaultConfig)
	}
	// Directly assign pq.StringArray slices (PostgreSQL text[] arrays)
	t.Capabilities = capabilities
	t.SupportedTargets = supportedTargets
	t.OutputFormats = outputFormats
	t.Tags = tags
	if len(metadata) > 0 {
		_ = json.Unmarshal(metadata, &t.Metadata)
	}

	twc := &tool.ToolWithConfig{
		Tool:      t,
		IsEnabled: true, // Default to enabled if no tenant config
	}

	// Build embedded category if available
	if catID.Valid && catName.Valid {
		cid, _ := shared.IDFromString(catID.String)
		twc.Category = &tool.EmbeddedCategory{
			ID:          cid,
			Name:        catName.String,
			DisplayName: catDisplayName.String,
			Icon:        catIcon.String,
			Color:       catColor.String,
		}
	}

	// If tenant config exists, populate it
	if configID.Valid {
		tc := &tool.TenantToolConfig{}
		tc.ID, _ = shared.IDFromString(configID.String)
		tc.ToolID = t.ID
		if isEnabled.Valid {
			tc.IsEnabled = isEnabled.Bool
			twc.IsEnabled = isEnabled.Bool
		}
		if len(tenantConfig) > 0 {
			_ = json.Unmarshal(tenantConfig, &tc.Config)
		} else {
			tc.Config = make(map[string]any)
		}
		if len(customTemplates) > 0 {
			_ = json.Unmarshal(customTemplates, &tc.CustomTemplates)
		}
		if len(customPatterns) > 0 {
			_ = json.Unmarshal(customPatterns, &tc.CustomPatterns)
		}
		if len(customWordlists) > 0 {
			_ = json.Unmarshal(customWordlists, &tc.CustomWordlists)
		}
		if configUpdatedBy.Valid {
			updatedByID, _ := shared.IDFromString(configUpdatedBy.String)
			tc.UpdatedBy = &updatedByID
		}
		if configCreatedAt.Valid {
			tc.CreatedAt = configCreatedAt.Time
		}
		if configUpdatedAt.Valid {
			tc.UpdatedAt = configUpdatedAt.Time
		}
		twc.TenantConfig = tc
	}

	// Build effective config
	twc.EffectiveConfig = make(map[string]any)
	for k, v := range t.DefaultConfig {
		twc.EffectiveConfig[k] = v
	}
	if twc.TenantConfig != nil {
		for k, v := range twc.TenantConfig.Config {
			twc.EffectiveConfig[k] = v
		}
	}

	return twc, nil
}

// selectQuery returns the base SELECT query.
func (r *TenantToolConfigRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, tool_id, config,
		       custom_templates, custom_patterns, custom_wordlists,
		       is_enabled, updated_by, created_at, updated_at
		FROM tenant_tool_configs
	`
}

// buildWhereClause builds the WHERE clause from filters.
func (r *TenantToolConfigRepository) buildWhereClause(filter tool.TenantToolConfigFilter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	// TenantID is required
	conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
	args = append(args, filter.TenantID.String())
	argIndex++

	if filter.ToolID != nil {
		conditions = append(conditions, fmt.Sprintf("tool_id = $%d", argIndex))
		args = append(args, filter.ToolID.String())
		argIndex++
	}

	if filter.IsEnabled != nil {
		conditions = append(conditions, fmt.Sprintf("is_enabled = $%d", argIndex))
		args = append(args, *filter.IsEnabled)
	}

	return strings.Join(conditions, " AND "), args
}

// scanConfig scans a single row into a TenantToolConfig.
func (r *TenantToolConfigRepository) scanConfig(row *sql.Row) (*tool.TenantToolConfig, error) {
	c := &tool.TenantToolConfig{}
	var (
		id              string
		tenantID        string
		toolID          string
		config          []byte
		customTemplates []byte
		customPatterns  []byte
		customWordlists []byte
		updatedBy       sql.NullString
	)

	err := row.Scan(
		&id,
		&tenantID,
		&toolID,
		&config,
		&customTemplates,
		&customPatterns,
		&customWordlists,
		&c.IsEnabled,
		&updatedBy,
		&c.CreatedAt,
		&c.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan tenant tool config: %w", err)
	}

	c.ID, _ = shared.IDFromString(id)
	c.TenantID, _ = shared.IDFromString(tenantID)
	c.ToolID, _ = shared.IDFromString(toolID)

	if updatedBy.Valid {
		updatedByID, _ := shared.IDFromString(updatedBy.String)
		c.UpdatedBy = &updatedByID
	}

	if len(config) > 0 {
		_ = json.Unmarshal(config, &c.Config)
	} else {
		c.Config = make(map[string]any)
	}

	if len(customTemplates) > 0 {
		_ = json.Unmarshal(customTemplates, &c.CustomTemplates)
	}

	if len(customPatterns) > 0 {
		_ = json.Unmarshal(customPatterns, &c.CustomPatterns)
	}

	if len(customWordlists) > 0 {
		_ = json.Unmarshal(customWordlists, &c.CustomWordlists)
	}

	return c, nil
}

// scanConfigFromRows scans a row from Rows into a TenantToolConfig.
func (r *TenantToolConfigRepository) scanConfigFromRows(rows *sql.Rows) (*tool.TenantToolConfig, error) {
	c := &tool.TenantToolConfig{}
	var (
		id              string
		tenantID        string
		toolID          string
		config          []byte
		customTemplates []byte
		customPatterns  []byte
		customWordlists []byte
		updatedBy       sql.NullString
	)

	err := rows.Scan(
		&id,
		&tenantID,
		&toolID,
		&config,
		&customTemplates,
		&customPatterns,
		&customWordlists,
		&c.IsEnabled,
		&updatedBy,
		&c.CreatedAt,
		&c.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan tenant tool config: %w", err)
	}

	c.ID, _ = shared.IDFromString(id)
	c.TenantID, _ = shared.IDFromString(tenantID)
	c.ToolID, _ = shared.IDFromString(toolID)

	if updatedBy.Valid {
		updatedByID, _ := shared.IDFromString(updatedBy.String)
		c.UpdatedBy = &updatedByID
	}

	if len(config) > 0 {
		_ = json.Unmarshal(config, &c.Config)
	} else {
		c.Config = make(map[string]any)
	}

	if len(customTemplates) > 0 {
		_ = json.Unmarshal(customTemplates, &c.CustomTemplates)
	}

	if len(customPatterns) > 0 {
		_ = json.Unmarshal(customPatterns, &c.CustomPatterns)
	}

	if len(customWordlists) > 0 {
		_ = json.Unmarshal(customWordlists, &c.CustomWordlists)
	}

	return c, nil
}
