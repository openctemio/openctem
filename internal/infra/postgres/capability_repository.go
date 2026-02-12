package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/capability"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// CapabilityRepository implements capability.Repository using PostgreSQL.
type CapabilityRepository struct {
	db *DB
}

// NewCapabilityRepository creates a new CapabilityRepository.
func NewCapabilityRepository(db *DB) *CapabilityRepository {
	return &CapabilityRepository{db: db}
}

// selectQuery returns the base SELECT query for capabilities.
func (r *CapabilityRepository) selectQuery() string {
	return `
		SELECT
			id, tenant_id, name, display_name, description,
			icon, color, category, is_builtin, sort_order,
			created_by, created_at, updated_at
		FROM capabilities
	`
}

// scanCapability scans a single row into a Capability.
func (r *CapabilityRepository) scanCapability(row interface{ Scan(...any) error }) (*capability.Capability, error) {
	var (
		id          string
		tenantID    sql.NullString
		name        string
		displayName string
		description sql.NullString
		icon        string
		color       string
		category    sql.NullString
		isBuiltin   bool
		sortOrder   int
		createdBy   sql.NullString
		createdAt   sql.NullTime
		updatedAt   sql.NullTime
	)

	err := row.Scan(
		&id, &tenantID, &name, &displayName, &description,
		&icon, &color, &category, &isBuiltin, &sortOrder,
		&createdBy, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	c := &capability.Capability{
		Name:        name,
		DisplayName: displayName,
		Icon:        icon,
		Color:       color,
		IsBuiltin:   isBuiltin,
		SortOrder:   sortOrder,
	}

	c.ID, _ = shared.IDFromString(id)

	if tenantID.Valid {
		tid, _ := shared.IDFromString(tenantID.String)
		c.TenantID = &tid
	}

	if description.Valid {
		c.Description = description.String
	}

	if category.Valid {
		c.Category = category.String
	}

	if createdBy.Valid {
		cid, _ := shared.IDFromString(createdBy.String)
		c.CreatedBy = &cid
	}

	if createdAt.Valid {
		c.CreatedAt = createdAt.Time
	}

	if updatedAt.Valid {
		c.UpdatedAt = updatedAt.Time
	}

	return c, nil
}

// Create persists a new capability.
func (r *CapabilityRepository) Create(ctx context.Context, c *capability.Capability) error {
	var tenantID any
	if c.TenantID != nil {
		tenantID = c.TenantID.String()
	}

	var createdBy any
	if c.CreatedBy != nil {
		createdBy = c.CreatedBy.String()
	}

	query := `
		INSERT INTO capabilities (
			id, tenant_id, name, display_name, description,
			icon, color, category, is_builtin, sort_order,
			created_by, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`

	_, err := r.db.ExecContext(ctx, query,
		c.ID.String(),
		tenantID,
		c.Name,
		c.DisplayName,
		c.Description,
		c.Icon,
		c.Color,
		c.Category,
		c.IsBuiltin,
		c.SortOrder,
		createdBy,
		c.CreatedAt,
		c.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: capability with name '%s' already exists", shared.ErrConflict, c.Name)
		}
		return fmt.Errorf("failed to create capability: %w", err)
	}

	return nil
}

// GetByID returns a capability by ID.
func (r *CapabilityRepository) GetByID(ctx context.Context, id shared.ID) (*capability.Capability, error) {
	query := r.selectQuery() + " WHERE id = $1"

	row := r.db.QueryRowContext(ctx, query, id.String())
	c, err := r.scanCapability(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: capability not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get capability: %w", err)
	}

	return c, nil
}

// GetByName returns a capability by name within a scope.
func (r *CapabilityRepository) GetByName(ctx context.Context, tenantID *shared.ID, name string) (*capability.Capability, error) {
	var query string
	var args []any

	if tenantID == nil {
		query = r.selectQuery() + " WHERE tenant_id IS NULL AND name = $1"
		args = []any{name}
	} else {
		query = r.selectQuery() + " WHERE tenant_id = $1 AND name = $2"
		args = []any{tenantID.String(), name}
	}

	row := r.db.QueryRowContext(ctx, query, args...)
	c, err := r.scanCapability(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: capability not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get capability by name: %w", err)
	}

	return c, nil
}

// List returns capabilities matching the filter with pagination.
func (r *CapabilityRepository) List(ctx context.Context, filter capability.Filter, page pagination.Pagination) (pagination.Result[*capability.Capability], error) {
	var conditions []string
	var args []any
	argIdx := 1

	// Always include platform capabilities OR tenant's own capabilities
	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("(tenant_id IS NULL OR tenant_id = $%d)", argIdx))
		args = append(args, filter.TenantID.String())
		argIdx++
	} else {
		conditions = append(conditions, "tenant_id IS NULL")
	}

	// Filter by builtin status
	if filter.IsBuiltin != nil {
		conditions = append(conditions, fmt.Sprintf("is_builtin = $%d", argIdx))
		args = append(args, *filter.IsBuiltin)
		argIdx++
	}

	// Filter by category
	if filter.Category != nil {
		conditions = append(conditions, fmt.Sprintf("category = $%d", argIdx))
		args = append(args, *filter.Category)
		argIdx++
	}

	// Search by name or display name
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR display_name ILIKE $%d)", argIdx, argIdx))
		args = append(args, wrapLikePattern(filter.Search))
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total
	countQuery := "SELECT COUNT(*) FROM capabilities" + whereClause
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return pagination.Result[*capability.Capability]{}, fmt.Errorf("failed to count capabilities: %w", err)
	}

	// Fetch items
	query := r.selectQuery() + whereClause + " ORDER BY sort_order ASC, display_name ASC"
	query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, page.PerPage, page.Offset())

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return pagination.Result[*capability.Capability]{}, fmt.Errorf("failed to list capabilities: %w", err)
	}
	defer rows.Close()

	var capabilities []*capability.Capability
	for rows.Next() {
		c, err := r.scanCapability(rows)
		if err != nil {
			return pagination.Result[*capability.Capability]{}, fmt.Errorf("failed to scan capability: %w", err)
		}
		capabilities = append(capabilities, c)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*capability.Capability]{}, fmt.Errorf("failed to iterate capabilities: %w", err)
	}

	return pagination.NewResult(capabilities, total, page), nil
}

// ListAll returns all capabilities for a tenant context.
func (r *CapabilityRepository) ListAll(ctx context.Context, tenantID *shared.ID) ([]*capability.Capability, error) {
	var query string
	var args []any

	if tenantID != nil {
		query = r.selectQuery() + " WHERE tenant_id IS NULL OR tenant_id = $1 ORDER BY sort_order ASC, display_name ASC"
		args = []any{tenantID.String()}
	} else {
		query = r.selectQuery() + " WHERE tenant_id IS NULL ORDER BY sort_order ASC, display_name ASC"
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list all capabilities: %w", err)
	}
	defer rows.Close()

	var capabilities []*capability.Capability
	for rows.Next() {
		c, err := r.scanCapability(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan capability: %w", err)
		}
		capabilities = append(capabilities, c)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate capabilities: %w", err)
	}

	return capabilities, nil
}

// ListByNames returns capabilities by their names.
func (r *CapabilityRepository) ListByNames(ctx context.Context, tenantID *shared.ID, names []string) ([]*capability.Capability, error) {
	if len(names) == 0 {
		return nil, nil
	}

	// Build IN clause
	placeholders := make([]string, len(names))
	args := make([]any, 0, len(names)+1)
	argIdx := 1

	// Tenant condition
	var tenantCondition string
	if tenantID != nil {
		tenantCondition = fmt.Sprintf("(tenant_id IS NULL OR tenant_id = $%d)", argIdx)
		args = append(args, tenantID.String())
		argIdx++
	} else {
		tenantCondition = "tenant_id IS NULL"
	}

	for i, name := range names {
		placeholders[i] = fmt.Sprintf("$%d", argIdx)
		args = append(args, name)
		argIdx++
	}

	query := r.selectQuery() + fmt.Sprintf(
		" WHERE %s AND name IN (%s) ORDER BY sort_order ASC",
		tenantCondition,
		strings.Join(placeholders, ", "),
	)

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list capabilities by names: %w", err)
	}
	defer rows.Close()

	var capabilities []*capability.Capability
	for rows.Next() {
		c, err := r.scanCapability(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan capability: %w", err)
		}
		capabilities = append(capabilities, c)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate capabilities: %w", err)
	}

	return capabilities, nil
}

// ListByCategory returns all capabilities in a category.
func (r *CapabilityRepository) ListByCategory(ctx context.Context, tenantID *shared.ID, category string) ([]*capability.Capability, error) {
	var query string
	var args []any

	if tenantID != nil {
		query = r.selectQuery() + " WHERE (tenant_id IS NULL OR tenant_id = $1) AND category = $2 ORDER BY sort_order ASC"
		args = []any{tenantID.String(), category}
	} else {
		query = r.selectQuery() + " WHERE tenant_id IS NULL AND category = $1 ORDER BY sort_order ASC"
		args = []any{category}
	}

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list capabilities by category: %w", err)
	}
	defer rows.Close()

	var capabilities []*capability.Capability
	for rows.Next() {
		c, err := r.scanCapability(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan capability: %w", err)
		}
		capabilities = append(capabilities, c)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate capabilities: %w", err)
	}

	return capabilities, nil
}

// Update updates an existing capability.
func (r *CapabilityRepository) Update(ctx context.Context, c *capability.Capability) error {
	query := `
		UPDATE capabilities SET
			display_name = $2,
			description = $3,
			icon = $4,
			color = $5,
			category = $6,
			sort_order = $7,
			updated_at = $8
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		c.ID.String(),
		c.DisplayName,
		c.Description,
		c.Icon,
		c.Color,
		c.Category,
		c.SortOrder,
		c.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to update capability: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("%w: capability not found", shared.ErrNotFound)
	}

	return nil
}

// Delete deletes a capability by ID.
func (r *CapabilityRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM capabilities WHERE id = $1 AND is_builtin = false"

	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete capability: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("%w: capability not found or is a builtin capability", shared.ErrNotFound)
	}

	return nil
}

// ExistsByName checks if a capability with the given name exists in the scope.
func (r *CapabilityRepository) ExistsByName(ctx context.Context, tenantID *shared.ID, name string) (bool, error) {
	var query string
	var args []any

	if tenantID == nil {
		query = "SELECT EXISTS(SELECT 1 FROM capabilities WHERE tenant_id IS NULL AND name = $1)"
		args = []any{name}
	} else {
		query = "SELECT EXISTS(SELECT 1 FROM capabilities WHERE tenant_id = $1 AND name = $2)"
		args = []any{tenantID.String(), name}
	}

	var exists bool
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check capability existence: %w", err)
	}

	return exists, nil
}

// CountByTenant returns the number of custom capabilities for a tenant.
func (r *CapabilityRepository) CountByTenant(ctx context.Context, tenantID shared.ID) (int64, error) {
	query := "SELECT COUNT(*) FROM capabilities WHERE tenant_id = $1"

	var count int64
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count tenant capabilities: %w", err)
	}

	return count, nil
}

// GetCategories returns all unique capability categories.
func (r *CapabilityRepository) GetCategories(ctx context.Context) ([]string, error) {
	query := "SELECT DISTINCT category FROM capabilities WHERE category IS NOT NULL ORDER BY category"

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get capability categories: %w", err)
	}
	defer rows.Close()

	var categories []string
	for rows.Next() {
		var category string
		if err := rows.Scan(&category); err != nil {
			return nil, fmt.Errorf("failed to scan category: %w", err)
		}
		categories = append(categories, category)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate categories: %w", err)
	}

	return categories, nil
}

// GetUsageStats returns usage statistics for a capability.
// Checks both the tool_capabilities junction table AND tools.capabilities array
// Also checks agents.capabilities array for agent counts.
func (r *CapabilityRepository) GetUsageStats(ctx context.Context, capabilityID shared.ID) (*capability.CapabilityUsageStats, error) {
	// First get the capability name (needed for array lookups)
	var capName string
	nameQuery := "SELECT name FROM capabilities WHERE id = $1"
	err := r.db.QueryRowContext(ctx, nameQuery, capabilityID.String()).Scan(&capName)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: capability not found", shared.ErrNotFound)
		}
		return nil, fmt.Errorf("failed to get capability name: %w", err)
	}

	stats := &capability.CapabilityUsageStats{}

	// Count tools using this capability (via junction table OR array)
	toolQuery := `
		SELECT DISTINCT t.name
		FROM tools t
		LEFT JOIN tool_capabilities tc ON tc.tool_id = t.id AND tc.capability_id = $1
		WHERE tc.capability_id IS NOT NULL
		   OR $2 = ANY(t.capabilities)
		ORDER BY t.name
		LIMIT 10
	`
	toolRows, err := r.db.QueryContext(ctx, toolQuery, capabilityID.String(), capName)
	if err != nil {
		return nil, fmt.Errorf("failed to count tools: %w", err)
	}
	defer toolRows.Close()

	for toolRows.Next() {
		var toolName string
		if err := toolRows.Scan(&toolName); err != nil {
			return nil, fmt.Errorf("failed to scan tool name: %w", err)
		}
		stats.ToolNames = append(stats.ToolNames, toolName)
	}
	if err := toolRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}
	stats.ToolCount = len(stats.ToolNames)

	// Count agents with this capability (via array)
	agentQuery := `
		SELECT name FROM agents
		WHERE $1 = ANY(capabilities)
		ORDER BY name
		LIMIT 10
	`
	agentRows, err := r.db.QueryContext(ctx, agentQuery, capName)
	if err != nil {
		return nil, fmt.Errorf("failed to count agents: %w", err)
	}
	defer agentRows.Close()

	for agentRows.Next() {
		var agentName string
		if err := agentRows.Scan(&agentName); err != nil {
			return nil, fmt.Errorf("failed to scan agent name: %w", err)
		}
		stats.AgentNames = append(stats.AgentNames, agentName)
	}
	if err := agentRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}
	stats.AgentCount = len(stats.AgentNames)

	return stats, nil
}

// GetUsageStatsBatch returns usage statistics for multiple capabilities.
// Performance: Uses single queries with UNNEST to avoid N+1 problem.
// Total queries: 3 (names, tools, agents) regardless of batch size.
func (r *CapabilityRepository) GetUsageStatsBatch(ctx context.Context, capabilityIDs []shared.ID) (map[shared.ID]*capability.CapabilityUsageStats, error) {
	if len(capabilityIDs) == 0 {
		return map[shared.ID]*capability.CapabilityUsageStats{}, nil
	}

	result := make(map[shared.ID]*capability.CapabilityUsageStats)
	for _, id := range capabilityIDs {
		result[id] = &capability.CapabilityUsageStats{}
	}

	// Build placeholders for parameterized query
	placeholders := make([]string, len(capabilityIDs))
	args := make([]any, len(capabilityIDs))
	for i, id := range capabilityIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id.String()
	}
	placeholderStr := strings.Join(placeholders, ", ")

	// Query 1: Get capability id->name mapping
	nameQuery := fmt.Sprintf("SELECT id, name FROM capabilities WHERE id IN (%s)", placeholderStr)
	nameRows, err := r.db.QueryContext(ctx, nameQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get capability names: %w", err)
	}
	defer nameRows.Close()

	idToName := make(map[string]string)
	nameToID := make(map[string]shared.ID)
	capNames := make([]string, 0, len(capabilityIDs))
	for nameRows.Next() {
		var idStr, name string
		if err := nameRows.Scan(&idStr, &name); err != nil {
			return nil, fmt.Errorf("failed to scan capability: %w", err)
		}
		idToName[idStr] = name
		id, _ := shared.IDFromString(idStr)
		nameToID[name] = id
		capNames = append(capNames, name)
	}
	if err := nameRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	// Query 2: Count tools for each capability (single GROUP BY query)
	toolQuery := `
		SELECT c.id, COUNT(DISTINCT t.id)
		FROM capabilities c
		LEFT JOIN tool_capabilities tc ON tc.capability_id = c.id
		LEFT JOIN tools t ON (tc.tool_id = t.id OR c.name = ANY(t.capabilities))
		WHERE c.id IN (` + placeholderStr + `)
		GROUP BY c.id
	`
	toolRows, err := r.db.QueryContext(ctx, toolQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to count tools: %w", err)
	}
	defer toolRows.Close()

	for toolRows.Next() {
		var idStr string
		var count int
		if err := toolRows.Scan(&idStr, &count); err != nil {
			return nil, fmt.Errorf("failed to scan tool count: %w", err)
		}
		id, _ := shared.IDFromString(idStr)
		if stats, ok := result[id]; ok {
			stats.ToolCount = count
		}
	}
	if err := toolRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	// Query 3: Count agents for ALL capability names in SINGLE query using UNNEST
	// This fixes the N+1 query problem - O(1) queries instead of O(n)
	if len(capNames) > 0 {
		// Build name placeholders
		namePlaceholders := make([]string, len(capNames))
		nameArgs := make([]any, len(capNames))
		for i, name := range capNames {
			namePlaceholders[i] = fmt.Sprintf("$%d", i+1)
			nameArgs[i] = name
		}

		agentQuery := `
			SELECT cap_name, COUNT(DISTINCT a.id) as agent_count
			FROM UNNEST(ARRAY[` + strings.Join(namePlaceholders, ", ") + `]::text[]) AS cap_name
			LEFT JOIN agents a ON cap_name = ANY(a.capabilities)
			GROUP BY cap_name
		`
		agentRows, err := r.db.QueryContext(ctx, agentQuery, nameArgs...)
		if err != nil {
			return nil, fmt.Errorf("failed to count agents: %w", err)
		}
		defer agentRows.Close()

		for agentRows.Next() {
			var capName string
			var count int
			if err := agentRows.Scan(&capName, &count); err != nil {
				return nil, fmt.Errorf("failed to scan agent count: %w", err)
			}
			if id, ok := nameToID[capName]; ok {
				if stats, ok := result[id]; ok {
					stats.AgentCount = count
				}
			}
		}
		if err := agentRows.Err(); err != nil {
			return nil, fmt.Errorf("iterate rows: %w", err)
		}
	}

	return result, nil
}

// ToolCapabilityRepository implements the junction table operations.
type ToolCapabilityRepository struct {
	db *DB
}

// NewToolCapabilityRepository creates a new ToolCapabilityRepository.
func NewToolCapabilityRepository(db *DB) *ToolCapabilityRepository {
	return &ToolCapabilityRepository{db: db}
}

// AddCapabilityToTool adds a capability to a tool.
// Security: Validates that the tool belongs to the tenant (or is a platform tool for admins).
func (r *ToolCapabilityRepository) AddCapabilityToTool(ctx context.Context, tenantID *shared.ID, toolID, capabilityID shared.ID) error {
	// Security: Validate tool ownership
	if err := r.validateToolOwnership(ctx, tenantID, toolID); err != nil {
		return err
	}

	// Security: Validate capability is accessible
	if err := r.ValidateCapabilitiesAccessible(ctx, tenantID, []shared.ID{capabilityID}); err != nil {
		return err
	}

	query := `
		INSERT INTO tool_capabilities (tool_id, capability_id, created_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (tool_id, capability_id) DO NOTHING
	`

	_, err := r.db.ExecContext(ctx, query, toolID.String(), capabilityID.String())
	if err != nil {
		return fmt.Errorf("failed to add capability to tool: %w", err)
	}

	return nil
}

// RemoveCapabilityFromTool removes a capability from a tool.
// Security: Validates that the tool belongs to the tenant.
func (r *ToolCapabilityRepository) RemoveCapabilityFromTool(ctx context.Context, tenantID *shared.ID, toolID, capabilityID shared.ID) error {
	// Security: Validate tool ownership
	if err := r.validateToolOwnership(ctx, tenantID, toolID); err != nil {
		return err
	}

	query := "DELETE FROM tool_capabilities WHERE tool_id = $1 AND capability_id = $2"

	_, err := r.db.ExecContext(ctx, query, toolID.String(), capabilityID.String())
	if err != nil {
		return fmt.Errorf("failed to remove capability from tool: %w", err)
	}

	return nil
}

// SetToolCapabilities replaces all capabilities for a tool.
// Security: Validates that the tool belongs to the tenant and all capabilities are accessible.
func (r *ToolCapabilityRepository) SetToolCapabilities(ctx context.Context, tenantID *shared.ID, toolID shared.ID, capabilityIDs []shared.ID) error {
	// Security: Validate tool ownership
	if err := r.validateToolOwnership(ctx, tenantID, toolID); err != nil {
		return err
	}

	// Security: Validate all capabilities are accessible by this tenant
	if len(capabilityIDs) > 0 {
		if err := r.ValidateCapabilitiesAccessible(ctx, tenantID, capabilityIDs); err != nil {
			return err
		}
	}

	// Use transaction for atomicity
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Delete existing capabilities
	_, err = tx.ExecContext(ctx, "DELETE FROM tool_capabilities WHERE tool_id = $1", toolID.String())
	if err != nil {
		return fmt.Errorf("failed to clear tool capabilities: %w", err)
	}

	// Insert new capabilities
	if len(capabilityIDs) > 0 {
		query := "INSERT INTO tool_capabilities (tool_id, capability_id, created_at) VALUES "
		args := make([]any, 0, len(capabilityIDs)*2)
		placeholders := make([]string, len(capabilityIDs))

		for i, capID := range capabilityIDs {
			placeholders[i] = fmt.Sprintf("($%d, $%d, NOW())", i*2+1, i*2+2)
			args = append(args, toolID.String(), capID.String())
		}

		query += strings.Join(placeholders, ", ") + " ON CONFLICT (tool_id, capability_id) DO NOTHING"
		_, err = tx.ExecContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("failed to insert tool capabilities: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// validateToolOwnership checks if the tool belongs to the tenant.
// If tenantID is nil, it's a platform operation (admin) - allow platform tools only.
// If tenantID is set, only allow tools belonging to that tenant.
func (r *ToolCapabilityRepository) validateToolOwnership(ctx context.Context, tenantID *shared.ID, toolID shared.ID) error {
	var query string
	var args []any

	if tenantID == nil {
		// Platform operation: only allow platform tools (tenant_id IS NULL)
		query = "SELECT 1 FROM tools WHERE id = $1 AND tenant_id IS NULL"
		args = []any{toolID.String()}
	} else {
		// Tenant operation: only allow tools belonging to this tenant
		query = "SELECT 1 FROM tools WHERE id = $1 AND tenant_id = $2"
		args = []any{toolID.String(), tenantID.String()}
	}

	var exists int
	err := r.db.QueryRowContext(ctx, query, args...).Scan(&exists)
	if err == sql.ErrNoRows {
		return fmt.Errorf("%w: tool not found or access denied", shared.ErrForbidden)
	}
	if err != nil {
		return fmt.Errorf("failed to validate tool ownership: %w", err)
	}

	return nil
}

// ValidateCapabilitiesAccessible checks if all capability IDs are accessible by the tenant.
// A capability is accessible if it's a platform capability (tenant_id IS NULL) or belongs to the tenant.
func (r *ToolCapabilityRepository) ValidateCapabilitiesAccessible(ctx context.Context, tenantID *shared.ID, capabilityIDs []shared.ID) error {
	if len(capabilityIDs) == 0 {
		return nil
	}

	// Build query to count accessible capabilities
	placeholders := make([]string, len(capabilityIDs))
	args := make([]any, 0, len(capabilityIDs)+1)

	for i, capID := range capabilityIDs {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args = append(args, capID.String())
	}

	var query string
	if tenantID == nil {
		// Platform operation: only platform capabilities accessible
		query = fmt.Sprintf(`
			SELECT COUNT(*) FROM capabilities
			WHERE id IN (%s) AND tenant_id IS NULL
		`, strings.Join(placeholders, ", "))
	} else {
		// Tenant operation: platform + own tenant capabilities accessible
		query = fmt.Sprintf(`
			SELECT COUNT(*) FROM capabilities
			WHERE id IN (%s) AND (tenant_id IS NULL OR tenant_id = $%d)
		`, strings.Join(placeholders, ", "), len(capabilityIDs)+1)
		args = append(args, tenantID.String())
	}

	var count int
	if err := r.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return fmt.Errorf("failed to validate capabilities: %w", err)
	}

	if count != len(capabilityIDs) {
		return fmt.Errorf("%w: one or more capabilities are not accessible", shared.ErrForbidden)
	}

	return nil
}

// GetToolCapabilities returns all capabilities for a tool.
func (r *ToolCapabilityRepository) GetToolCapabilities(ctx context.Context, toolID shared.ID) ([]*capability.Capability, error) {
	query := `
		SELECT
			c.id, c.tenant_id, c.name, c.display_name, c.description,
			c.icon, c.color, c.category, c.is_builtin, c.sort_order,
			c.created_by, c.created_at, c.updated_at
		FROM capabilities c
		INNER JOIN tool_capabilities tc ON tc.capability_id = c.id
		WHERE tc.tool_id = $1
		ORDER BY c.sort_order ASC, c.display_name ASC
	`

	rows, err := r.db.QueryContext(ctx, query, toolID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get tool capabilities: %w", err)
	}
	defer rows.Close()

	var capabilities []*capability.Capability
	for rows.Next() {
		c, err := r.scanCapability(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan capability: %w", err)
		}
		capabilities = append(capabilities, c)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate capabilities: %w", err)
	}

	return capabilities, nil
}

// scanCapability scans a capability row (reusing CapabilityRepository logic).
func (r *ToolCapabilityRepository) scanCapability(row interface{ Scan(...any) error }) (*capability.Capability, error) {
	var (
		id          string
		tenantID    sql.NullString
		name        string
		displayName string
		description sql.NullString
		icon        string
		color       string
		category    sql.NullString
		isBuiltin   bool
		sortOrder   int
		createdBy   sql.NullString
		createdAt   sql.NullTime
		updatedAt   sql.NullTime
	)

	err := row.Scan(
		&id, &tenantID, &name, &displayName, &description,
		&icon, &color, &category, &isBuiltin, &sortOrder,
		&createdBy, &createdAt, &updatedAt,
	)
	if err != nil {
		return nil, err
	}

	c := &capability.Capability{
		Name:        name,
		DisplayName: displayName,
		Icon:        icon,
		Color:       color,
		IsBuiltin:   isBuiltin,
		SortOrder:   sortOrder,
	}

	c.ID, _ = shared.IDFromString(id)

	if tenantID.Valid {
		tid, _ := shared.IDFromString(tenantID.String)
		c.TenantID = &tid
	}

	if description.Valid {
		c.Description = description.String
	}

	if category.Valid {
		c.Category = category.String
	}

	if createdBy.Valid {
		cid, _ := shared.IDFromString(createdBy.String)
		c.CreatedBy = &cid
	}

	if createdAt.Valid {
		c.CreatedAt = createdAt.Time
	}

	if updatedAt.Valid {
		c.UpdatedAt = updatedAt.Time
	}

	return c, nil
}

// GetToolsByCapability returns all tool IDs that have a specific capability.
func (r *ToolCapabilityRepository) GetToolsByCapability(ctx context.Context, capabilityID shared.ID) ([]shared.ID, error) {
	query := "SELECT tool_id FROM tool_capabilities WHERE capability_id = $1"

	rows, err := r.db.QueryContext(ctx, query, capabilityID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get tools by capability: %w", err)
	}
	defer rows.Close()

	var toolIDs []shared.ID
	for rows.Next() {
		var toolIDStr string
		if err := rows.Scan(&toolIDStr); err != nil {
			return nil, fmt.Errorf("failed to scan tool ID: %w", err)
		}
		toolID, _ := shared.IDFromString(toolIDStr)
		toolIDs = append(toolIDs, toolID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate tool IDs: %w", err)
	}

	return toolIDs, nil
}

// GetToolsByCapabilityName returns all tool IDs that have a specific capability by name.
func (r *ToolCapabilityRepository) GetToolsByCapabilityName(ctx context.Context, capabilityName string) ([]shared.ID, error) {
	query := `
		SELECT tc.tool_id
		FROM tool_capabilities tc
		INNER JOIN capabilities c ON c.id = tc.capability_id
		WHERE c.name = $1
	`

	rows, err := r.db.QueryContext(ctx, query, capabilityName)
	if err != nil {
		return nil, fmt.Errorf("failed to get tools by capability name: %w", err)
	}
	defer rows.Close()

	var toolIDs []shared.ID
	for rows.Next() {
		var toolIDStr string
		if err := rows.Scan(&toolIDStr); err != nil {
			return nil, fmt.Errorf("failed to scan tool ID: %w", err)
		}
		toolID, _ := shared.IDFromString(toolIDStr)
		toolIDs = append(toolIDs, toolID)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate tool IDs: %w", err)
	}

	return toolIDs, nil
}
