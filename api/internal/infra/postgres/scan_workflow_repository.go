package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ScanWorkflowRepository implements scanrun.TemplateRepository using PostgreSQL.
type ScanWorkflowRepository struct {
	db *DB
}

// NewScanWorkflowRepository creates a new ScanWorkflowRepository.
func NewScanWorkflowRepository(db *DB) *ScanWorkflowRepository {
	return &ScanWorkflowRepository{db: db}
}

// Create persists a new scan workflow.
func (r *ScanWorkflowRepository) Create(ctx context.Context, t *scanworkflow.Workflow) error {
	triggers, err := json.Marshal(t.Triggers)
	if err != nil {
		return fmt.Errorf("failed to marshal triggers: %w", err)
	}

	settings, err := json.Marshal(t.Settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	var uiStartPos, uiEndPos []byte
	if t.UIStartPosition != nil {
		uiStartPos, _ = json.Marshal(t.UIStartPosition)
	}
	if t.UIEndPosition != nil {
		uiEndPos, _ = json.Marshal(t.UIEndPosition)
	}

	query := `
		INSERT INTO scan_workflows (
			id, tenant_id, name, description, version,
			triggers, settings, is_active, is_system_template,
			tags, ui_start_position, ui_end_position,
			created_by, created_at, updated_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	_, err = r.db.ExecContext(ctx, query,
		t.ID.String(),
		t.TenantID.String(),
		t.Name,
		t.Description,
		t.Version,
		triggers,
		settings,
		t.IsActive,
		t.IsSystemTemplate,
		pq.Array(t.Tags),
		nullBytes(uiStartPos),
		nullBytes(uiEndPos),
		nullID(t.CreatedBy),
		t.CreatedAt,
		t.UpdatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "pipeline template already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create pipeline template: %w", err)
	}

	return nil
}

// GetByID retrieves a template by its ID.
func (r *ScanWorkflowRepository) GetByID(ctx context.Context, id shared.ID) (*scanworkflow.Workflow, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanTemplate(row)
}

// GetByTenantAndID retrieves a template by tenant and ID.
func (r *ScanWorkflowRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*scanworkflow.Workflow, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanTemplate(row)
}

// GetByName retrieves a template by name and version.
func (r *ScanWorkflowRepository) GetByName(ctx context.Context, tenantID shared.ID, name string, version int) (*scanworkflow.Workflow, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND name = $2 AND version = $3"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), name, version)
	return r.scanTemplate(row)
}

// List lists templates with filters and pagination.
func (r *ScanWorkflowRepository) List(ctx context.Context, filter scanworkflow.Filter, page pagination.Pagination) (pagination.Result[*scanworkflow.Workflow], error) {
	var result pagination.Result[*scanworkflow.Workflow]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM scan_workflows"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count pipeline templates: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list pipeline templates: %w", err)
	}
	defer rows.Close()

	var templates []*scanworkflow.Workflow
	var templateIDs []string
	for rows.Next() {
		t, err := r.scanTemplateFromRows(rows)
		if err != nil {
			return result, err
		}
		templates = append(templates, t)
		templateIDs = append(templateIDs, t.ID.String())
	}
	if err := rows.Err(); err != nil {
		return result, err
	}

	// Load steps for all templates in a single batch query
	if len(templateIDs) > 0 {
		stepsQuery := `
			SELECT id, scan_workflow_id, step_key, name, description, step_order,
			       ui_position_x, ui_position_y,
			       tool, tool_id, capabilities, config, timeout_seconds,
			       depends_on, condition_type, condition_value,
			       max_retries, retry_delay_seconds, created_at, prefer_tools
			FROM scan_workflow_steps
			WHERE scan_workflow_id = ANY($1)
			ORDER BY scan_workflow_id, step_order ASC
		`

		stepRows, err := r.db.QueryContext(ctx, stepsQuery, pq.Array(templateIDs))
		if err != nil {
			return result, fmt.Errorf("failed to load pipeline steps: %w", err)
		}
		defer stepRows.Close()

		// Build a map of template ID -> steps
		stepsMap := make(map[string][]*scanworkflow.Step)
		for stepRows.Next() {
			step, err := scanStep(stepRows)
			if err != nil {
				return result, err
			}
			stepsMap[step.ScanWorkflowID.String()] = append(stepsMap[step.ScanWorkflowID.String()], step)
		}
		if err := stepRows.Err(); err != nil {
			return result, err
		}

		// Assign steps to templates
		for _, t := range templates {
			if steps, ok := stepsMap[t.ID.String()]; ok {
				t.Steps = steps
			}
		}
	}

	return pagination.NewResult(templates, total, page), nil
}

// Update updates a template.
func (r *ScanWorkflowRepository) Update(ctx context.Context, t *scanworkflow.Workflow) error {
	triggers, err := json.Marshal(t.Triggers)
	if err != nil {
		return fmt.Errorf("failed to marshal triggers: %w", err)
	}

	settings, err := json.Marshal(t.Settings)
	if err != nil {
		return fmt.Errorf("failed to marshal settings: %w", err)
	}

	var uiStartPos, uiEndPos []byte
	if t.UIStartPosition != nil {
		uiStartPos, _ = json.Marshal(t.UIStartPosition)
	}
	if t.UIEndPosition != nil {
		uiEndPos, _ = json.Marshal(t.UIEndPosition)
	}

	query := `
		UPDATE scan_workflows
		SET name = $2, description = $3, version = $4,
		    triggers = $5, settings = $6, is_active = $7,
		    tags = $8, ui_start_position = $9, ui_end_position = $10,
		    updated_at = $11
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		t.ID.String(),
		t.Name,
		t.Description,
		t.Version,
		triggers,
		settings,
		t.IsActive,
		pq.Array(t.Tags),
		nullBytes(uiStartPos),
		nullBytes(uiEndPos),
		t.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update pipeline template: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a template.
func (r *ScanWorkflowRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM scan_workflows WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete pipeline template: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// DeleteInTx deletes a template within a transaction.
func (r *ScanWorkflowRepository) DeleteInTx(ctx context.Context, tx *sql.Tx, id shared.ID) error {
	query := "DELETE FROM scan_workflows WHERE id = $1"
	result, err := tx.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete pipeline template in tx: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// GetWithSteps retrieves a template with its steps.
func (r *ScanWorkflowRepository) GetWithSteps(ctx context.Context, id shared.ID) (*scanworkflow.Workflow, error) {
	template, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Load steps
	stepsQuery := `
		SELECT id, scan_workflow_id, step_key, name, description, step_order,
		       ui_position_x, ui_position_y,
		       tool, tool_id, capabilities, config, timeout_seconds,
		       depends_on, condition_type, condition_value,
		       max_retries, retry_delay_seconds, created_at, prefer_tools
		FROM scan_workflow_steps
		WHERE scan_workflow_id = $1
		ORDER BY step_order ASC
	`

	rows, err := r.db.QueryContext(ctx, stepsQuery, id.String())
	if err != nil {
		return nil, fmt.Errorf("failed to load pipeline steps: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		step, err := scanStep(rows)
		if err != nil {
			return nil, err
		}
		template.Steps = append(template.Steps, step)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return template, nil
}

// GetSystemTemplateByID retrieves a system template by ID (for copy-on-use).
func (r *ScanWorkflowRepository) GetSystemTemplateByID(ctx context.Context, id shared.ID) (*scanworkflow.Workflow, error) {
	query := r.selectQuery() + " WHERE id = $1 AND is_system_template = true"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanTemplate(row)
}

// ListWithSystemTemplates lists tenant templates + system templates.
// Returns both tenant-specific templates and system templates (marked with is_system_template=true).
func (r *ScanWorkflowRepository) ListWithSystemTemplates(ctx context.Context, tenantID shared.ID, filter scanworkflow.Filter, page pagination.Pagination) (pagination.Result[*scanworkflow.Workflow], error) {
	var result pagination.Result[*scanworkflow.Workflow]

	// Build query that gets both tenant templates AND system templates
	// (tenant_id = $1 OR is_system_template = true)
	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM scan_workflows"

	var conditions []string
	var args []any

	// Core condition: tenant templates OR system templates
	args = append(args, tenantID.String())
	conditions = append(conditions, fmt.Sprintf("(tenant_id = $%d OR is_system_template = true)", len(args)))

	// Additional filters
	if filter.IsActive != nil {
		args = append(args, *filter.IsActive)
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", len(args)))
	}

	if filter.Search != "" {
		args = append(args, wrapLikePattern(filter.Search))
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", len(args), len(args)))
	}

	whereClause := strings.Join(conditions, " AND ")
	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count pipeline templates: %w", err)
	}

	// Apply pagination - order by: tenant templates first, then system templates
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY is_system_template ASC, created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list pipeline templates: %w", err)
	}
	defer rows.Close()

	var templates []*scanworkflow.Workflow
	var templateIDs []string
	for rows.Next() {
		t, err := r.scanTemplateFromRows(rows)
		if err != nil {
			return result, err
		}
		templates = append(templates, t)
		templateIDs = append(templateIDs, t.ID.String())
	}
	if err := rows.Err(); err != nil {
		return result, err
	}

	// Load steps for all templates in a single batch query
	if len(templateIDs) > 0 {
		stepsQuery := `
			SELECT id, scan_workflow_id, step_key, name, description, step_order,
			       ui_position_x, ui_position_y,
			       tool, tool_id, capabilities, config, timeout_seconds,
			       depends_on, condition_type, condition_value,
			       max_retries, retry_delay_seconds, created_at, prefer_tools
			FROM scan_workflow_steps
			WHERE scan_workflow_id = ANY($1)
			ORDER BY scan_workflow_id, step_order ASC
		`

		stepRows, err := r.db.QueryContext(ctx, stepsQuery, pq.Array(templateIDs))
		if err != nil {
			return result, fmt.Errorf("failed to load pipeline steps: %w", err)
		}
		defer stepRows.Close()

		// Build a map of template ID -> steps
		stepsMap := make(map[string][]*scanworkflow.Step)
		for stepRows.Next() {
			step, err := scanStep(stepRows)
			if err != nil {
				return result, err
			}
			stepsMap[step.ScanWorkflowID.String()] = append(stepsMap[step.ScanWorkflowID.String()], step)
		}
		if err := stepRows.Err(); err != nil {
			return result, err
		}

		// Assign steps to templates
		for _, t := range templates {
			if steps, ok := stepsMap[t.ID.String()]; ok {
				t.Steps = steps
			}
		}
	}

	return pagination.NewResult(templates, total, page), nil
}

func (r *ScanWorkflowRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, name, description, version,
		       triggers, settings, is_active, is_system_template,
		       tags, ui_start_position, ui_end_position,
		       created_by, created_at, updated_at
		FROM scan_workflows
	`
}

func (r *ScanWorkflowRepository) buildWhereClause(filter scanworkflow.Filter) (string, []any) {
	var conditions []string
	var args []any

	if filter.TenantID != nil {
		args = append(args, filter.TenantID.String())
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", len(args)))
	}

	if filter.IsActive != nil {
		args = append(args, *filter.IsActive)
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", len(args)))
	}

	if filter.IsSystemTemplate != nil {
		args = append(args, *filter.IsSystemTemplate)
		conditions = append(conditions, fmt.Sprintf("is_system_template = $%d", len(args)))
	}

	if filter.Search != "" {
		args = append(args, wrapLikePattern(filter.Search))
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", len(args), len(args)))
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

func (r *ScanWorkflowRepository) scanTemplate(row *sql.Row) (*scanworkflow.Workflow, error) {
	t := &scanworkflow.Workflow{}
	var (
		id         string
		tenantID   string
		triggers   []byte
		settings   []byte
		tags       pq.StringArray
		uiStartPos []byte
		uiEndPos   []byte
		createdBy  sql.NullString
	)

	err := row.Scan(
		&id,
		&tenantID,
		&t.Name,
		&t.Description,
		&t.Version,
		&triggers,
		&settings,
		&t.IsActive,
		&t.IsSystemTemplate,
		&tags,
		&uiStartPos,
		&uiEndPos,
		&createdBy,
		&t.CreatedAt,
		&t.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan pipeline template: %w", err)
	}

	t.ID, _ = shared.IDFromString(id)
	t.TenantID, _ = shared.IDFromString(tenantID)
	t.Tags = tags

	if createdBy.Valid {
		createdByID, _ := shared.IDFromString(createdBy.String)
		t.CreatedBy = &createdByID
	}

	if len(triggers) > 0 {
		_ = json.Unmarshal(triggers, &t.Triggers)
	}
	if len(settings) > 0 {
		_ = json.Unmarshal(settings, &t.Settings)
	}
	if len(uiStartPos) > 0 {
		var pos scanworkflow.UIPosition
		if json.Unmarshal(uiStartPos, &pos) == nil {
			t.UIStartPosition = &pos
		}
	}
	if len(uiEndPos) > 0 {
		var pos scanworkflow.UIPosition
		if json.Unmarshal(uiEndPos, &pos) == nil {
			t.UIEndPosition = &pos
		}
	}

	return t, nil
}

func (r *ScanWorkflowRepository) scanTemplateFromRows(rows *sql.Rows) (*scanworkflow.Workflow, error) {
	t := &scanworkflow.Workflow{}
	var (
		id         string
		tenantID   string
		triggers   []byte
		settings   []byte
		tags       pq.StringArray
		uiStartPos []byte
		uiEndPos   []byte
		createdBy  sql.NullString
	)

	err := rows.Scan(
		&id,
		&tenantID,
		&t.Name,
		&t.Description,
		&t.Version,
		&triggers,
		&settings,
		&t.IsActive,
		&t.IsSystemTemplate,
		&tags,
		&uiStartPos,
		&uiEndPos,
		&createdBy,
		&t.CreatedAt,
		&t.UpdatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan pipeline template: %w", err)
	}

	t.ID, _ = shared.IDFromString(id)
	t.TenantID, _ = shared.IDFromString(tenantID)
	t.Tags = tags

	if createdBy.Valid {
		createdByID, _ := shared.IDFromString(createdBy.String)
		t.CreatedBy = &createdByID
	}

	if len(triggers) > 0 {
		_ = json.Unmarshal(triggers, &t.Triggers)
	}
	if len(settings) > 0 {
		_ = json.Unmarshal(settings, &t.Settings)
	}
	if len(uiStartPos) > 0 {
		var pos scanworkflow.UIPosition
		if json.Unmarshal(uiStartPos, &pos) == nil {
			t.UIStartPosition = &pos
		}
	}
	if len(uiEndPos) > 0 {
		var pos scanworkflow.UIPosition
		if json.Unmarshal(uiEndPos, &pos) == nil {
			t.UIEndPosition = &pos
		}
	}

	return t, nil
}

func scanStep(rows *sql.Rows) (*scanworkflow.Step, error) {
	s := &scanworkflow.Step{}
	var (
		id             string
		scanWorkflowID string
		capabilities   pq.StringArray
		dependsOn      pq.StringArray
		config         []byte
		conditionType  sql.NullString
		conditionVal   sql.NullString
		tool           sql.NullString
		toolID         sql.NullString
		uiPosX         sql.NullFloat64
		uiPosY         sql.NullFloat64
		description    sql.NullString
		preferTools    pq.StringArray
	)

	err := rows.Scan(
		&id,
		&scanWorkflowID,
		&s.StepKey,
		&s.Name,
		&description,
		&s.StepOrder,
		&uiPosX,
		&uiPosY,
		&tool,
		&toolID,
		&capabilities,
		&config,
		&s.TimeoutSeconds,
		&dependsOn,
		&conditionType,
		&conditionVal,
		&s.MaxRetries,
		&s.RetryDelaySeconds,
		&s.CreatedAt,
		&preferTools,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan pipeline step: %w", err)
	}
	s.PreferTools = preferTools
	s.Description = description.String

	s.ID, _ = shared.IDFromString(id)
	s.ScanWorkflowID, _ = shared.IDFromString(scanWorkflowID)
	s.Capabilities = capabilities
	s.DependsOn = dependsOn
	if uiPosX.Valid {
		s.UIPosition.X = uiPosX.Float64
	}
	if uiPosY.Valid {
		s.UIPosition.Y = uiPosY.Float64
	}
	if tool.Valid {
		s.Tool = tool.String
	}
	if toolID.Valid {
		parsedToolID, err := shared.IDFromString(toolID.String)
		if err == nil {
			s.ToolID = &parsedToolID
		}
	}

	if len(config) > 0 {
		_ = json.Unmarshal(config, &s.Config)
	}

	if conditionType.Valid {
		s.Condition = scanworkflow.Condition{
			Type:  scanworkflow.ConditionType(conditionType.String),
			Value: conditionVal.String,
		}
	} else {
		s.Condition = scanworkflow.AlwaysCondition()
	}

	return s, nil
}

// ScanWorkflowStepRepository implements scanrun.StepRepository using PostgreSQL.
type ScanWorkflowStepRepository struct {
	db *DB
}

// NewScanWorkflowStepRepository creates a new ScanWorkflowStepRepository.
func NewScanWorkflowStepRepository(db *DB) *ScanWorkflowStepRepository {
	return &ScanWorkflowStepRepository{db: db}
}

// Create persists a new step.
func (r *ScanWorkflowStepRepository) Create(ctx context.Context, s *scanworkflow.Step) error {
	return insertStep(ctx, r.db, s)
}

// CreateBatch creates multiple steps.
// OPTIMIZED: Uses batch INSERT instead of individual inserts for better performance.
func (r *ScanWorkflowStepRepository) CreateBatch(ctx context.Context, steps []*scanworkflow.Step) error {
	if len(steps) == 0 {
		return nil
	}

	// For small batches, use simple loop (overhead of building batch query not worth it)
	if len(steps) <= 3 {
		for _, s := range steps {
			if err := r.Create(ctx, s); err != nil {
				return err
			}
		}
		return nil
	}

	// Build batch INSERT query
	const numCols = 20
	valueStrings := make([]string, 0, len(steps))
	valueArgs := make([]any, 0, len(steps)*numCols)

	for i, s := range steps {
		config, err := json.Marshal(s.Config)
		if err != nil {
			return fmt.Errorf("failed to marshal config for step %d: %w", i, err)
		}

		baseIdx := i * numCols
		placeholders := make([]string, numCols)
		for j := range numCols {
			placeholders[j] = fmt.Sprintf("$%d", baseIdx+j+1)
		}
		valueStrings = append(valueStrings, "("+strings.Join(placeholders, ", ")+")")

		valueArgs = append(valueArgs,
			s.ID.String(),
			s.ScanWorkflowID.String(),
			s.StepKey,
			s.Name,
			s.Description,
			s.StepOrder,
			s.UIPosition.X,
			s.UIPosition.Y,
			nullString(s.Tool),
			nullID(s.ToolID),
			pq.Array(s.Capabilities),
			config,
			s.TimeoutSeconds,
			pq.Array(s.DependsOn),
			nullString(string(s.Condition.Type)),
			nullString(s.Condition.Value),
			s.MaxRetries,
			s.RetryDelaySeconds,
			s.CreatedAt,
			pq.Array(nonNilStrings(s.PreferTools)),
		)
	}

	query := fmt.Sprintf(`
		INSERT INTO scan_workflow_steps (
			id, scan_workflow_id, step_key, name, description, step_order,
			ui_position_x, ui_position_y,
			tool, tool_id, capabilities, config, timeout_seconds,
			depends_on, condition_type, condition_value,
			max_retries, retry_delay_seconds, created_at, prefer_tools
		)
		VALUES %s
	`, strings.Join(valueStrings, ", "))

	_, err := r.db.ExecContext(ctx, query, valueArgs...)
	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "step already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to batch create pipeline steps: %w", err)
	}

	return nil
}

// GetByID retrieves a step by ID.
func (r *ScanWorkflowStepRepository) GetByID(ctx context.Context, id shared.ID) (*scanworkflow.Step, error) {
	query := `
		SELECT id, scan_workflow_id, step_key, name, description, step_order,
		       ui_position_x, ui_position_y,
		       tool, tool_id, capabilities, config, timeout_seconds,
		       depends_on, condition_type, condition_value,
		       max_retries, retry_delay_seconds, created_at, prefer_tools
		FROM scan_workflow_steps
		WHERE id = $1
	`

	rows, err := r.db.QueryContext(ctx, query, id.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get step: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, shared.ErrNotFound
	}

	return scanStep(rows)
}

// GetByScanWorkflowID retrieves all steps for a scan workflow.
func (r *ScanWorkflowStepRepository) GetByScanWorkflowID(ctx context.Context, scanWorkflowID shared.ID) ([]*scanworkflow.Step, error) {
	query := `
		SELECT id, scan_workflow_id, step_key, name, description, step_order,
		       ui_position_x, ui_position_y,
		       tool, tool_id, capabilities, config, timeout_seconds,
		       depends_on, condition_type, condition_value,
		       max_retries, retry_delay_seconds, created_at, prefer_tools
		FROM scan_workflow_steps
		WHERE scan_workflow_id = $1
		ORDER BY step_order ASC
	`

	rows, err := r.db.QueryContext(ctx, query, scanWorkflowID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get steps: %w", err)
	}
	defer rows.Close()

	var steps []*scanworkflow.Step
	for rows.Next() {
		s, err := scanStep(rows)
		if err != nil {
			return nil, err
		}
		steps = append(steps, s)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return steps, nil
}

// GetByKey retrieves a step by scan workflow ID and step key.
func (r *ScanWorkflowStepRepository) GetByKey(ctx context.Context, scanWorkflowID shared.ID, stepKey string) (*scanworkflow.Step, error) {
	query := `
		SELECT id, scan_workflow_id, step_key, name, description, step_order,
		       ui_position_x, ui_position_y,
		       tool, tool_id, capabilities, config, timeout_seconds,
		       depends_on, condition_type, condition_value,
		       max_retries, retry_delay_seconds, created_at, prefer_tools
		FROM scan_workflow_steps
		WHERE scan_workflow_id = $1 AND step_key = $2
	`

	rows, err := r.db.QueryContext(ctx, query, scanWorkflowID.String(), stepKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get step: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, shared.ErrNotFound
	}

	return scanStep(rows)
}

// Update updates a step.
func (r *ScanWorkflowStepRepository) Update(ctx context.Context, s *scanworkflow.Step) error {
	config, err := json.Marshal(s.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	query := `
		UPDATE scan_workflow_steps
		SET name = $2, description = $3, step_order = $4,
		    ui_position_x = $5, ui_position_y = $6,
		    tool = $7, tool_id = $8, capabilities = $9, config = $10, timeout_seconds = $11,
		    depends_on = $12, condition_type = $13, condition_value = $14,
		    max_retries = $15, retry_delay_seconds = $16, prefer_tools = $17
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		s.ID.String(),
		s.Name,
		s.Description,
		s.StepOrder,
		s.UIPosition.X,
		s.UIPosition.Y,
		nullString(s.Tool),
		nullID(s.ToolID),
		pq.Array(s.Capabilities),
		config,
		s.TimeoutSeconds,
		pq.Array(s.DependsOn),
		nullString(string(s.Condition.Type)),
		nullString(s.Condition.Value),
		s.MaxRetries,
		s.RetryDelaySeconds,
		pq.Array(nonNilStrings(s.PreferTools)),
	)

	if err != nil {
		return fmt.Errorf("failed to update step: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a step.
func (r *ScanWorkflowStepRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM scan_workflow_steps WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete step: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// DeleteByScanWorkflowID deletes all steps for a scan workflow.
func (r *ScanWorkflowStepRepository) DeleteByScanWorkflowID(ctx context.Context, scanWorkflowID shared.ID) error {
	query := "DELETE FROM scan_workflow_steps WHERE scan_workflow_id = $1"
	_, err := r.db.ExecContext(ctx, query, scanWorkflowID.String())
	return err
}

// DeleteByScanWorkflowIDInTx deletes all steps for a scan workflow within a transaction.
func (r *ScanWorkflowStepRepository) DeleteByScanWorkflowIDInTx(ctx context.Context, tx *sql.Tx, scanWorkflowID shared.ID) error {
	query := "DELETE FROM scan_workflow_steps WHERE scan_workflow_id = $1"
	_, err := tx.ExecContext(ctx, query, scanWorkflowID.String())
	return err
}

// Reorder updates the order of steps.
func (r *ScanWorkflowStepRepository) Reorder(ctx context.Context, scanWorkflowID shared.ID, stepOrders map[string]int) error {
	for stepKey, order := range stepOrders {
		query := "UPDATE scan_workflow_steps SET step_order = $3 WHERE scan_workflow_id = $1 AND step_key = $2"
		_, err := r.db.ExecContext(ctx, query, scanWorkflowID.String(), stepKey, order)
		if err != nil {
			return fmt.Errorf("failed to reorder step %s: %w", stepKey, err)
		}
	}
	return nil
}

// FindScanWorkflowIDsByToolName finds the tenant's active scan workflow IDs that use a
// specific tool. Used for cascade deactivation when one of the tenant's tools
// is deactivated or deleted. Tenant-scoped: tool names are unique only per
// tenant, so without the filter a tenant's custom tool named like a platform
// tool deactivated every other tenant's scan workflows using that name.
func (r *ScanWorkflowStepRepository) FindScanWorkflowIDsByToolName(ctx context.Context, tenantID shared.ID, toolName string) ([]shared.ID, error) {
	query := `
		SELECT DISTINCT pt.id
		FROM scan_workflows pt
		JOIN scan_workflow_steps ps ON ps.scan_workflow_id = pt.id
		WHERE ps.tool = $1
		  AND pt.tenant_id = $2
		  AND pt.is_active = true
		  AND pt.is_system_template = false
	`

	rows, err := r.db.QueryContext(ctx, query, toolName, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to find pipelines by tool: %w", err)
	}
	defer rows.Close()

	var scanWorkflowIDs []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan pipeline id: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pipeline id: %w", err)
		}
		scanWorkflowIDs = append(scanWorkflowIDs, id)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pipeline ids: %w", err)
	}

	return scanWorkflowIDs, nil
}
