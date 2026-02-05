package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lib/pq"

	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// PipelineTemplateRepository implements pipeline.TemplateRepository using PostgreSQL.
type PipelineTemplateRepository struct {
	db *DB
}

// NewPipelineTemplateRepository creates a new PipelineTemplateRepository.
func NewPipelineTemplateRepository(db *DB) *PipelineTemplateRepository {
	return &PipelineTemplateRepository{db: db}
}

// Create persists a new pipeline template.
func (r *PipelineTemplateRepository) Create(ctx context.Context, t *pipeline.Template) error {
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
		INSERT INTO pipeline_templates (
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
func (r *PipelineTemplateRepository) GetByID(ctx context.Context, id shared.ID) (*pipeline.Template, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanTemplate(row)
}

// GetByTenantAndID retrieves a template by tenant and ID.
func (r *PipelineTemplateRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*pipeline.Template, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanTemplate(row)
}

// GetByName retrieves a template by name and version.
func (r *PipelineTemplateRepository) GetByName(ctx context.Context, tenantID shared.ID, name string, version int) (*pipeline.Template, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND name = $2 AND version = $3"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), name, version)
	return r.scanTemplate(row)
}

// List lists templates with filters and pagination.
func (r *PipelineTemplateRepository) List(ctx context.Context, filter pipeline.TemplateFilter, page pagination.Pagination) (pagination.Result[*pipeline.Template], error) {
	var result pagination.Result[*pipeline.Template]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM pipeline_templates"
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

	var templates []*pipeline.Template
	var templateIDs []string
	for rows.Next() {
		t, err := r.scanTemplateFromRows(rows)
		if err != nil {
			return result, err
		}
		templates = append(templates, t)
		templateIDs = append(templateIDs, t.ID.String())
	}

	// Load steps for all templates in a single batch query
	if len(templateIDs) > 0 {
		stepsQuery := `
			SELECT id, pipeline_id, step_key, name, description, step_order,
			       ui_position_x, ui_position_y,
			       tool, capabilities, config, timeout_seconds,
			       depends_on, condition_type, condition_value,
			       max_retries, retry_delay_seconds, created_at
			FROM pipeline_steps
			WHERE pipeline_id = ANY($1)
			ORDER BY pipeline_id, step_order ASC
		`

		stepRows, err := r.db.QueryContext(ctx, stepsQuery, pq.Array(templateIDs))
		if err != nil {
			return result, fmt.Errorf("failed to load pipeline steps: %w", err)
		}
		defer stepRows.Close()

		// Build a map of template ID -> steps
		stepsMap := make(map[string][]*pipeline.Step)
		for stepRows.Next() {
			step, err := scanStep(stepRows)
			if err != nil {
				return result, err
			}
			stepsMap[step.PipelineID.String()] = append(stepsMap[step.PipelineID.String()], step)
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
func (r *PipelineTemplateRepository) Update(ctx context.Context, t *pipeline.Template) error {
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
		UPDATE pipeline_templates
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
func (r *PipelineTemplateRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM pipeline_templates WHERE id = $1"
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
func (r *PipelineTemplateRepository) DeleteInTx(ctx context.Context, tx *sql.Tx, id shared.ID) error {
	query := "DELETE FROM pipeline_templates WHERE id = $1"
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
func (r *PipelineTemplateRepository) GetWithSteps(ctx context.Context, id shared.ID) (*pipeline.Template, error) {
	template, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Load steps
	stepsQuery := `
		SELECT id, pipeline_id, step_key, name, description, step_order,
		       ui_position_x, ui_position_y,
		       tool, capabilities, config, timeout_seconds,
		       depends_on, condition_type, condition_value,
		       max_retries, retry_delay_seconds, created_at
		FROM pipeline_steps
		WHERE pipeline_id = $1
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

	return template, nil
}

// GetSystemTemplateByID retrieves a system template by ID (for copy-on-use).
func (r *PipelineTemplateRepository) GetSystemTemplateByID(ctx context.Context, id shared.ID) (*pipeline.Template, error) {
	query := r.selectQuery() + " WHERE id = $1 AND is_system_template = true"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanTemplate(row)
}

// ListWithSystemTemplates lists tenant templates + system templates.
// Returns both tenant-specific templates and system templates (marked with is_system_template=true).
func (r *PipelineTemplateRepository) ListWithSystemTemplates(ctx context.Context, tenantID shared.ID, filter pipeline.TemplateFilter, page pagination.Pagination) (pagination.Result[*pipeline.Template], error) {
	var result pagination.Result[*pipeline.Template]

	// Build query that gets both tenant templates AND system templates
	// (tenant_id = $1 OR is_system_template = true)
	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM pipeline_templates"

	var conditions []string
	var args []any
	argIndex := 1

	// Core condition: tenant templates OR system templates
	conditions = append(conditions, fmt.Sprintf("(tenant_id = $%d OR is_system_template = true)", argIndex))
	args = append(args, tenantID.String())
	argIndex++

	// Additional filters
	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIndex))
		args = append(args, *filter.IsActive)
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, wrapLikePattern(filter.Search))
		argIndex++
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

	var templates []*pipeline.Template
	var templateIDs []string
	for rows.Next() {
		t, err := r.scanTemplateFromRows(rows)
		if err != nil {
			return result, err
		}
		templates = append(templates, t)
		templateIDs = append(templateIDs, t.ID.String())
	}

	// Load steps for all templates in a single batch query
	if len(templateIDs) > 0 {
		stepsQuery := `
			SELECT id, pipeline_id, step_key, name, description, step_order,
			       ui_position_x, ui_position_y,
			       tool, capabilities, config, timeout_seconds,
			       depends_on, condition_type, condition_value,
			       max_retries, retry_delay_seconds, created_at
			FROM pipeline_steps
			WHERE pipeline_id = ANY($1)
			ORDER BY pipeline_id, step_order ASC
		`

		stepRows, err := r.db.QueryContext(ctx, stepsQuery, pq.Array(templateIDs))
		if err != nil {
			return result, fmt.Errorf("failed to load pipeline steps: %w", err)
		}
		defer stepRows.Close()

		// Build a map of template ID -> steps
		stepsMap := make(map[string][]*pipeline.Step)
		for stepRows.Next() {
			step, err := scanStep(stepRows)
			if err != nil {
				return result, err
			}
			stepsMap[step.PipelineID.String()] = append(stepsMap[step.PipelineID.String()], step)
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

func (r *PipelineTemplateRepository) selectQuery() string {
	return `
		SELECT id, tenant_id, name, description, version,
		       triggers, settings, is_active, is_system_template,
		       tags, ui_start_position, ui_end_position,
		       created_by, created_at, updated_at
		FROM pipeline_templates
	`
}

func (r *PipelineTemplateRepository) buildWhereClause(filter pipeline.TemplateFilter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID.String())
		argIndex++
	}

	if filter.IsActive != nil {
		conditions = append(conditions, fmt.Sprintf("is_active = $%d", argIndex))
		args = append(args, *filter.IsActive)
		argIndex++
	}

	if filter.IsSystemTemplate != nil {
		conditions = append(conditions, fmt.Sprintf("is_system_template = $%d", argIndex))
		args = append(args, *filter.IsSystemTemplate)
		argIndex++
	}

	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf("(name ILIKE $%d OR description ILIKE $%d)", argIndex, argIndex))
		args = append(args, wrapLikePattern(filter.Search))
		argIndex++
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

func (r *PipelineTemplateRepository) scanTemplate(row *sql.Row) (*pipeline.Template, error) {
	t := &pipeline.Template{}
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
		var pos pipeline.UIPosition
		if json.Unmarshal(uiStartPos, &pos) == nil {
			t.UIStartPosition = &pos
		}
	}
	if len(uiEndPos) > 0 {
		var pos pipeline.UIPosition
		if json.Unmarshal(uiEndPos, &pos) == nil {
			t.UIEndPosition = &pos
		}
	}

	return t, nil
}

func (r *PipelineTemplateRepository) scanTemplateFromRows(rows *sql.Rows) (*pipeline.Template, error) {
	t := &pipeline.Template{}
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
		var pos pipeline.UIPosition
		if json.Unmarshal(uiStartPos, &pos) == nil {
			t.UIStartPosition = &pos
		}
	}
	if len(uiEndPos) > 0 {
		var pos pipeline.UIPosition
		if json.Unmarshal(uiEndPos, &pos) == nil {
			t.UIEndPosition = &pos
		}
	}

	return t, nil
}

func scanStep(rows *sql.Rows) (*pipeline.Step, error) {
	s := &pipeline.Step{}
	var (
		id            string
		pipelineID    string
		capabilities  pq.StringArray
		dependsOn     pq.StringArray
		config        []byte
		conditionType sql.NullString
		conditionVal  sql.NullString
		tool          sql.NullString
	)

	err := rows.Scan(
		&id,
		&pipelineID,
		&s.StepKey,
		&s.Name,
		&s.Description,
		&s.StepOrder,
		&s.UIPosition.X,
		&s.UIPosition.Y,
		&tool,
		&capabilities,
		&config,
		&s.TimeoutSeconds,
		&dependsOn,
		&conditionType,
		&conditionVal,
		&s.MaxRetries,
		&s.RetryDelaySeconds,
		&s.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan pipeline step: %w", err)
	}

	s.ID, _ = shared.IDFromString(id)
	s.PipelineID, _ = shared.IDFromString(pipelineID)
	s.Capabilities = capabilities
	s.DependsOn = dependsOn
	if tool.Valid {
		s.Tool = tool.String
	}

	if len(config) > 0 {
		_ = json.Unmarshal(config, &s.Config)
	}

	if conditionType.Valid {
		s.Condition = pipeline.Condition{
			Type:  pipeline.ConditionType(conditionType.String),
			Value: conditionVal.String,
		}
	} else {
		s.Condition = pipeline.AlwaysCondition()
	}

	return s, nil
}

// PipelineStepRepository implements pipeline.StepRepository using PostgreSQL.
type PipelineStepRepository struct {
	db *DB
}

// NewPipelineStepRepository creates a new PipelineStepRepository.
func NewPipelineStepRepository(db *DB) *PipelineStepRepository {
	return &PipelineStepRepository{db: db}
}

// Create persists a new step.
func (r *PipelineStepRepository) Create(ctx context.Context, s *pipeline.Step) error {
	config, err := json.Marshal(s.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	query := `
		INSERT INTO pipeline_steps (
			id, pipeline_id, step_key, name, description, step_order,
			ui_position_x, ui_position_y,
			tool, capabilities, config, timeout_seconds,
			depends_on, condition_type, condition_value,
			max_retries, retry_delay_seconds, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`

	_, err = r.db.ExecContext(ctx, query,
		s.ID.String(),
		s.PipelineID.String(),
		s.StepKey,
		s.Name,
		s.Description,
		s.StepOrder,
		s.UIPosition.X,
		s.UIPosition.Y,
		nullString(s.Tool),
		pq.Array(s.Capabilities),
		config,
		s.TimeoutSeconds,
		pq.Array(s.DependsOn),
		nullString(string(s.Condition.Type)),
		nullString(s.Condition.Value),
		s.MaxRetries,
		s.RetryDelaySeconds,
		s.CreatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "step already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create pipeline step: %w", err)
	}

	return nil
}

// CreateBatch creates multiple steps.
// OPTIMIZED: Uses batch INSERT instead of individual inserts for better performance.
func (r *PipelineStepRepository) CreateBatch(ctx context.Context, steps []*pipeline.Step) error {
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
	const numCols = 18
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
			s.PipelineID.String(),
			s.StepKey,
			s.Name,
			s.Description,
			s.StepOrder,
			s.UIPosition.X,
			s.UIPosition.Y,
			nullString(s.Tool),
			pq.Array(s.Capabilities),
			config,
			s.TimeoutSeconds,
			pq.Array(s.DependsOn),
			nullString(string(s.Condition.Type)),
			nullString(s.Condition.Value),
			s.MaxRetries,
			s.RetryDelaySeconds,
			s.CreatedAt,
		)
	}

	query := fmt.Sprintf(`
		INSERT INTO pipeline_steps (
			id, pipeline_id, step_key, name, description, step_order,
			ui_position_x, ui_position_y,
			tool, capabilities, config, timeout_seconds,
			depends_on, condition_type, condition_value,
			max_retries, retry_delay_seconds, created_at
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
func (r *PipelineStepRepository) GetByID(ctx context.Context, id shared.ID) (*pipeline.Step, error) {
	query := `
		SELECT id, pipeline_id, step_key, name, description, step_order,
		       ui_position_x, ui_position_y,
		       tool, capabilities, config, timeout_seconds,
		       depends_on, condition_type, condition_value,
		       max_retries, retry_delay_seconds, created_at
		FROM pipeline_steps
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

// GetByPipelineID retrieves all steps for a pipeline.
func (r *PipelineStepRepository) GetByPipelineID(ctx context.Context, pipelineID shared.ID) ([]*pipeline.Step, error) {
	query := `
		SELECT id, pipeline_id, step_key, name, description, step_order,
		       ui_position_x, ui_position_y,
		       tool, capabilities, config, timeout_seconds,
		       depends_on, condition_type, condition_value,
		       max_retries, retry_delay_seconds, created_at
		FROM pipeline_steps
		WHERE pipeline_id = $1
		ORDER BY step_order ASC
	`

	rows, err := r.db.QueryContext(ctx, query, pipelineID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get steps: %w", err)
	}
	defer rows.Close()

	var steps []*pipeline.Step
	for rows.Next() {
		s, err := scanStep(rows)
		if err != nil {
			return nil, err
		}
		steps = append(steps, s)
	}

	return steps, nil
}

// GetByKey retrieves a step by pipeline ID and step key.
func (r *PipelineStepRepository) GetByKey(ctx context.Context, pipelineID shared.ID, stepKey string) (*pipeline.Step, error) {
	query := `
		SELECT id, pipeline_id, step_key, name, description, step_order,
		       ui_position_x, ui_position_y,
		       tool, capabilities, config, timeout_seconds,
		       depends_on, condition_type, condition_value,
		       max_retries, retry_delay_seconds, created_at
		FROM pipeline_steps
		WHERE pipeline_id = $1 AND step_key = $2
	`

	rows, err := r.db.QueryContext(ctx, query, pipelineID.String(), stepKey)
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
func (r *PipelineStepRepository) Update(ctx context.Context, s *pipeline.Step) error {
	config, err := json.Marshal(s.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	query := `
		UPDATE pipeline_steps
		SET name = $2, description = $3, step_order = $4,
		    ui_position_x = $5, ui_position_y = $6,
		    tool = $7, capabilities = $8, config = $9, timeout_seconds = $10,
		    depends_on = $11, condition_type = $12, condition_value = $13,
		    max_retries = $14, retry_delay_seconds = $15
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
		pq.Array(s.Capabilities),
		config,
		s.TimeoutSeconds,
		pq.Array(s.DependsOn),
		nullString(string(s.Condition.Type)),
		nullString(s.Condition.Value),
		s.MaxRetries,
		s.RetryDelaySeconds,
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
func (r *PipelineStepRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM pipeline_steps WHERE id = $1"
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

// DeleteByPipelineID deletes all steps for a pipeline.
func (r *PipelineStepRepository) DeleteByPipelineID(ctx context.Context, pipelineID shared.ID) error {
	query := "DELETE FROM pipeline_steps WHERE pipeline_id = $1"
	_, err := r.db.ExecContext(ctx, query, pipelineID.String())
	return err
}

// DeleteByPipelineIDInTx deletes all steps for a pipeline within a transaction.
func (r *PipelineStepRepository) DeleteByPipelineIDInTx(ctx context.Context, tx *sql.Tx, pipelineID shared.ID) error {
	query := "DELETE FROM pipeline_steps WHERE pipeline_id = $1"
	_, err := tx.ExecContext(ctx, query, pipelineID.String())
	return err
}

// Reorder updates the order of steps.
func (r *PipelineStepRepository) Reorder(ctx context.Context, pipelineID shared.ID, stepOrders map[string]int) error {
	for stepKey, order := range stepOrders {
		query := "UPDATE pipeline_steps SET step_order = $3 WHERE pipeline_id = $1 AND step_key = $2"
		_, err := r.db.ExecContext(ctx, query, pipelineID.String(), stepKey, order)
		if err != nil {
			return fmt.Errorf("failed to reorder step %s: %w", stepKey, err)
		}
	}
	return nil
}

// FindPipelineIDsByToolName finds all active pipeline IDs that use a specific tool.
// Used for cascade deactivation when a tool is deactivated or deleted.
func (r *PipelineStepRepository) FindPipelineIDsByToolName(ctx context.Context, toolName string) ([]shared.ID, error) {
	query := `
		SELECT DISTINCT pt.id
		FROM pipeline_templates pt
		JOIN pipeline_steps ps ON ps.pipeline_id = pt.id
		WHERE ps.tool = $1
		  AND pt.is_active = true
		  AND pt.is_system_template = false
	`

	rows, err := r.db.QueryContext(ctx, query, toolName)
	if err != nil {
		return nil, fmt.Errorf("failed to find pipelines by tool: %w", err)
	}
	defer rows.Close()

	var pipelineIDs []shared.ID
	for rows.Next() {
		var idStr string
		if err := rows.Scan(&idStr); err != nil {
			return nil, fmt.Errorf("failed to scan pipeline id: %w", err)
		}
		id, err := shared.IDFromString(idStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pipeline id: %w", err)
		}
		pipelineIDs = append(pipelineIDs, id)
	}

	return pipelineIDs, nil
}
