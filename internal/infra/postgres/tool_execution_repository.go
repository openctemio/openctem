package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tool"
	"github.com/openctemio/api/pkg/pagination"
)

// ToolExecutionRepository implements tool.ToolExecutionRepository.
type ToolExecutionRepository struct {
	db *DB
}

// NewToolExecutionRepository creates a new ToolExecutionRepository.
func NewToolExecutionRepository(db *DB) *ToolExecutionRepository {
	return &ToolExecutionRepository{db: db}
}

// Create creates a new tool execution record.
func (r *ToolExecutionRepository) Create(ctx context.Context, execution *tool.ToolExecution) error {
	inputConfigJSON, err := json.Marshal(execution.InputConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal input config: %w", err)
	}

	outputSummaryJSON, err := json.Marshal(execution.OutputSummary)
	if err != nil {
		return fmt.Errorf("failed to marshal output summary: %w", err)
	}

	query := `
		INSERT INTO tool_executions (
			id, tenant_id, tool_id, agent_id, pipeline_run_id, step_run_id,
			status, input_config, targets_count, findings_count, output_summary,
			error_message, started_at, completed_at, duration_ms, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14, $15, $16
		)`

	_, err = r.db.ExecContext(ctx, query,
		execution.ID.String(),
		execution.TenantID.String(),
		execution.ToolID.String(),
		nullStringFromIDPtr(execution.AgentID),
		nullStringFromIDPtr(execution.PipelineRunID),
		nullStringFromIDPtr(execution.StepRunID),
		string(execution.Status),
		inputConfigJSON,
		execution.TargetsCount,
		execution.FindingsCount,
		outputSummaryJSON,
		nullStringFromString(execution.ErrorMessage),
		execution.StartedAt,
		nullTimeFromTimePtr(execution.CompletedAt),
		execution.DurationMs,
		execution.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create tool execution: %w", err)
	}

	return nil
}

// GetByID retrieves a tool execution by ID.
func (r *ToolExecutionRepository) GetByID(ctx context.Context, id shared.ID) (*tool.ToolExecution, error) {
	query := `
		SELECT id, tenant_id, tool_id, agent_id, pipeline_run_id, step_run_id,
			status, input_config, targets_count, findings_count, output_summary,
			error_message, started_at, completed_at, duration_ms, created_at
		FROM tool_executions WHERE id = $1`

	var (
		execID        string
		tenantID      string
		toolID        string
		agentID       sql.NullString
		pipelineRunID sql.NullString
		stepRunID     sql.NullString
		status        string
		inputConfig   []byte
		targetsCount  int
		findingsCount int
		outputSummary []byte
		errorMessage  sql.NullString
		startedAt     time.Time
		completedAt   sql.NullTime
		durationMs    sql.NullInt64
		createdAt     time.Time
	)

	err := r.db.QueryRowContext(ctx, query, id.String()).Scan(
		&execID, &tenantID, &toolID, &agentID, &pipelineRunID, &stepRunID,
		&status, &inputConfig, &targetsCount, &findingsCount, &outputSummary,
		&errorMessage, &startedAt, &completedAt, &durationMs, &createdAt,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get tool execution: %w", err)
	}

	return rowToToolExecution(
		execID, tenantID, toolID, agentID, pipelineRunID, stepRunID,
		status, inputConfig, targetsCount, findingsCount, outputSummary,
		errorMessage, startedAt, completedAt, durationMs, createdAt,
	)
}

// List retrieves tool executions with filters.
func (r *ToolExecutionRepository) List(
	ctx context.Context,
	filter tool.ToolExecutionFilter,
	page pagination.Pagination,
) (pagination.Result[*tool.ToolExecution], error) {
	baseQuery := `FROM tool_executions WHERE tenant_id = $1`
	args := []any{filter.TenantID.String()}
	argIndex := 2

	if filter.ToolID != nil {
		baseQuery += fmt.Sprintf(" AND tool_id = $%d", argIndex)
		args = append(args, filter.ToolID.String())
		argIndex++
	}

	if filter.AgentID != nil {
		baseQuery += fmt.Sprintf(" AND agent_id = $%d", argIndex)
		args = append(args, filter.AgentID.String())
		argIndex++
	}

	if filter.PipelineRunID != nil {
		baseQuery += fmt.Sprintf(" AND pipeline_run_id = $%d", argIndex)
		args = append(args, filter.PipelineRunID.String())
		argIndex++
	}

	if filter.Status != nil {
		baseQuery += fmt.Sprintf(" AND status = $%d", argIndex)
		args = append(args, string(*filter.Status))
		argIndex++
	}

	// Count total
	var total int64
	countQuery := "SELECT COUNT(*) " + baseQuery
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return pagination.Result[*tool.ToolExecution]{}, fmt.Errorf("failed to count tool executions: %w", err)
	}

	// Get items
	selectQuery := `
		SELECT id, tenant_id, tool_id, agent_id, pipeline_run_id, step_run_id,
			status, input_config, targets_count, findings_count, output_summary,
			error_message, started_at, completed_at, duration_ms, created_at
		` + baseQuery + " ORDER BY started_at DESC LIMIT $" + fmt.Sprint(argIndex) + " OFFSET $" + fmt.Sprint(argIndex+1)
	args = append(args, page.Limit(), page.Offset())

	rows, err := r.db.QueryContext(ctx, selectQuery, args...)
	if err != nil {
		return pagination.Result[*tool.ToolExecution]{}, fmt.Errorf("failed to list tool executions: %w", err)
	}
	defer rows.Close()

	executions := make([]*tool.ToolExecution, 0)
	for rows.Next() {
		var (
			execID        string
			tenantID      string
			toolID        string
			agentID       sql.NullString
			pipelineRunID sql.NullString
			stepRunID     sql.NullString
			status        string
			inputConfig   []byte
			targetsCount  int
			findingsCount int
			outputSummary []byte
			errorMessage  sql.NullString
			startedAt     time.Time
			completedAt   sql.NullTime
			durationMs    sql.NullInt64
			createdAt     time.Time
		)

		if err := rows.Scan(
			&execID, &tenantID, &toolID, &agentID, &pipelineRunID, &stepRunID,
			&status, &inputConfig, &targetsCount, &findingsCount, &outputSummary,
			&errorMessage, &startedAt, &completedAt, &durationMs, &createdAt,
		); err != nil {
			return pagination.Result[*tool.ToolExecution]{}, fmt.Errorf("failed to scan row: %w", err)
		}

		execution, err := rowToToolExecution(
			execID, tenantID, toolID, agentID, pipelineRunID, stepRunID,
			status, inputConfig, targetsCount, findingsCount, outputSummary,
			errorMessage, startedAt, completedAt, durationMs, createdAt,
		)
		if err != nil {
			return pagination.Result[*tool.ToolExecution]{}, err
		}
		executions = append(executions, execution)
	}

	if err := rows.Err(); err != nil {
		return pagination.Result[*tool.ToolExecution]{}, fmt.Errorf("error iterating rows: %w", err)
	}

	return pagination.NewResult(executions, total, page), nil
}

// Update updates a tool execution.
func (r *ToolExecutionRepository) Update(ctx context.Context, execution *tool.ToolExecution) error {
	outputSummaryJSON, err := json.Marshal(execution.OutputSummary)
	if err != nil {
		return fmt.Errorf("failed to marshal output summary: %w", err)
	}

	query := `
		UPDATE tool_executions SET
			status = $1,
			findings_count = $2,
			output_summary = $3,
			error_message = $4,
			completed_at = $5,
			duration_ms = $6
		WHERE id = $7`

	result, err := r.db.ExecContext(ctx, query,
		string(execution.Status),
		execution.FindingsCount,
		outputSummaryJSON,
		nullStringFromString(execution.ErrorMessage),
		nullTimeFromTimePtr(execution.CompletedAt),
		execution.DurationMs,
		execution.ID.String(),
	)

	if err != nil {
		return fmt.Errorf("failed to update tool execution: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// GetToolStats retrieves statistics for a specific tool.
func (r *ToolExecutionRepository) GetToolStats(
	ctx context.Context,
	tenantID, toolID shared.ID,
	days int,
) (*tool.ToolStats, error) {
	query := `
		SELECT
			COUNT(*) as total_runs,
			COUNT(*) FILTER (WHERE status = 'completed') as successful_runs,
			COUNT(*) FILTER (WHERE status IN ('failed', 'timeout')) as failed_runs,
			COALESCE(SUM(findings_count), 0) as total_findings,
			COALESCE(AVG(duration_ms), 0)::bigint as avg_duration_ms
		FROM tool_executions
		WHERE tenant_id = $1 AND tool_id = $2
		AND started_at >= NOW() - INTERVAL '1 day' * $3`

	var totalRuns, successfulRuns, failedRuns, totalFindings, avgDurationMs int64

	err := r.db.QueryRowContext(ctx, query, tenantID.String(), toolID.String(), days).Scan(
		&totalRuns, &successfulRuns, &failedRuns, &totalFindings, &avgDurationMs,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get tool stats: %w", err)
	}

	return &tool.ToolStats{
		ToolID:         toolID,
		TotalRuns:      totalRuns,
		SuccessfulRuns: successfulRuns,
		FailedRuns:     failedRuns,
		TotalFindings:  totalFindings,
		AvgDurationMs:  avgDurationMs,
	}, nil
}

// GetTenantStats retrieves aggregated tool statistics for a tenant.
func (r *ToolExecutionRepository) GetTenantStats(
	ctx context.Context,
	tenantID shared.ID,
	days int,
) (*tool.TenantToolStats, error) {
	// Get aggregate stats
	aggregateQuery := `
		SELECT
			COUNT(*) as total_runs,
			COUNT(*) FILTER (WHERE status = 'completed') as successful_runs,
			COUNT(*) FILTER (WHERE status IN ('failed', 'timeout')) as failed_runs,
			COALESCE(SUM(findings_count), 0) as total_findings
		FROM tool_executions
		WHERE tenant_id = $1
		AND started_at >= NOW() - INTERVAL '1 day' * $2`

	var totalRuns, successfulRuns, failedRuns, totalFindings int64

	err := r.db.QueryRowContext(ctx, aggregateQuery, tenantID.String(), days).Scan(
		&totalRuns, &successfulRuns, &failedRuns, &totalFindings,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant aggregate stats: %w", err)
	}

	// Get per-tool breakdown
	breakdownQuery := `
		SELECT
			tool_id,
			COUNT(*) as total_runs,
			COUNT(*) FILTER (WHERE status = 'completed') as successful_runs,
			COUNT(*) FILTER (WHERE status IN ('failed', 'timeout')) as failed_runs,
			COALESCE(SUM(findings_count), 0) as total_findings,
			COALESCE(AVG(duration_ms), 0)::bigint as avg_duration_ms
		FROM tool_executions
		WHERE tenant_id = $1
		AND started_at >= NOW() - INTERVAL '1 day' * $2
		GROUP BY tool_id
		ORDER BY total_runs DESC`

	rows, err := r.db.QueryContext(ctx, breakdownQuery, tenantID.String(), days)
	if err != nil {
		return nil, fmt.Errorf("failed to get tool breakdown stats: %w", err)
	}
	defer rows.Close()

	breakdown := make([]tool.ToolStats, 0)
	for rows.Next() {
		var (
			toolIDStr      string
			toolTotalRuns  int64
			toolSuccessful int64
			toolFailed     int64
			toolFindings   int64
			toolAvgMs      int64
		)

		if err := rows.Scan(&toolIDStr, &toolTotalRuns, &toolSuccessful, &toolFailed, &toolFindings, &toolAvgMs); err != nil {
			return nil, fmt.Errorf("failed to scan breakdown row: %w", err)
		}

		tID, _ := shared.IDFromString(toolIDStr)
		breakdown = append(breakdown, tool.ToolStats{
			ToolID:         tID,
			TotalRuns:      toolTotalRuns,
			SuccessfulRuns: toolSuccessful,
			FailedRuns:     toolFailed,
			TotalFindings:  toolFindings,
			AvgDurationMs:  toolAvgMs,
		})
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating breakdown rows: %w", err)
	}

	return &tool.TenantToolStats{
		TenantID:       tenantID,
		TotalRuns:      totalRuns,
		SuccessfulRuns: successfulRuns,
		FailedRuns:     failedRuns,
		TotalFindings:  totalFindings,
		ToolBreakdown:  breakdown,
	}, nil
}

// rowToToolExecution converts scanned values to a ToolExecution entity.
func rowToToolExecution(
	execID, tenantIDStr, toolIDStr string,
	agentID, pipelineRunID, stepRunID sql.NullString,
	status string,
	inputConfig []byte,
	targetsCount, findingsCount int,
	outputSummary []byte,
	errorMessage sql.NullString,
	startedAt time.Time,
	completedAt sql.NullTime,
	durationMs sql.NullInt64,
	createdAt time.Time,
) (*tool.ToolExecution, error) {
	id, err := shared.IDFromString(execID)
	if err != nil {
		return nil, fmt.Errorf("invalid execution id: %w", err)
	}

	tenantID, err := shared.IDFromString(tenantIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant id: %w", err)
	}

	toolID, err := shared.IDFromString(toolIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid tool id: %w", err)
	}

	var inputCfg map[string]any
	if len(inputConfig) > 0 {
		if err := json.Unmarshal(inputConfig, &inputCfg); err != nil {
			return nil, fmt.Errorf("failed to unmarshal input config: %w", err)
		}
	}

	var outputSum map[string]any
	if len(outputSummary) > 0 {
		if err := json.Unmarshal(outputSummary, &outputSum); err != nil {
			return nil, fmt.Errorf("failed to unmarshal output summary: %w", err)
		}
	}

	execution := &tool.ToolExecution{
		ID:            id,
		TenantID:      tenantID,
		ToolID:        toolID,
		AgentID:       idPtrFromNullString(agentID),
		PipelineRunID: idPtrFromNullString(pipelineRunID),
		StepRunID:     idPtrFromNullString(stepRunID),
		Status:        tool.ExecutionStatus(status),
		InputConfig:   inputCfg,
		TargetsCount:  targetsCount,
		FindingsCount: findingsCount,
		OutputSummary: outputSum,
		ErrorMessage:  errorMessage.String,
		StartedAt:     startedAt,
		CompletedAt:   timePtrFromNullTime(completedAt),
		DurationMs:    int(durationMs.Int64),
		CreatedAt:     createdAt,
	}

	return execution, nil
}

// Helper functions
func nullStringFromIDPtr(id *shared.ID) sql.NullString {
	if id == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: id.String(), Valid: true}
}

func nullStringFromString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func nullTimeFromTimePtr(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

func idPtrFromNullString(ns sql.NullString) *shared.ID {
	if !ns.Valid {
		return nil
	}
	id, err := shared.IDFromString(ns.String)
	if err != nil {
		return nil
	}
	return &id
}

func timePtrFromNullTime(nt sql.NullTime) *time.Time {
	if !nt.Valid {
		return nil
	}
	return &nt.Time
}
