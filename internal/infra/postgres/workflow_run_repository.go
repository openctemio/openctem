package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/workflow"
	"github.com/openctemio/api/pkg/pagination"
)

// WorkflowRunRepository implements workflow.RunRepository using PostgreSQL.
type WorkflowRunRepository struct {
	db *DB
}

// NewWorkflowRunRepository creates a new WorkflowRunRepository.
func NewWorkflowRunRepository(db *DB) *WorkflowRunRepository {
	return &WorkflowRunRepository{db: db}
}

// Create creates a new workflow run.
func (r *WorkflowRunRepository) Create(ctx context.Context, run *workflow.Run) error {
	triggerData, err := json.Marshal(run.TriggerData)
	if err != nil {
		return fmt.Errorf("failed to marshal trigger data: %w", err)
	}

	context, err := json.Marshal(run.Context)
	if err != nil {
		return fmt.Errorf("failed to marshal context: %w", err)
	}

	query := `
		INSERT INTO workflow_runs (
			id, workflow_id, tenant_id, trigger_type, trigger_data,
			status, error_message, context,
			total_nodes, completed_nodes, failed_nodes,
			started_at, completed_at, triggered_by, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	_, err = r.db.ExecContext(ctx, query,
		run.ID.String(),
		run.WorkflowID.String(),
		run.TenantID.String(),
		string(run.TriggerType),
		triggerData,
		string(run.Status),
		run.ErrorMessage,
		context,
		run.TotalNodes,
		run.CompletedNodes,
		run.FailedNodes,
		run.StartedAt,
		run.CompletedAt,
		nullID(run.TriggeredBy),
		run.CreatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create workflow run: %w", err)
	}

	return nil
}

// GetByID retrieves a run by ID.
func (r *WorkflowRunRepository) GetByID(ctx context.Context, id shared.ID) (*workflow.Run, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanRun(row)
}

// GetByTenantAndID retrieves a run by tenant and ID.
func (r *WorkflowRunRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*workflow.Run, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanRun(row)
}

// List lists runs with filters and pagination.
func (r *WorkflowRunRepository) List(ctx context.Context, filter workflow.RunFilter, page pagination.Pagination) (pagination.Result[*workflow.Run], error) {
	var result pagination.Result[*workflow.Run]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM workflow_runs"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count workflow runs: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	baseQuery += fmt.Sprintf(" ORDER BY created_at DESC LIMIT %d OFFSET %d", page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list workflow runs: %w", err)
	}
	defer rows.Close()

	var runs []*workflow.Run
	for rows.Next() {
		run, err := r.scanRunFromRows(rows)
		if err != nil {
			return result, err
		}
		runs = append(runs, run)
	}

	return pagination.NewResult(runs, total, page), nil
}

// ListByWorkflowID lists runs for a specific workflow.
func (r *WorkflowRunRepository) ListByWorkflowID(ctx context.Context, workflowID shared.ID, pageNum, perPage int) ([]*workflow.Run, int64, error) {
	countQuery := "SELECT COUNT(*) FROM workflow_runs WHERE workflow_id = $1"
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, workflowID.String()).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count runs: %w", err)
	}

	offset := (pageNum - 1) * perPage
	query := r.selectQuery() + " WHERE workflow_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"

	rows, err := r.db.QueryContext(ctx, query, workflowID.String(), perPage, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list runs: %w", err)
	}
	defer rows.Close()

	var runs []*workflow.Run
	for rows.Next() {
		run, err := r.scanRunFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		runs = append(runs, run)
	}

	return runs, total, nil
}

// Update updates a run.
func (r *WorkflowRunRepository) Update(ctx context.Context, run *workflow.Run) error {
	context, err := json.Marshal(run.Context)
	if err != nil {
		return fmt.Errorf("failed to marshal context: %w", err)
	}

	query := `
		UPDATE workflow_runs
		SET status = $2, error_message = $3, context = $4,
		    total_nodes = $5, completed_nodes = $6, failed_nodes = $7,
		    started_at = $8, completed_at = $9
		WHERE id = $1
	`

	result, err := r.db.ExecContext(ctx, query,
		run.ID.String(),
		string(run.Status),
		run.ErrorMessage,
		context,
		run.TotalNodes,
		run.CompletedNodes,
		run.FailedNodes,
		run.StartedAt,
		run.CompletedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update workflow run: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a run.
func (r *WorkflowRunRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM workflow_runs WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete workflow run: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// GetWithNodeRuns retrieves a run with its node runs.
func (r *WorkflowRunRepository) GetWithNodeRuns(ctx context.Context, id shared.ID) (*workflow.Run, error) {
	run, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Load node runs
	query := `
		SELECT id, workflow_run_id, node_id, node_key, node_type,
		       status, error_message, error_code,
		       input, output, condition_result,
		       started_at, completed_at, created_at
		FROM workflow_node_runs
		WHERE workflow_run_id = $1
		ORDER BY created_at ASC
	`

	rows, err := r.db.QueryContext(ctx, query, id.String())
	if err != nil {
		return nil, fmt.Errorf("failed to load node runs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		nodeRun, err := scanNodeRun(rows)
		if err != nil {
			return nil, err
		}
		run.NodeRuns = append(run.NodeRuns, nodeRun)
	}

	return run, nil
}

// GetActiveByWorkflowID retrieves active runs for a workflow.
func (r *WorkflowRunRepository) GetActiveByWorkflowID(ctx context.Context, workflowID shared.ID) ([]*workflow.Run, error) {
	query := r.selectQuery() + " WHERE workflow_id = $1 AND status IN ('pending', 'running')"

	rows, err := r.db.QueryContext(ctx, query, workflowID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get active runs: %w", err)
	}
	defer rows.Close()

	var runs []*workflow.Run
	for rows.Next() {
		run, err := r.scanRunFromRows(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}

	return runs, nil
}

// CountActiveByWorkflowID counts active runs for a workflow.
func (r *WorkflowRunRepository) CountActiveByWorkflowID(ctx context.Context, workflowID shared.ID) (int, error) {
	query := `SELECT COUNT(*) FROM workflow_runs WHERE workflow_id = $1 AND status IN ('pending', 'running')`
	var count int
	err := r.db.QueryRowContext(ctx, query, workflowID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active runs: %w", err)
	}
	return count, nil
}

// CountActiveByTenantID counts active runs for a tenant.
func (r *WorkflowRunRepository) CountActiveByTenantID(ctx context.Context, tenantID shared.ID) (int, error) {
	query := `SELECT COUNT(*) FROM workflow_runs WHERE tenant_id = $1 AND status IN ('pending', 'running')`
	var count int
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active runs for tenant: %w", err)
	}
	return count, nil
}

// UpdateStats updates run statistics.
func (r *WorkflowRunRepository) UpdateStats(ctx context.Context, id shared.ID, completed, failed int) error {
	query := `UPDATE workflow_runs SET completed_nodes = $2, failed_nodes = $3 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id.String(), completed, failed)
	if err != nil {
		return fmt.Errorf("failed to update run stats: %w", err)
	}
	return nil
}

// UpdateStatus updates run status.
func (r *WorkflowRunRepository) UpdateStatus(ctx context.Context, id shared.ID, status workflow.RunStatus, errorMessage string) error {
	query := `UPDATE workflow_runs SET status = $2, error_message = $3 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id.String(), string(status), errorMessage)
	if err != nil {
		return fmt.Errorf("failed to update run status: %w", err)
	}
	return nil
}

// CreateRunIfUnderLimit atomically checks concurrent run limits and creates run if under limit.
// Uses a transaction with row-level locking to prevent race conditions.
// This prevents TOCTOU (time-of-check-time-of-use) vulnerabilities where multiple concurrent
// triggers could bypass the limits.
func (r *WorkflowRunRepository) CreateRunIfUnderLimit(ctx context.Context, run *workflow.Run, maxPerWorkflow, maxPerTenant int) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Lock the workflow row to serialize concurrent triggers for the same workflow
	// This prevents race conditions where multiple triggers check limits simultaneously
	lockQuery := `SELECT id FROM workflows WHERE id = $1 FOR UPDATE`
	if _, err := tx.ExecContext(ctx, lockQuery, run.WorkflowID.String()); err != nil {
		return fmt.Errorf("failed to lock workflow: %w", err)
	}

	// Count active runs for this workflow (no FOR UPDATE needed - we already hold lock on workflows row)
	var workflowActiveCount int
	workflowCountQuery := `
		SELECT COUNT(*) FROM workflow_runs
		WHERE workflow_id = $1 AND status IN ('pending', 'running')
	`
	if err := tx.QueryRowContext(ctx, workflowCountQuery, run.WorkflowID.String()).Scan(&workflowActiveCount); err != nil {
		return fmt.Errorf("failed to count active runs for workflow: %w", err)
	}
	if workflowActiveCount >= maxPerWorkflow {
		return shared.NewDomainError(
			"MAX_CONCURRENT_RUNS",
			fmt.Sprintf("maximum concurrent runs (%d) reached for this workflow", maxPerWorkflow),
			shared.ErrValidation,
		)
	}

	// Count active runs for this tenant
	var tenantActiveCount int
	tenantCountQuery := `
		SELECT COUNT(*) FROM workflow_runs
		WHERE tenant_id = $1 AND status IN ('pending', 'running')
	`
	if err := tx.QueryRowContext(ctx, tenantCountQuery, run.TenantID.String()).Scan(&tenantActiveCount); err != nil {
		return fmt.Errorf("failed to count active runs for tenant: %w", err)
	}
	if tenantActiveCount >= maxPerTenant {
		return shared.NewDomainError(
			"MAX_CONCURRENT_RUNS",
			fmt.Sprintf("maximum concurrent workflow runs (%d) reached for tenant", maxPerTenant),
			shared.ErrValidation,
		)
	}

	// Create the run within the same transaction
	triggerData, err := json.Marshal(run.TriggerData)
	if err != nil {
		return fmt.Errorf("failed to marshal trigger data: %w", err)
	}

	context, err := json.Marshal(run.Context)
	if err != nil {
		return fmt.Errorf("failed to marshal context: %w", err)
	}

	insertQuery := `
		INSERT INTO workflow_runs (
			id, workflow_id, tenant_id, trigger_type, trigger_data,
			status, error_message, context,
			total_nodes, completed_nodes, failed_nodes,
			started_at, completed_at, triggered_by, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`

	_, err = tx.ExecContext(ctx, insertQuery,
		run.ID.String(),
		run.WorkflowID.String(),
		run.TenantID.String(),
		string(run.TriggerType),
		triggerData,
		string(run.Status),
		run.ErrorMessage,
		context,
		run.TotalNodes,
		run.CompletedNodes,
		run.FailedNodes,
		run.StartedAt,
		run.CompletedAt,
		nullID(run.TriggeredBy),
		run.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create workflow run: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (r *WorkflowRunRepository) selectQuery() string {
	return `
		SELECT id, workflow_id, tenant_id, trigger_type, trigger_data,
		       status, error_message, context,
		       total_nodes, completed_nodes, failed_nodes,
		       started_at, completed_at, triggered_by, created_at
		FROM workflow_runs
	`
}

func (r *WorkflowRunRepository) buildWhereClause(filter workflow.RunFilter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.TenantID != nil {
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argIndex))
		args = append(args, filter.TenantID.String())
		argIndex++
	}

	if filter.WorkflowID != nil {
		conditions = append(conditions, fmt.Sprintf("workflow_id = $%d", argIndex))
		args = append(args, filter.WorkflowID.String())
		argIndex++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, string(*filter.Status))
		argIndex++
	}

	if filter.TriggerType != nil {
		conditions = append(conditions, fmt.Sprintf("trigger_type = $%d", argIndex))
		args = append(args, string(*filter.TriggerType))
		argIndex++
	}

	if filter.TriggeredBy != nil {
		conditions = append(conditions, fmt.Sprintf("triggered_by = $%d", argIndex))
		args = append(args, filter.TriggeredBy.String())
		argIndex++
	}

	if filter.StartedFrom != nil {
		conditions = append(conditions, fmt.Sprintf("started_at >= $%d", argIndex))
		args = append(args, *filter.StartedFrom)
		argIndex++
	}

	if filter.StartedTo != nil {
		conditions = append(conditions, fmt.Sprintf("started_at <= $%d", argIndex))
		args = append(args, *filter.StartedTo)
		argIndex++
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

func (r *WorkflowRunRepository) scanRun(row *sql.Row) (*workflow.Run, error) {
	run := &workflow.Run{}
	var (
		id          string
		workflowID  string
		tenantID    string
		triggerType string
		triggerData []byte
		status      string
		context     []byte
		triggeredBy sql.NullString
	)

	var errorMessage sql.NullString
	err := row.Scan(
		&id,
		&workflowID,
		&tenantID,
		&triggerType,
		&triggerData,
		&status,
		&errorMessage,
		&context,
		&run.TotalNodes,
		&run.CompletedNodes,
		&run.FailedNodes,
		&run.StartedAt,
		&run.CompletedAt,
		&triggeredBy,
		&run.CreatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan workflow run: %w", err)
	}

	run.ID, _ = shared.IDFromString(id)
	run.WorkflowID, _ = shared.IDFromString(workflowID)
	run.TenantID, _ = shared.IDFromString(tenantID)
	run.TriggerType = workflow.TriggerType(triggerType)
	run.Status = workflow.RunStatus(status)
	run.ErrorMessage = errorMessage.String

	if len(triggerData) > 0 {
		_ = json.Unmarshal(triggerData, &run.TriggerData)
	}
	if len(context) > 0 {
		_ = json.Unmarshal(context, &run.Context)
	}
	if triggeredBy.Valid {
		triggeredByID, _ := shared.IDFromString(triggeredBy.String)
		run.TriggeredBy = &triggeredByID
	}

	return run, nil
}

func (r *WorkflowRunRepository) scanRunFromRows(rows *sql.Rows) (*workflow.Run, error) {
	run := &workflow.Run{}
	var (
		id          string
		workflowID  string
		tenantID    string
		triggerType string
		triggerData []byte
		status      string
		context     []byte
		triggeredBy sql.NullString
	)

	var errorMessage sql.NullString
	err := rows.Scan(
		&id,
		&workflowID,
		&tenantID,
		&triggerType,
		&triggerData,
		&status,
		&errorMessage,
		&context,
		&run.TotalNodes,
		&run.CompletedNodes,
		&run.FailedNodes,
		&run.StartedAt,
		&run.CompletedAt,
		&triggeredBy,
		&run.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan workflow run from rows: %w", err)
	}

	run.ID, _ = shared.IDFromString(id)
	run.WorkflowID, _ = shared.IDFromString(workflowID)
	run.TenantID, _ = shared.IDFromString(tenantID)
	run.TriggerType = workflow.TriggerType(triggerType)
	run.Status = workflow.RunStatus(status)
	run.ErrorMessage = errorMessage.String

	if len(triggerData) > 0 {
		_ = json.Unmarshal(triggerData, &run.TriggerData)
	}
	if len(context) > 0 {
		_ = json.Unmarshal(context, &run.Context)
	}
	if triggeredBy.Valid {
		triggeredByID, _ := shared.IDFromString(triggeredBy.String)
		run.TriggeredBy = &triggeredByID
	}

	return run, nil
}

// scanNodeRun scans a workflow node run from rows.
func scanNodeRun(rows *sql.Rows) (*workflow.NodeRun, error) {
	nr := &workflow.NodeRun{}
	var (
		id              string
		workflowRunID   string
		nodeID          string
		nodeType        string
		status          string
		errorCode       sql.NullString
		input           []byte
		output          []byte
		conditionResult sql.NullBool
	)

	var errorMessage sql.NullString
	err := rows.Scan(
		&id,
		&workflowRunID,
		&nodeID,
		&nr.NodeKey,
		&nodeType,
		&status,
		&errorMessage,
		&errorCode,
		&input,
		&output,
		&conditionResult,
		&nr.StartedAt,
		&nr.CompletedAt,
		&nr.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan node run: %w", err)
	}

	nr.ID, _ = shared.IDFromString(id)
	nr.WorkflowRunID, _ = shared.IDFromString(workflowRunID)
	nr.NodeID, _ = shared.IDFromString(nodeID)
	nr.NodeType = workflow.NodeType(nodeType)
	nr.Status = workflow.NodeRunStatus(status)
	nr.ErrorMessage = errorMessage.String

	if errorCode.Valid {
		nr.ErrorCode = errorCode.String
	}
	if len(input) > 0 {
		_ = json.Unmarshal(input, &nr.Input)
	}
	if len(output) > 0 {
		_ = json.Unmarshal(output, &nr.Output)
	}
	if conditionResult.Valid {
		nr.ConditionResult = &conditionResult.Bool
	}

	return nr, nil
}
