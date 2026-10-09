package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// AutomationRunRepository implements automation.RunRepository using PostgreSQL.
type AutomationRunRepository struct {
	db *DB
}

// NewAutomationRunRepository creates a new AutomationRunRepository.
func NewAutomationRunRepository(db *DB) *AutomationRunRepository {
	return &AutomationRunRepository{db: db}
}

// Create creates a new workflow run.
func (r *AutomationRunRepository) Create(ctx context.Context, run *automation.Run) error {
	triggerData, err := json.Marshal(run.TriggerData)
	if err != nil {
		return fmt.Errorf("failed to marshal trigger data: %w", err)
	}

	context, err := json.Marshal(run.Context)
	if err != nil {
		return fmt.Errorf("failed to marshal context: %w", err)
	}

	query := `
		INSERT INTO automation_runs (
			id, automation_id, tenant_id, trigger_type, trigger_data,
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
func (r *AutomationRunRepository) GetByID(ctx context.Context, id shared.ID) (*automation.Run, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanRun(row)
}

// GetByTenantAndID retrieves a run by tenant and ID.
func (r *AutomationRunRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*automation.Run, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanRun(row)
}

// List lists runs with filters and pagination.
func (r *AutomationRunRepository) List(ctx context.Context, filter automation.RunFilter, page pagination.Pagination) (pagination.Result[*automation.Run], error) {
	var result pagination.Result[*automation.Run]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM automation_runs"
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

	var runs []*automation.Run
	for rows.Next() {
		run, err := r.scanRunFromRows(rows)
		if err != nil {
			return result, err
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return result, err
	}

	return pagination.NewResult(runs, total, page), nil
}

// ListByWorkflowID lists runs for a specific workflow.
func (r *AutomationRunRepository) ListByWorkflowID(ctx context.Context, workflowID shared.ID, pageNum, perPage int) ([]*automation.Run, int64, error) {
	countQuery := "SELECT COUNT(*) FROM automation_runs WHERE automation_id = $1"
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, workflowID.String()).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("failed to count runs: %w", err)
	}

	offset := (pageNum - 1) * perPage
	query := r.selectQuery() + " WHERE automation_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"

	rows, err := r.db.QueryContext(ctx, query, workflowID.String(), perPage, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list runs: %w", err)
	}
	defer rows.Close()

	var runs []*automation.Run
	for rows.Next() {
		run, err := r.scanRunFromRows(rows)
		if err != nil {
			return nil, 0, err
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}

	return runs, total, nil
}

// Update updates a run.
func (r *AutomationRunRepository) Update(ctx context.Context, run *automation.Run) error {
	context, err := json.Marshal(run.Context)
	if err != nil {
		return fmt.Errorf("failed to marshal context: %w", err)
	}

	query := `
		UPDATE automation_runs
		SET status = $2, error_message = $3, context = $4,
		    total_nodes = $5, completed_nodes = $6, failed_nodes = $7,
		    started_at = $8, completed_at = $9
		WHERE id = $1
		  AND status NOT IN ('completed', 'failed', 'canceled')
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
		// A finished run never changes again: a cancel is not overwritten by
		// the executor finishing, and a finished run is not reopened.
		var exists bool
		if err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM automation_runs WHERE id = $1)`,
			run.ID.String()).Scan(&exists); err != nil {
			return fmt.Errorf("failed to check workflow run: %w", err)
		}
		if exists {
			return automation.ErrRunAlreadyFinished
		}
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a run.
func (r *AutomationRunRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM automation_runs WHERE id = $1"
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
func (r *AutomationRunRepository) GetWithNodeRuns(ctx context.Context, id shared.ID) (*automation.Run, error) {
	run, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Load node runs
	query := `
		SELECT id, automation_run_id, node_id, node_key, node_type,
		       status, error_message, error_code,
		       input, output, condition_result,
		       started_at, completed_at, created_at
		FROM automation_run_steps
		WHERE automation_run_id = $1
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
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return run, nil
}

// GetActiveByWorkflowID retrieves active runs for a workflow.
func (r *AutomationRunRepository) GetActiveByWorkflowID(ctx context.Context, workflowID shared.ID) ([]*automation.Run, error) {
	query := r.selectQuery() + " WHERE automation_id = $1 AND status IN ('pending', 'running')"

	rows, err := r.db.QueryContext(ctx, query, workflowID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get active runs: %w", err)
	}
	defer rows.Close()

	var runs []*automation.Run
	for rows.Next() {
		run, err := r.scanRunFromRows(rows)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return runs, nil
}

// CountActiveByWorkflowID counts active runs for a workflow.
func (r *AutomationRunRepository) CountActiveByWorkflowID(ctx context.Context, workflowID shared.ID) (int, error) {
	query := `SELECT COUNT(*) FROM automation_runs WHERE automation_id = $1 AND status IN ('pending', 'running')`
	var count int
	err := r.db.QueryRowContext(ctx, query, workflowID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active runs: %w", err)
	}
	return count, nil
}

// CountActiveByTenantID counts active runs for a tenant.
func (r *AutomationRunRepository) CountActiveByTenantID(ctx context.Context, tenantID shared.ID) (int, error) {
	query := `SELECT COUNT(*) FROM automation_runs WHERE tenant_id = $1 AND status IN ('pending', 'running')`
	var count int
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active runs for tenant: %w", err)
	}
	return count, nil
}

// UpdateStats updates run statistics.
func (r *AutomationRunRepository) UpdateStats(ctx context.Context, id shared.ID, completed, failed int) error {
	query := `UPDATE automation_runs SET completed_nodes = $2, failed_nodes = $3 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id.String(), completed, failed)
	if err != nil {
		return fmt.Errorf("failed to update run stats: %w", err)
	}
	return nil
}

// UpdateStatus updates run status.
func (r *AutomationRunRepository) UpdateStatus(ctx context.Context, id shared.ID, status automation.RunStatus, errorMessage string) error {
	query := `UPDATE automation_runs SET status = $2, error_message = $3 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id.String(), string(status), errorMessage)
	if err != nil {
		return fmt.Errorf("failed to update run status: %w", err)
	}
	return nil
}

// CreateRunIfUnderLimit creates run when the automation and the tenant are
// under their limits, in one transaction that holds the workflow row lock,
// so concurrent triggers cannot both pass a check (TOCTOU):
//
//   - a run with the idempotency key of an existing run of the same
//     automation is not created: automation.ErrRunDuplicate;
//   - over maxActivePerWorkflow / maxActivePerTenant waiting or running
//     runs: MAX_CONCURRENT_RUNS;
//   - over automation.MaxRunsPerWorkflowPerHour / MaxRunsPerTenantPerHour runs
//     created in the last hour: automation.ErrCodeRunThrottled. The first
//     refusal of the window also records one failed "THROTTLED" run, so the
//     automation's history shows that events were dropped.
//
//nolint:cyclop // one transaction: lock, dedupe, two caps, two quotas, insert
func (r *AutomationRunRepository) CreateRunIfUnderLimit(ctx context.Context, run *automation.Run, maxActivePerWorkflow, maxActivePerTenant int) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Lock the workflow row (in the run's tenant) to serialize concurrent
	// triggers for the same workflow.
	var locked string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM automations WHERE id = $1 AND tenant_id = $2 FOR UPDATE`,
		run.WorkflowID.String(), run.TenantID.String()).Scan(&locked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return shared.ErrNotFound
		}
		return fmt.Errorf("failed to lock workflow: %w", err)
	}

	if run.IdempotencyKey != "" {
		var exists bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM automation_runs WHERE automation_id = $1 AND idempotency_key = $2)`,
			run.WorkflowID.String(), run.IdempotencyKey).Scan(&exists); err != nil {
			return fmt.Errorf("failed to check run idempotency: %w", err)
		}
		if exists {
			return automation.ErrRunDuplicate
		}
	}

	var wfActive, wfHour, tenantActive, tenantHour int
	if err := tx.QueryRowContext(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE automation_id = $1 AND status IN ('pending', 'running')),
			COUNT(*) FILTER (WHERE automation_id = $1 AND created_at > NOW() - $3::interval),
			COUNT(*) FILTER (WHERE status IN ('pending', 'running')),
			COUNT(*) FILTER (WHERE created_at > NOW() - $3::interval)
		FROM automation_runs
		WHERE tenant_id = $2 AND (status IN ('pending', 'running') OR created_at > NOW() - $3::interval)`,
		run.WorkflowID.String(), run.TenantID.String(), quotaWindow()).Scan(&wfActive, &wfHour, &tenantActive, &tenantHour); err != nil {
		return fmt.Errorf("failed to count runs: %w", err)
	}
	if wfActive >= maxActivePerWorkflow {
		return shared.NewDomainError("MAX_CONCURRENT_RUNS",
			fmt.Sprintf("maximum concurrent runs (%d) reached for this workflow", maxActivePerWorkflow), shared.ErrValidation)
	}
	if tenantActive >= maxActivePerTenant {
		return shared.NewDomainError("MAX_CONCURRENT_RUNS",
			fmt.Sprintf("maximum concurrent workflow runs (%d) reached for tenant", maxActivePerTenant), shared.ErrValidation)
	}
	var throttled string
	switch {
	case wfHour >= automation.MaxRunsPerWorkflowPerHour:
		throttled = fmt.Sprintf("this automation started %d runs in the last hour (limit %d); later events are dropped until the hour passes",
			wfHour, automation.MaxRunsPerWorkflowPerHour)
	case tenantHour >= automation.MaxRunsPerTenantPerHour:
		throttled = fmt.Sprintf("the organization started %d automation runs in the last hour (limit %d); later events are dropped until the hour passes",
			tenantHour, automation.MaxRunsPerTenantPerHour)
	}
	if throttled != "" {
		if err := r.recordThrottled(ctx, tx, run, throttled); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("failed to commit transaction: %w", err)
		}
		return automation.NewRunThrottledError(throttled)
	}

	if err := r.insertRun(ctx, tx, run); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

// quotaWindow is automation.RunQuotaWindow as a Postgres interval.
func quotaWindow() string {
	return fmt.Sprintf("%d seconds", int(automation.RunQuotaWindow.Seconds()))
}

// recordThrottled writes, once per automation per quota window, a failed run
// saying events were dropped (so throttling is visible in the run history,
// not only in logs).
func (r *AutomationRunRepository) recordThrottled(ctx context.Context, tx *sql.Tx, run *automation.Run, msg string) error {
	var recorded bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM automation_runs
		 WHERE automation_id = $1 AND status = 'failed' AND error_message LIKE $2
		   AND created_at > NOW() - $3::interval)`,
		run.WorkflowID.String(), automation.ThrottledRunPrefix+"%", quotaWindow()).Scan(&recorded); err != nil {
		return fmt.Errorf("failed to check throttled marker: %w", err)
	}
	if recorded {
		return nil
	}
	marker, err := automation.NewRun(run.WorkflowID, run.TenantID, run.TriggerType, map[string]any{"throttled": true})
	if err != nil {
		return err
	}
	marker.Fail(automation.ThrottledRunPrefix + msg)
	return r.insertRun(ctx, tx, marker)
}

// insertRun inserts run inside tx.
func (r *AutomationRunRepository) insertRun(ctx context.Context, tx *sql.Tx, run *automation.Run) error {
	triggerData, err := json.Marshal(run.TriggerData)
	if err != nil {
		return fmt.Errorf("failed to marshal trigger data: %w", err)
	}
	runContext, err := json.Marshal(run.Context)
	if err != nil {
		return fmt.Errorf("failed to marshal context: %w", err)
	}
	var idemKey any
	if run.IdempotencyKey != "" {
		idemKey = run.IdempotencyKey
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO automation_runs (
			id, automation_id, tenant_id, trigger_type, trigger_data,
			status, error_message, context,
			total_nodes, completed_nodes, failed_nodes,
			started_at, completed_at, triggered_by, created_at,
			subject_id, idempotency_key
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		run.ID.String(),
		run.WorkflowID.String(),
		run.TenantID.String(),
		string(run.TriggerType),
		triggerData,
		string(run.Status),
		run.ErrorMessage,
		runContext,
		run.TotalNodes,
		run.CompletedNodes,
		run.FailedNodes,
		run.StartedAt,
		run.CompletedAt,
		nullID(run.TriggeredBy),
		run.CreatedAt,
		nullID(run.SubjectID),
		idemKey,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return automation.ErrRunDuplicate
		}
		return fmt.Errorf("failed to create workflow run: %w", err)
	}
	return nil
}

func (r *AutomationRunRepository) selectQuery() string {
	return `
		SELECT id, automation_id, tenant_id, trigger_type, trigger_data,
		       status, error_message, context,
		       total_nodes, completed_nodes, failed_nodes,
		       started_at, completed_at, triggered_by, created_at
		FROM automation_runs
	`
}

func (r *AutomationRunRepository) buildWhereClause(filter automation.RunFilter) (string, []any) {
	var conditions []string
	var args []any

	if filter.TenantID != nil {
		args = append(args, filter.TenantID.String())
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", len(args)))
	}

	if filter.WorkflowID != nil {
		args = append(args, filter.WorkflowID.String())
		conditions = append(conditions, fmt.Sprintf("automation_id = $%d", len(args)))
	}

	if filter.Status != nil {
		args = append(args, string(*filter.Status))
		conditions = append(conditions, fmt.Sprintf("status = $%d", len(args)))
	}

	if filter.TriggerType != nil {
		args = append(args, string(*filter.TriggerType))
		conditions = append(conditions, fmt.Sprintf("trigger_type = $%d", len(args)))
	}

	if filter.TriggeredBy != nil {
		args = append(args, filter.TriggeredBy.String())
		conditions = append(conditions, fmt.Sprintf("triggered_by = $%d", len(args)))
	}

	if filter.StartedFrom != nil {
		args = append(args, *filter.StartedFrom)
		conditions = append(conditions, fmt.Sprintf("started_at >= $%d", len(args)))
	}

	if filter.StartedTo != nil {
		args = append(args, *filter.StartedTo)
		conditions = append(conditions, fmt.Sprintf("started_at <= $%d", len(args)))
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

func (r *AutomationRunRepository) scanRun(row *sql.Row) (*automation.Run, error) {
	run := &automation.Run{}
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
	run.TriggerType = automation.TriggerType(triggerType)
	run.Status = automation.RunStatus(status)
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

func (r *AutomationRunRepository) scanRunFromRows(rows *sql.Rows) (*automation.Run, error) {
	run := &automation.Run{}
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
	run.TriggerType = automation.TriggerType(triggerType)
	run.Status = automation.RunStatus(status)
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
func scanNodeRun(rows *sql.Rows) (*automation.NodeRun, error) {
	nr := &automation.NodeRun{}
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
	nr.NodeType = automation.NodeType(nodeType)
	nr.Status = automation.NodeRunStatus(status)
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

// HasRecentSubjectRun implements automation.RecentSubjectRunChecker.
func (r *AutomationRunRepository) HasRecentSubjectRun(ctx context.Context, tenantID, workflowID, subjectID shared.ID, triggerType automation.TriggerType, since time.Time) (bool, error) {
	var found bool
	err := r.db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM automation_runs
		 WHERE tenant_id = $1 AND automation_id = $2 AND subject_id = $3
		   AND trigger_type = $4 AND created_at > $5)`,
		tenantID.String(), workflowID.String(), subjectID.String(), string(triggerType), since).Scan(&found)
	if err != nil {
		return false, fmt.Errorf("failed to check recent subject run: %w", err)
	}
	return found, nil
}

// LatestOutcomes implements automation.RunOutcomeReader.
func (r *AutomationRunRepository) LatestOutcomes(ctx context.Context, tenantID, workflowID shared.ID, n int) ([]automation.RunStatus, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT status FROM automation_runs
		 WHERE tenant_id = $1 AND automation_id = $2 AND status IN ('completed', 'failed')
		   AND COALESCE(error_message, '') NOT LIKE $3
		 ORDER BY created_at DESC
		 LIMIT $4`,
		tenantID.String(), workflowID.String(), automation.ThrottledRunPrefix+"%", n)
	if err != nil {
		return nil, fmt.Errorf("failed to read latest run outcomes: %w", err)
	}
	defer rows.Close()
	out := make([]automation.RunStatus, 0, n)
	for rows.Next() {
		var st string
		if err := rows.Scan(&st); err != nil {
			return nil, fmt.Errorf("failed to scan run outcome: %w", err)
		}
		out = append(out, automation.RunStatus(st))
	}
	return out, rows.Err()
}

// FailStaleRuns implements automation.StaleRunReaper. The open steps of the
// runs it ends fail with them, in the same statement.
func (r *AutomationRunRepository) FailStaleRuns(ctx context.Context, before time.Time, reason string) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx, `
		WITH stale AS (
			UPDATE automation_runs
			   SET status = 'failed', error_message = $2, completed_at = NOW()
			 WHERE status IN ('pending', 'running') AND created_at < $1
			RETURNING id
		), steps AS (
			UPDATE automation_run_steps
			   SET status = 'failed', error_message = $2, error_code = 'RUN_INTERRUPTED', completed_at = NOW()
			 WHERE automation_run_id IN (SELECT id FROM stale) AND status IN ('pending', 'running')
		)
		SELECT COUNT(*) FROM stale`, before, reason).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("failed to end stale workflow runs: %w", err)
	}
	return n, nil
}
