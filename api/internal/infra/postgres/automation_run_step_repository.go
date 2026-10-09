package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AutomationRunStepRepository implements automation.NodeRunRepository using PostgreSQL.
type AutomationRunStepRepository struct {
	db *DB
}

// NewAutomationRunStepRepository creates a new AutomationRunStepRepository.
func NewAutomationRunStepRepository(db *DB) *AutomationRunStepRepository {
	return &AutomationRunStepRepository{db: db}
}

// Create creates a new node run.
func (r *AutomationRunStepRepository) Create(ctx context.Context, nr *automation.NodeRun) error {
	input, err := json.Marshal(nr.Input)
	if err != nil {
		return fmt.Errorf("failed to marshal input: %w", err)
	}

	output, err := json.Marshal(nr.Output)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	query := `
		INSERT INTO automation_run_steps (
			id, automation_run_id, node_id, node_key, node_type,
			status, error_message, error_code,
			input, output, condition_result,
			started_at, completed_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	_, err = r.db.ExecContext(ctx, query,
		nr.ID.String(),
		nr.WorkflowRunID.String(),
		nr.NodeID.String(),
		nr.NodeKey,
		string(nr.NodeType),
		string(nr.Status),
		nr.ErrorMessage,
		nr.ErrorCode,
		input,
		output,
		nr.ConditionResult,
		nr.StartedAt,
		nr.CompletedAt,
		nr.CreatedAt,
	)

	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "node run already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create node run: %w", err)
	}

	return nil
}

// CreateBatch creates multiple node runs.
func (r *AutomationRunStepRepository) CreateBatch(ctx context.Context, nodeRuns []*automation.NodeRun) error {
	if len(nodeRuns) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `
		INSERT INTO automation_run_steps (
			id, automation_run_id, node_id, node_key, node_type,
			status, error_message, error_code,
			input, output, condition_result,
			started_at, completed_at, created_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`

	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	for _, nr := range nodeRuns {
		input, err := json.Marshal(nr.Input)
		if err != nil {
			return fmt.Errorf("failed to marshal input: %w", err)
		}

		output, err := json.Marshal(nr.Output)
		if err != nil {
			return fmt.Errorf("failed to marshal output: %w", err)
		}

		_, err = stmt.ExecContext(ctx,
			nr.ID.String(),
			nr.WorkflowRunID.String(),
			nr.NodeID.String(),
			nr.NodeKey,
			string(nr.NodeType),
			string(nr.Status),
			nr.ErrorMessage,
			nr.ErrorCode,
			input,
			output,
			nr.ConditionResult,
			nr.StartedAt,
			nr.CompletedAt,
			nr.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("failed to insert node run: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetByID retrieves a node run by ID.
func (r *AutomationRunStepRepository) GetByID(ctx context.Context, id shared.ID) (*automation.NodeRun, error) {
	query := r.selectQuery() + " WHERE id = $1"

	rows, err := r.db.QueryContext(ctx, query, id.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query node run: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, shared.ErrNotFound
	}

	return scanNodeRun(rows)
}

// GetByWorkflowRunID retrieves all node runs for a workflow run.
func (r *AutomationRunStepRepository) GetByWorkflowRunID(ctx context.Context, workflowRunID shared.ID) ([]*automation.NodeRun, error) {
	query := r.selectQuery() + " WHERE automation_run_id = $1 ORDER BY created_at ASC"

	rows, err := r.db.QueryContext(ctx, query, workflowRunID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query node runs: %w", err)
	}
	defer rows.Close()

	var nodeRuns []*automation.NodeRun
	for rows.Next() {
		nr, err := scanNodeRun(rows)
		if err != nil {
			return nil, err
		}
		nodeRuns = append(nodeRuns, nr)
	}

	return nodeRuns, nil
}

// GetByNodeKey retrieves a node run by workflow run ID and node key.
func (r *AutomationRunStepRepository) GetByNodeKey(ctx context.Context, workflowRunID shared.ID, nodeKey string) (*automation.NodeRun, error) {
	query := r.selectQuery() + " WHERE automation_run_id = $1 AND node_key = $2"

	rows, err := r.db.QueryContext(ctx, query, workflowRunID.String(), nodeKey)
	if err != nil {
		return nil, fmt.Errorf("failed to query node run by key: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, shared.ErrNotFound
	}

	return scanNodeRun(rows)
}

// List lists node runs with filters.
func (r *AutomationRunStepRepository) List(ctx context.Context, filter automation.NodeRunFilter) ([]*automation.NodeRun, error) {
	query := r.selectQuery()
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		query += " WHERE " + whereClause
	}

	query += " ORDER BY created_at ASC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list node runs: %w", err)
	}
	defer rows.Close()

	var nodeRuns []*automation.NodeRun
	for rows.Next() {
		nr, err := scanNodeRun(rows)
		if err != nil {
			return nil, err
		}
		nodeRuns = append(nodeRuns, nr)
	}

	return nodeRuns, nil
}

// Update updates a node run.
func (r *AutomationRunStepRepository) Update(ctx context.Context, nr *automation.NodeRun) error {
	input, err := json.Marshal(nr.Input)
	if err != nil {
		return fmt.Errorf("failed to marshal input: %w", err)
	}

	output, err := json.Marshal(nr.Output)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	query := `
		UPDATE automation_run_steps
		SET status = $2, error_message = $3, error_code = $4,
		    input = $5, output = $6, condition_result = $7,
		    started_at = $8, completed_at = $9
		WHERE id = $1
		  AND status NOT IN ('completed', 'failed', 'skipped')
	`

	result, err := r.db.ExecContext(ctx, query,
		nr.ID.String(),
		string(nr.Status),
		nr.ErrorMessage,
		nr.ErrorCode,
		input,
		output,
		nr.ConditionResult,
		nr.StartedAt,
		nr.CompletedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update node run: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		var exists bool
		if err := r.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM automation_run_steps WHERE id = $1)`,
			nr.ID.String()).Scan(&exists); err != nil {
			return fmt.Errorf("failed to check node run: %w", err)
		}
		if exists {
			return automation.ErrNodeRunAlreadyFinished
		}
		return shared.ErrNotFound
	}

	return nil
}

var _ automation.NodeRunCanceler = (*AutomationRunStepRepository)(nil)

// SkipOpenNodeRuns ends the open node runs of a canceled run (RFC-046 §8):
// only for a run of tenantID that is canceled, so it can be repeated and
// never touches a live run.
func (r *AutomationRunStepRepository) SkipOpenNodeRuns(ctx context.Context, tenantID, runID shared.ID) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE automation_run_steps nr
		SET status = 'skipped', error_message = 'run canceled', completed_at = NOW()
		WHERE nr.automation_run_id = $2
		  AND nr.status IN ('pending', 'running')
		  AND EXISTS (SELECT 1 FROM automation_runs wr
		              WHERE wr.id = $2 AND wr.tenant_id = $1 AND wr.status = 'canceled')`,
		tenantID.String(), runID.String())
	if err != nil {
		return 0, fmt.Errorf("failed to skip open node runs: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to read rows affected: %w", err)
	}
	return n, nil
}

// Delete deletes a node run.
func (r *AutomationRunStepRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM automation_run_steps WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete node run: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// UpdateStatus updates node run status.
func (r *AutomationRunStepRepository) UpdateStatus(ctx context.Context, id shared.ID, status automation.NodeRunStatus, errorMessage, errorCode string) error {
	query := `UPDATE automation_run_steps SET status = $2, error_message = $3, error_code = $4 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id.String(), string(status), errorMessage, errorCode)
	if err != nil {
		return fmt.Errorf("failed to update node run status: %w", err)
	}
	return nil
}

// Complete marks a node run as completed.
func (r *AutomationRunStepRepository) Complete(ctx context.Context, id shared.ID, output map[string]any) error {
	outputJSON, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	query := `
		UPDATE automation_run_steps
		SET status = 'completed', output = $2, completed_at = NOW()
		WHERE id = $1
	`

	_, err = r.db.ExecContext(ctx, query, id.String(), outputJSON)
	if err != nil {
		return fmt.Errorf("failed to complete node run: %w", err)
	}
	return nil
}

// GetPendingByDependencies gets node runs that are pending and have their dependencies completed.
func (r *AutomationRunStepRepository) GetPendingByDependencies(ctx context.Context, workflowRunID shared.ID, completedNodeKeys []string) ([]*automation.NodeRun, error) {
	// This is a simplified version - the actual implementation would need to
	// join with automation_edges to check dependencies
	query := r.selectQuery() + " WHERE automation_run_id = $1 AND status = 'pending'"

	rows, err := r.db.QueryContext(ctx, query, workflowRunID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query pending node runs: %w", err)
	}
	defer rows.Close()

	var nodeRuns []*automation.NodeRun
	for rows.Next() {
		nr, err := scanNodeRun(rows)
		if err != nil {
			return nil, err
		}
		nodeRuns = append(nodeRuns, nr)
	}

	return nodeRuns, nil
}

func (r *AutomationRunStepRepository) selectQuery() string {
	return `
		SELECT id, automation_run_id, node_id, node_key, node_type,
		       status, error_message, error_code,
		       input, output, condition_result,
		       started_at, completed_at, created_at
		FROM automation_run_steps
	`
}

func (r *AutomationRunStepRepository) buildWhereClause(filter automation.NodeRunFilter) (string, []any) {
	var conditions []string
	var args []any

	if filter.WorkflowRunID != nil {
		args = append(args, filter.WorkflowRunID.String())
		conditions = append(conditions, fmt.Sprintf("automation_run_id = $%d", len(args)))
	}

	if filter.NodeID != nil {
		args = append(args, filter.NodeID.String())
		conditions = append(conditions, fmt.Sprintf("node_id = $%d", len(args)))
	}

	if filter.Status != nil {
		args = append(args, string(*filter.Status))
		conditions = append(conditions, fmt.Sprintf("status = $%d", len(args)))
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}
