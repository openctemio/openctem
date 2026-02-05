package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/workflow"
)

// WorkflowNodeRunRepository implements workflow.NodeRunRepository using PostgreSQL.
type WorkflowNodeRunRepository struct {
	db *DB
}

// NewWorkflowNodeRunRepository creates a new WorkflowNodeRunRepository.
func NewWorkflowNodeRunRepository(db *DB) *WorkflowNodeRunRepository {
	return &WorkflowNodeRunRepository{db: db}
}

// Create creates a new node run.
func (r *WorkflowNodeRunRepository) Create(ctx context.Context, nr *workflow.NodeRun) error {
	input, err := json.Marshal(nr.Input)
	if err != nil {
		return fmt.Errorf("failed to marshal input: %w", err)
	}

	output, err := json.Marshal(nr.Output)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	query := `
		INSERT INTO workflow_node_runs (
			id, workflow_run_id, node_id, node_key, node_type,
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
func (r *WorkflowNodeRunRepository) CreateBatch(ctx context.Context, nodeRuns []*workflow.NodeRun) error {
	if len(nodeRuns) == 0 {
		return nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `
		INSERT INTO workflow_node_runs (
			id, workflow_run_id, node_id, node_key, node_type,
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
func (r *WorkflowNodeRunRepository) GetByID(ctx context.Context, id shared.ID) (*workflow.NodeRun, error) {
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
func (r *WorkflowNodeRunRepository) GetByWorkflowRunID(ctx context.Context, workflowRunID shared.ID) ([]*workflow.NodeRun, error) {
	query := r.selectQuery() + " WHERE workflow_run_id = $1 ORDER BY created_at ASC"

	rows, err := r.db.QueryContext(ctx, query, workflowRunID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query node runs: %w", err)
	}
	defer rows.Close()

	var nodeRuns []*workflow.NodeRun
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
func (r *WorkflowNodeRunRepository) GetByNodeKey(ctx context.Context, workflowRunID shared.ID, nodeKey string) (*workflow.NodeRun, error) {
	query := r.selectQuery() + " WHERE workflow_run_id = $1 AND node_key = $2"

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
func (r *WorkflowNodeRunRepository) List(ctx context.Context, filter workflow.NodeRunFilter) ([]*workflow.NodeRun, error) {
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

	var nodeRuns []*workflow.NodeRun
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
func (r *WorkflowNodeRunRepository) Update(ctx context.Context, nr *workflow.NodeRun) error {
	input, err := json.Marshal(nr.Input)
	if err != nil {
		return fmt.Errorf("failed to marshal input: %w", err)
	}

	output, err := json.Marshal(nr.Output)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	query := `
		UPDATE workflow_node_runs
		SET status = $2, error_message = $3, error_code = $4,
		    input = $5, output = $6, condition_result = $7,
		    started_at = $8, completed_at = $9
		WHERE id = $1
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
		return shared.ErrNotFound
	}

	return nil
}

// Delete deletes a node run.
func (r *WorkflowNodeRunRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM workflow_node_runs WHERE id = $1"
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
func (r *WorkflowNodeRunRepository) UpdateStatus(ctx context.Context, id shared.ID, status workflow.NodeRunStatus, errorMessage, errorCode string) error {
	query := `UPDATE workflow_node_runs SET status = $2, error_message = $3, error_code = $4 WHERE id = $1`
	_, err := r.db.ExecContext(ctx, query, id.String(), string(status), errorMessage, errorCode)
	if err != nil {
		return fmt.Errorf("failed to update node run status: %w", err)
	}
	return nil
}

// Complete marks a node run as completed.
func (r *WorkflowNodeRunRepository) Complete(ctx context.Context, id shared.ID, output map[string]any) error {
	outputJSON, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	query := `
		UPDATE workflow_node_runs
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
func (r *WorkflowNodeRunRepository) GetPendingByDependencies(ctx context.Context, workflowRunID shared.ID, completedNodeKeys []string) ([]*workflow.NodeRun, error) {
	// This is a simplified version - the actual implementation would need to
	// join with workflow_edges to check dependencies
	query := r.selectQuery() + " WHERE workflow_run_id = $1 AND status = 'pending'"

	rows, err := r.db.QueryContext(ctx, query, workflowRunID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query pending node runs: %w", err)
	}
	defer rows.Close()

	var nodeRuns []*workflow.NodeRun
	for rows.Next() {
		nr, err := scanNodeRun(rows)
		if err != nil {
			return nil, err
		}
		nodeRuns = append(nodeRuns, nr)
	}

	return nodeRuns, nil
}

func (r *WorkflowNodeRunRepository) selectQuery() string {
	return `
		SELECT id, workflow_run_id, node_id, node_key, node_type,
		       status, error_message, error_code,
		       input, output, condition_result,
		       started_at, completed_at, created_at
		FROM workflow_node_runs
	`
}

func (r *WorkflowNodeRunRepository) buildWhereClause(filter workflow.NodeRunFilter) (string, []any) {
	var conditions []string
	var args []any
	argIndex := 1

	if filter.WorkflowRunID != nil {
		conditions = append(conditions, fmt.Sprintf("workflow_run_id = $%d", argIndex))
		args = append(args, filter.WorkflowRunID.String())
		argIndex++
	}

	if filter.NodeID != nil {
		conditions = append(conditions, fmt.Sprintf("node_id = $%d", argIndex))
		args = append(args, filter.NodeID.String())
		argIndex++
	}

	if filter.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIndex))
		args = append(args, string(*filter.Status))
		argIndex++
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}
