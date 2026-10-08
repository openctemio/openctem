package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// stepExecer is what a step write runs on: the pool or a transaction.
type stepExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

const insertStepSQL = `
	INSERT INTO scan_workflow_steps (
		id, scan_workflow_id, step_key, name, description, step_order,
		ui_position_x, ui_position_y,
		tool, tool_id, capabilities, config, timeout_seconds,
		depends_on, condition_type, condition_value,
		max_retries, retry_delay_seconds, created_at, prefer_tools
	)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
`

// insertStep inserts one step.
func insertStep(ctx context.Context, ex stepExecer, s *scanworkflow.Step) error {
	config, err := json.Marshal(s.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	_, err = ex.ExecContext(ctx, insertStepSQL,
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
	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "step already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to create pipeline step: %w", err)
	}
	return nil
}

// updateStepInPlace rewrites every editable column of a step, step_key
// included, keeping its id. Bound to the scan workflow, so an id of another
// scan workflow's step changes nothing.
func updateStepInPlace(ctx context.Context, ex stepExecer, s *scanworkflow.Step) error {
	config, err := json.Marshal(s.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	res, err := ex.ExecContext(ctx, `
		UPDATE scan_workflow_steps
		SET step_key = $3, name = $4, description = $5, step_order = $6,
		    ui_position_x = $7, ui_position_y = $8,
		    tool = $9, tool_id = $10, capabilities = $11, config = $12, timeout_seconds = $13,
		    depends_on = $14, condition_type = $15, condition_value = $16,
		    max_retries = $17, retry_delay_seconds = $18, prefer_tools = $19
		WHERE id = $1 AND scan_workflow_id = $2
	`,
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
		pq.Array(nonNilStrings(s.PreferTools)),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return shared.NewDomainError("ALREADY_EXISTS", "step already exists", shared.ErrAlreadyExists)
		}
		return fmt.Errorf("failed to update pipeline step: %w", err)
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return shared.ErrNotFound
	}
	return nil
}

// MutateSteps implements scanrun.StepRepository.
//
// Concurrency: the scan workflow row is locked FOR UPDATE before the active-run
// check. Creating a run inserts into scan_runs, whose foreign key to
// scan_workflows takes a KEY SHARE lock on the same row, which conflicts
// with FOR UPDATE. So a run created concurrently either commits first (and
// this save sees it and refuses) or waits until the save commits (and the run
// starts on the saved steps). Two saves of one scan workflow are serialized, and
// each mutate sees the steps the previous one stored.
func (r *ScanWorkflowStepRepository) MutateSteps(
	ctx context.Context,
	tenantID, scanWorkflowID shared.ID,
	mutate func(current []*scanworkflow.Step) ([]*scanworkflow.Step, error),
) ([]*scanworkflow.Step, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var locked string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM scan_workflows WHERE id = $1 AND tenant_id = $2 FOR UPDATE`,
		scanWorkflowID.String(), tenantID.String()).Scan(&locked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to lock pipeline: %w", err)
	}

	var active bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM scan_runs
			WHERE scan_workflow_id = $1 AND tenant_id = $2
			  AND status NOT IN `+terminalRunStatusesSQL+`
		)`, scanWorkflowID.String(), tenantID.String()).Scan(&active); err != nil {
		return nil, fmt.Errorf("failed to check active runs: %w", err)
	}
	if active {
		return nil, scanworkflow.ErrScanWorkflowRunActive
	}

	current, err := r.stepsInTx(ctx, tx, scanWorkflowID)
	if err != nil {
		return nil, err
	}
	existing := make(map[shared.ID]bool, len(current))
	for _, s := range current {
		existing[s.ID] = true
	}

	// The keys as stored: mutate may change the current steps in place.
	storedKeys := make(map[shared.ID]string, len(current))
	for _, s := range current {
		storedKeys[s.ID] = s.StepKey
	}

	desired, err := mutate(current)
	if err != nil {
		return nil, err
	}
	if err := refuseKeyChangeAfterRuns(ctx, tx, tenantID, scanWorkflowID, storedKeys, desired); err != nil {
		return nil, err
	}

	keep := make([]string, 0, len(desired))
	seen := make(map[shared.ID]bool, len(desired))
	for _, s := range desired {
		if s.ID.IsZero() || seen[s.ID] {
			return nil, fmt.Errorf("%w: duplicate or missing step id", shared.ErrValidation)
		}
		seen[s.ID] = true
		s.ScanWorkflowID = scanWorkflowID
		keep = append(keep, s.ID.String())
	}

	// Removed steps go; their step runs stay (scan_run_steps.step_id SET NULL).
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM scan_workflow_steps WHERE scan_workflow_id = $1 AND NOT (id = ANY($2::uuid[]))`,
		scanWorkflowID.String(), pq.Array(keep)); err != nil {
		return nil, fmt.Errorf("failed to remove steps: %w", err)
	}
	// Park the kept steps' keys on a value no request can produce, so keys
	// can move between kept steps (a rename, or two steps swapping keys)
	// without tripping UNIQUE (scan_workflow_id, step_key) half way.
	if _, err := tx.ExecContext(ctx,
		`UPDATE scan_workflow_steps SET step_key = '~' || id::text WHERE scan_workflow_id = $1`,
		scanWorkflowID.String()); err != nil {
		return nil, fmt.Errorf("failed to prepare step keys: %w", err)
	}

	for _, s := range desired {
		if existing[s.ID] {
			err = updateStepInPlace(ctx, tx, s)
		} else {
			err = insertStep(ctx, tx, s)
		}
		if err != nil {
			return nil, err
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit transaction: %w", err)
	}
	return desired, nil
}

// refuseKeyChangeAfterRuns refuses a save that changes a kept step's key
// when the scan workflow has any run (finished ones too): their step runs
// and step outputs name the step by its key. It runs under the scan
// workflow's row lock, so a run cannot be created between the check and the
// write.
func refuseKeyChangeAfterRuns(ctx context.Context, tx *sql.Tx, tenantID, scanWorkflowID shared.ID, keyOf map[shared.ID]string, desired []*scanworkflow.Step) error {
	var oldKey, newKey string
	for _, s := range desired {
		if k, ok := keyOf[s.ID]; ok && k != s.StepKey {
			oldKey, newKey = k, s.StepKey
			break
		}
	}
	if oldKey == "" {
		return nil
	}
	var hasRuns bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM scan_runs WHERE scan_workflow_id = $1 AND tenant_id = $2)`,
		scanWorkflowID.String(), tenantID.String()).Scan(&hasRuns); err != nil {
		return fmt.Errorf("failed to check runs: %w", err)
	}
	if hasRuns {
		return scanworkflow.StepKeyHasRunsError(oldKey, newKey)
	}
	return nil
}

func (r *ScanWorkflowStepRepository) stepsInTx(ctx context.Context, tx *sql.Tx, scanWorkflowID shared.ID) ([]*scanworkflow.Step, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, scan_workflow_id, step_key, name, description, step_order,
		       ui_position_x, ui_position_y,
		       tool, tool_id, capabilities, config, timeout_seconds,
		       depends_on, condition_type, condition_value,
		       max_retries, retry_delay_seconds, created_at, prefer_tools
		FROM scan_workflow_steps
		WHERE scan_workflow_id = $1
		ORDER BY step_order ASC
	`, scanWorkflowID.String())
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
	return steps, rows.Err()
}
