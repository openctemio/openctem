package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// stepExecer is what a step write runs on: the pool or a transaction.
type stepExecer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

const insertStepSQL = `
	INSERT INTO pipeline_steps (
		id, pipeline_id, step_key, name, description, step_order,
		ui_position_x, ui_position_y,
		tool, tool_id, capabilities, config, timeout_seconds,
		depends_on, condition_type, condition_value,
		max_retries, retry_delay_seconds, created_at
	)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
`

// insertStep inserts one step.
func insertStep(ctx context.Context, ex stepExecer, s *pipeline.Step) error {
	config, err := json.Marshal(s.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	_, err = ex.ExecContext(ctx, insertStepSQL,
		s.ID.String(),
		s.PipelineID.String(),
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
// included, keeping its id. Bound to the pipeline, so an id of another
// pipeline's step changes nothing.
func updateStepInPlace(ctx context.Context, ex stepExecer, s *pipeline.Step) error {
	config, err := json.Marshal(s.Config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	res, err := ex.ExecContext(ctx, `
		UPDATE pipeline_steps
		SET step_key = $3, name = $4, description = $5, step_order = $6,
		    ui_position_x = $7, ui_position_y = $8,
		    tool = $9, tool_id = $10, capabilities = $11, config = $12, timeout_seconds = $13,
		    depends_on = $14, condition_type = $15, condition_value = $16,
		    max_retries = $17, retry_delay_seconds = $18
		WHERE id = $1 AND pipeline_id = $2
	`,
		s.ID.String(),
		s.PipelineID.String(),
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

// MutateSteps implements pipeline.StepRepository.
//
// Concurrency: the pipeline row is locked FOR UPDATE before the active-run
// check. Creating a run inserts into pipeline_runs, whose foreign key to
// pipeline_templates takes a KEY SHARE lock on the same row, which conflicts
// with FOR UPDATE. So a run created concurrently either commits first (and
// this save sees it and refuses) or waits until the save commits (and the run
// starts on the saved steps). Two saves of one pipeline are serialized, and
// each mutate sees the steps the previous one stored.
func (r *PipelineStepRepository) MutateSteps(
	ctx context.Context,
	tenantID, pipelineID shared.ID,
	mutate func(current []*pipeline.Step) ([]*pipeline.Step, error),
) ([]*pipeline.Step, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var locked string
	err = tx.QueryRowContext(ctx,
		`SELECT id FROM pipeline_templates WHERE id = $1 AND tenant_id = $2 FOR UPDATE`,
		pipelineID.String(), tenantID.String()).Scan(&locked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to lock pipeline: %w", err)
	}

	var active bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pipeline_runs
			WHERE pipeline_id = $1 AND tenant_id = $2
			  AND status NOT IN `+terminalRunStatusesSQL+`
		)`, pipelineID.String(), tenantID.String()).Scan(&active); err != nil {
		return nil, fmt.Errorf("failed to check active runs: %w", err)
	}
	if active {
		return nil, pipeline.ErrPipelineRunActive
	}

	current, err := r.stepsInTx(ctx, tx, pipelineID)
	if err != nil {
		return nil, err
	}
	existing := make(map[shared.ID]bool, len(current))
	for _, s := range current {
		existing[s.ID] = true
	}

	desired, err := mutate(current)
	if err != nil {
		return nil, err
	}

	keep := make([]string, 0, len(desired))
	seen := make(map[shared.ID]bool, len(desired))
	for _, s := range desired {
		if s.ID.IsZero() || seen[s.ID] {
			return nil, fmt.Errorf("%w: duplicate or missing step id", shared.ErrValidation)
		}
		seen[s.ID] = true
		s.PipelineID = pipelineID
		keep = append(keep, s.ID.String())
	}

	// Removed steps go; their step runs stay (step_runs.step_id SET NULL).
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM pipeline_steps WHERE pipeline_id = $1 AND NOT (id = ANY($2::uuid[]))`,
		pipelineID.String(), pq.Array(keep)); err != nil {
		return nil, fmt.Errorf("failed to remove steps: %w", err)
	}
	// Park the kept steps' keys on a value no request can produce, so keys
	// can move between kept steps (a rename, or two steps swapping keys)
	// without tripping UNIQUE (pipeline_id, step_key) half way.
	if _, err := tx.ExecContext(ctx,
		`UPDATE pipeline_steps SET step_key = '~' || id::text WHERE pipeline_id = $1`,
		pipelineID.String()); err != nil {
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

func (r *PipelineStepRepository) stepsInTx(ctx context.Context, tx *sql.Tx, pipelineID shared.ID) ([]*pipeline.Step, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, pipeline_id, step_key, name, description, step_order,
		       ui_position_x, ui_position_y,
		       tool, tool_id, capabilities, config, timeout_seconds,
		       depends_on, condition_type, condition_value,
		       max_retries, retry_delay_seconds, created_at
		FROM pipeline_steps
		WHERE pipeline_id = $1
		ORDER BY step_order ASC
	`, pipelineID.String())
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
	return steps, rows.Err()
}
