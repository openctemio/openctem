package postgres

// Tasks of a run, read from the commands it dispatched (RFC-046 §4.1).
// See docs/rfcs/RFC-046-scans-redesign.md.

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ pipeline.TaskReader = (*CommandRepository)(nil)

// runTaskStatusSQL maps a command status onto a task status.
const runTaskStatusSQL = `CASE commands.status
	WHEN 'pending' THEN 'queued'
	WHEN 'acknowledged' THEN 'running'
	WHEN 'running' THEN 'running'
	WHEN 'completed' THEN 'completed'
	WHEN 'canceled' THEN 'canceled'
	ELSE 'failed' END`

// runTaskTargetsSQL counts a command's targets: its targets array, or one
// for a single target.
const runTaskTargetsSQL = `CASE
	WHEN jsonb_typeof(commands.payload->'targets') = 'array' THEN jsonb_array_length(commands.payload->'targets')
	WHEN COALESCE(commands.payload->>'target', '') <> '' THEN 1
	ELSE 0 END`

// runTaskSummarySQL aggregates the task summary columns over commands.
const runTaskSummarySQL = `
	count(*),
	count(*) FILTER (WHERE commands.status = 'pending'),
	count(*) FILTER (WHERE commands.status IN ('acknowledged', 'running')),
	count(*) FILTER (WHERE commands.status = 'completed'),
	count(*) FILTER (WHERE commands.status NOT IN ('pending', 'acknowledged', 'running', 'completed', 'canceled')),
	count(*) FILTER (WHERE commands.status = 'canceled'),
	count(DISTINCT commands.sensor_id) FILTER (WHERE commands.acknowledged_at IS NOT NULL)`

// ListRunTasks returns up to limit commands of runID in dispatch order, and
// the summary of all of them. A command belongs to the run through the
// pipeline_run_id that both the scan and the pipeline dispatcher write into
// its payload (served by idx_commands_pipeline_run). Only commands of tenantID are read, and a sensor is named only
// when it is a sensor of tenantID; a shared platform sensor stays anonymous.
func (r *CommandRepository) ListRunTasks(ctx context.Context, tenantID, runID shared.ID, limit int) ([]pipeline.Task, pipeline.TaskSummary, error) {
	if limit <= 0 || limit > pipeline.MaxRunTasks {
		limit = pipeline.MaxRunTasks
	}
	membership := `commands.tenant_id = $1 AND (commands.payload->>'pipeline_run_id') = $2::text`

	var sum pipeline.TaskSummary
	if err := r.db.QueryRowContext(ctx, `SELECT `+runTaskSummarySQL+` FROM commands WHERE `+membership,
		tenantID.String(), runID.String()).
		Scan(&sum.Total, &sum.Queued, &sum.Running, &sum.Completed, &sum.Failed, &sum.Canceled, &sum.Sensors); err != nil {
		return nil, pipeline.TaskSummary{}, fmt.Errorf("failed to summarize run tasks: %w", err)
	}
	if sum.Total == 0 {
		return nil, sum, nil
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT commands.id, commands.step_run_id,
		       COALESCE(sr.step_key, commands.payload->>'step_key', ''),
		       COALESCE(`+commandToolSQL+`, ''),
		       `+runTaskStatusSQL+`,
		       s.id, COALESCE(s.name, ''),
		       COALESCE(commands.is_platform_job, FALSE),
		       `+runTaskTargetsSQL+`,
		       COALESCE(commands.dispatch_attempts, 0),
		       commands.created_at, commands.started_at, commands.completed_at,
		       COALESCE(commands.error_message, '')
		FROM commands
		LEFT JOIN step_runs sr ON sr.id = commands.step_run_id
		LEFT JOIN sensors s ON s.id = commands.sensor_id AND s.tenant_id = commands.tenant_id
		WHERE `+membership+`
		ORDER BY commands.created_at, commands.id
		LIMIT $3`,
		tenantID.String(), runID.String(), limit)
	if err != nil {
		return nil, pipeline.TaskSummary{}, fmt.Errorf("failed to list run tasks: %w", err)
	}
	defer rows.Close()

	tasks := make([]pipeline.Task, 0, min(sum.Total, limit))
	for rows.Next() {
		var (
			t                     pipeline.Task
			id                    string
			stepRunID, sensorID   sql.NullString
			status                string
			startedAt, completeAt sql.NullTime
		)
		if err := rows.Scan(&id, &stepRunID, &t.StepKey, &t.Tool, &status, &sensorID, &t.SensorName,
			&t.Platform, &t.Targets, &t.Attempts, &t.CreatedAt, &startedAt, &completeAt, &t.ErrorMessage); err != nil {
			return nil, pipeline.TaskSummary{}, fmt.Errorf("failed to scan run task: %w", err)
		}
		t.ID, _ = shared.IDFromString(id)
		t.Status = pipeline.TaskStatus(status)
		if stepRunID.Valid {
			if sid, err := shared.IDFromString(stepRunID.String); err == nil {
				t.StepRunID = &sid
			}
		}
		if sensorID.Valid {
			if sid, err := shared.IDFromString(sensorID.String); err == nil {
				t.SensorID = &sid
			}
		}
		if startedAt.Valid {
			v := startedAt.Time
			t.StartedAt = &v
		}
		if completeAt.Valid {
			v := completeAt.Time
			t.CompletedAt = &v
		}
		tasks = append(tasks, t)
	}
	if err := rows.Err(); err != nil {
		return nil, pipeline.TaskSummary{}, fmt.Errorf("failed to read run tasks: %w", err)
	}
	return tasks, sum, nil
}

// TaskSummaries returns the task summary of each run in runIDs that has
// tasks, in one query, reading only commands of tenantID.
func (r *CommandRepository) TaskSummaries(ctx context.Context, tenantID shared.ID, runIDs []shared.ID) (map[shared.ID]pipeline.TaskSummary, error) {
	out := make(map[shared.ID]pipeline.TaskSummary, len(runIDs))
	if len(runIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(runIDs))
	for i, id := range runIDs {
		ids[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT commands.payload->>'pipeline_run_id', `+runTaskSummarySQL+`
		FROM commands
		WHERE commands.tenant_id = $1
		  AND (commands.payload->>'pipeline_run_id') = ANY($2::text[])
		GROUP BY commands.payload->>'pipeline_run_id'`,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("failed to summarize tasks: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			runID string
			s     pipeline.TaskSummary
		)
		if err := rows.Scan(&runID, &s.Total, &s.Queued, &s.Running, &s.Completed, &s.Failed, &s.Canceled, &s.Sensors); err != nil {
			return nil, fmt.Errorf("failed to scan task summary: %w", err)
		}
		if id, err := shared.IDFromString(runID); err == nil {
			out[id] = s
		}
	}
	return out, rows.Err()
}
