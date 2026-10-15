package postgres

// Tasks of a run, read from the commands it dispatched (RFC-046 §4.1).
// See docs/rfcs/RFC-046-scans-redesign.md.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanwindow"

	"github.com/lib/pq"
	"github.com/openctemio/ctis/outcome"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ scanrun.TaskReader = (*CommandRepository)(nil)

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
	count(DISTINCT commands.sensor_id) FILTER (WHERE commands.acknowledged_at IS NOT NULL AND NOT COALESCE(commands.is_platform_job, FALSE))`

// ListRunTasks returns up to limit commands of runID in dispatch order, and
// the summary of all of them. A command belongs to the run through the
// scan_run_id that both the scan and the scan workflow dispatcher write into
// its payload (served by idx_commands_pipeline_run). Only commands of tenantID are read, and a sensor is named only
// when it is a sensor of tenantID; a shared platform sensor stays anonymous.
func (r *CommandRepository) ListRunTasks(ctx context.Context, tenantID, runID shared.ID, limit int) ([]scanrun.Task, scanrun.TaskSummary, error) {
	if limit <= 0 || limit > scanrun.MaxRunTasks {
		limit = scanrun.MaxRunTasks
	}
	membership := `commands.tenant_id = $1 AND (commands.payload->>'scan_run_id') = $2::text`

	var sum scanrun.TaskSummary
	if err := r.db.QueryRowContext(ctx, `SELECT `+runTaskSummarySQL+` FROM commands WHERE `+membership,
		tenantID.String(), runID.String()).
		Scan(&sum.Total, &sum.Queued, &sum.Running, &sum.Completed, &sum.Failed, &sum.Canceled, &sum.Sensors); err != nil {
		return nil, scanrun.TaskSummary{}, fmt.Errorf("failed to summarize run tasks: %w", err)
	}
	if sum.Total == 0 {
		return nil, sum, nil
	}

	tasks, err := r.queryRunTasks(ctx, membership, []any{tenantID.String(), runID.String()}, limit, min(sum.Total, limit))
	if err != nil {
		return nil, scanrun.TaskSummary{}, err
	}
	return tasks, sum, nil
}

var _ scanrun.TaskPager = (*CommandRepository)(nil)

// ListRunTasksAfter returns up to limit tasks of runID after the cursor, in
// dispatch order (created_at, id); from the first task when after is nil.
// Only commands of tenantID are read, and sensors are named as in
// ListRunTasks.
func (r *CommandRepository) ListRunTasksAfter(ctx context.Context, tenantID, runID shared.ID, after *scanrun.TaskCursor, limit int) ([]scanrun.Task, error) {
	if limit <= 0 || limit > scanrun.MaxRunTasks {
		limit = scanrun.MaxRunTasks
	}
	where := `commands.tenant_id = $1 AND (commands.payload->>'scan_run_id') = $2::text`
	args := []any{tenantID.String(), runID.String()}
	if after != nil {
		where += ` AND (commands.created_at, commands.id) > ($3::timestamptz, $4::uuid)`
		args = append(args, after.CreatedAt, after.ID.String())
	}
	return r.queryRunTasks(ctx, where, args, limit, limit)
}

// queryRunTasks reads the tasks matching where (a constant predicate over
// commands; values only in args) in dispatch order, at most limit of them.
func (r *CommandRepository) queryRunTasks(ctx context.Context, where string, args []any, limit, capacity int) ([]scanrun.Task, error) {
	args = append(args, limit)
	rows, err := r.db.QueryContext(ctx, `
		SELECT commands.id, commands.scan_run_step_id,
		       COALESCE(sr.step_key, commands.payload->>'step_key', ''),
		       COALESCE(`+commandToolSQL+`, ''),
		       `+runTaskStatusSQL+`,
		       CASE WHEN commands.is_platform_job THEN NULL ELSE s.id END,
		       CASE WHEN commands.is_platform_job THEN '' ELSE COALESCE(s.name, '') END,
		       COALESCE(commands.is_platform_job, FALSE),
		       `+runTaskTargetsSQL+`,
		       COALESCE(commands.dispatch_attempts, 0),
		       commands.created_at, commands.started_at, commands.completed_at,
		       COALESCE(commands.error_message, ''),
		       CASE WHEN jsonb_typeof(commands.result->'metadata'->'refused_targets') = 'array'
		            THEN commands.result->'metadata'->'refused_targets' END,
		       CASE WHEN jsonb_typeof(commands.result->'metadata'->'refused_targets_total') = 'number'
		            THEN LEAST(GREATEST((commands.result->'metadata'->>'refused_targets_total')::numeric, 0), `+strconv.Itoa(scanrun.MaxSkippedTargetsTotal)+`)::bigint
		            ELSE 0 END,
		       CASE WHEN commands.status = 'pending' THEN commands.window_hold END,
		       CASE WHEN jsonb_typeof(commands.result->'metadata'->'coverage_gaps') = 'array'
		            THEN commands.result->'metadata'->'coverage_gaps' END,
		       CASE WHEN jsonb_typeof(commands.result->'metadata'->'coverage_gaps_total') = 'number'
		            THEN LEAST(GREATEST((commands.result->'metadata'->>'coverage_gaps_total')::numeric, 0), `+strconv.Itoa(scanrun.MaxCoverageGapsTotal)+`)::bigint
		            ELSE 0 END,
		       commands.progress_done, commands.progress_total, commands.last_progress_at,
		       CASE WHEN (commands.payload->'budget'->>'task_seconds') ~ '^[0-9]{1,9}$'
		            THEN LEAST((commands.payload->'budget'->>'task_seconds')::bigint, 86400) END,
		       CASE WHEN (commands.payload->'budget'->>'stall_seconds') ~ '^[0-9]{1,9}$'
		            THEN LEAST((commands.payload->'budget'->>'stall_seconds')::bigint, 86400) END,
		       (commands.status = 'pending' AND NOT `+hostFreePredicate+`),
		       `+egressRefusedTargetsSQL+`,
		       `+guardRefusedTargetsSQL+`,
		       CASE WHEN jsonb_typeof(commands.result->'metadata'->'refused_targets') = 'array'
		            THEN jsonb_array_length(commands.result->'metadata'->'refused_targets') ELSE 0 END
		FROM commands
		LEFT JOIN scan_run_steps sr ON sr.id = commands.scan_run_step_id
		LEFT JOIN sensors s ON s.id = commands.sensor_id AND s.tenant_id = commands.tenant_id AND s.scope = 'organization'
		WHERE `+where+`
		ORDER BY commands.created_at, commands.id
		LIMIT $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list run tasks: %w", err)
	}
	defer rows.Close()

	tasks := make([]scanrun.Task, 0, capacity)
	for rows.Next() {
		var (
			t                     scanrun.Task
			id                    string
			stepRunID, sensorID   sql.NullString
			status                string
			startedAt, completeAt sql.NullTime
			skipped, hold, gaps   []byte
			skippedTotal          int
			guardListed, listed   int
			gapsTotal             int
			progDone, progTotal   sql.NullInt64
			progressAt            sql.NullTime
			taskSecs, stallSecs   sql.NullInt64
		)
		if err := rows.Scan(&id, &stepRunID, &t.StepKey, &t.Tool, &status, &sensorID, &t.SensorName,
			&t.Platform, &t.Targets, &t.Attempts, &t.CreatedAt, &startedAt, &completeAt, &t.ErrorMessage,
			&skipped, &skippedTotal, &hold, &gaps, &gapsTotal,
			&progDone, &progTotal, &progressAt, &taskSecs, &stallSecs, &t.WaitingOnHosts, &t.EgressRefusedTargets,
			&guardListed, &listed); err != nil {
			return nil, fmt.Errorf("failed to scan run task: %w", err)
		}
		// Sensor-supplied: parsed defensively, bounded and cleaned.
		t.Skipped, t.SkippedTotal = scanrun.ParseSkippedTargets(skipped, skippedTotal)
		t.CoverageGaps, t.CoverageGapsTotal = scanrun.ParseCoverageGaps(gaps, gapsTotal)
		// Sensor-supplied: never more than the task's own targets.
		t.EgressRefusedTargets = min(max(t.EgressRefusedTargets, 0), t.Targets)
		t.GuardRefusedTargets = scanrun.GuardRefusedCount(guardListed, listed, skippedTotal, t.Targets)
		if len(hold) > 0 {
			var h scanwindow.Hold
			if json.Unmarshal(hold, &h) == nil {
				t.WindowHold = &h
			}
		}
		t.ID, _ = shared.IDFromString(id)
		t.Status = scanrun.TaskStatus(status)
		if progTotal.Valid && progTotal.Int64 > 0 {
			t.Progress = &scanrun.TaskProgress{Done: int(progDone.Int64), Total: int(progTotal.Int64)}
			if progressAt.Valid {
				v := progressAt.Time
				t.Progress.LastAt = &v
			}
		}
		t.BudgetSeconds = int(taskSecs.Int64)
		t.StallSeconds = int(stallSecs.Int64)
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
		return nil, fmt.Errorf("failed to read run tasks: %w", err)
	}
	return tasks, nil
}

// TaskSummaries returns the task summary of each run in runIDs that has
// tasks, in one query, reading only commands of tenantID.
func (r *CommandRepository) TaskSummaries(ctx context.Context, tenantID shared.ID, runIDs []shared.ID) (map[shared.ID]scanrun.TaskSummary, error) {
	out := make(map[shared.ID]scanrun.TaskSummary, len(runIDs))
	if len(runIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(runIDs))
	for i, id := range runIDs {
		ids[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT commands.payload->>'scan_run_id', `+runTaskSummarySQL+`
		FROM commands
		WHERE commands.tenant_id = $1
		  AND (commands.payload->>'scan_run_id') = ANY($2::text[])
		GROUP BY commands.payload->>'scan_run_id'`,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("failed to summarize tasks: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			runID string
			s     scanrun.TaskSummary
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

// guardRefusedTargetsSQL counts the entries of a command result's
// refused_targets list (sensor result metadata) that the sensor's target
// guard refused: rule target_guard. It reads at most outcome.MaxTargets
// entries; the caller bounds the count by the command's targets
// (scanrun.GuardRefusedCount).
var guardRefusedTargetsSQL = `CASE WHEN jsonb_typeof(commands.result->'metadata'->'refused_targets') = 'array'
		       THEN (SELECT count(*) FROM (
		                SELECT o FROM jsonb_array_elements(commands.result->'metadata'->'refused_targets') o
		                LIMIT ` + strconv.Itoa(outcome.MaxTargets) + `) e
		             WHERE e.o->>'rule' = '` + scanrun.SkipRuleTargetGuard + `')
		       ELSE 0 END`

// egressRefusedTargetsSQL counts the per-target outcomes of a completed
// command's result (ctis outcome, target_outcomes) that its sensor's
// network confinement refused: failed with class egress_refused. It reads
// at most outcome.MaxTargets entries; the caller bounds the count by the
// command's targets.
var egressRefusedTargetsSQL = `CASE WHEN commands.status = 'completed'
		            AND jsonb_typeof(commands.result->'` + outcome.ResultKey + `') = 'array'
		       THEN (SELECT count(*) FROM (
		                SELECT o FROM jsonb_array_elements(commands.result->'` + outcome.ResultKey + `') o
		                LIMIT ` + strconv.Itoa(outcome.MaxTargets) + `) e
		             WHERE e.o->>'state' = '` + string(outcome.Failed) + `'
		               AND e.o->>'class' = '` + string(outcome.EgressRefused) + `')
		       ELSE 0 END`
