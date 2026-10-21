package postgres

// Per-command progress and stall detection: research/122 and
// pkg/domain/command/progress.go.

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/ctis/politeness"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var (
	_ command.ProgressRecorder = (*CommandRepository)(nil)
	_ command.StallReaper      = (*CommandRepository)(nil)
	_ command.StallStopper     = (*CommandRepository)(nil)
	_ command.StopFinder       = (*CommandRepository)(nil)
	_ command.StopRequeuer     = (*CommandRepository)(nil)
)

// commandTargetCountSQL is how many targets command c carries (at least 1).
const commandTargetCountSQL = `GREATEST(CASE
	WHEN jsonb_typeof(c.payload->'targets') = 'array' THEN jsonb_array_length(c.payload->'targets')
	ELSE 1 END, 1)`

// budgetSecondsSQL reads one of the payload budget's seconds (a sensor never
// writes the payload; still, a malformed value is ignored, never cast), within
// [lo, hi]; NULL when absent or malformed.
func budgetSecondsSQL(key string, lo, hi int) string {
	return fmt.Sprintf(`CASE WHEN (c.payload->'budget'->>'%[1]s') ~ '^[0-9]{1,9}$'
		THEN LEAST(GREATEST((c.payload->'budget'->>'%[1]s')::bigint, %[2]d), %[3]d) END`, key, lo, hi)
}

// overrunSecondsSQL is when the sensor stops a running command c itself,
// in seconds after its start: sdk-go's job timeout. An explicit payload
// timeout_seconds wins (at most scan.MaxScanTimeoutSeconds); without one it
// is twice the task budget. The platform must not take a task back before
// then: a step with a one-hour timeout and a five-minute budget estimate is
// still within its time at sixteen minutes (live, 2026-10-14: an httpx task
// was re-queued three times at twice its budget while its sensor was
// allowed an hour, and then failed as exhausted). A sensor's local policy
// may cap the timeout lower; that sensor stops earlier, and its result only
// arrives sooner.
func overrunSecondsSQL() string {
	return fmt.Sprintf(`CASE WHEN (c.payload->>'timeout_seconds') ~ '^[0-9]{1,9}$'
		AND (c.payload->>'timeout_seconds')::bigint > 0
		THEN LEAST((c.payload->>'timeout_seconds')::bigint, %d)
		ELSE 2 * (%s) END`, scan.MaxScanTimeoutSeconds, budgetSecondsSQL("task_seconds", 300, 86400))
}

// clearProgressSQL resets a command's progress, liveness, stop request and
// released hosts (a claim or a re-queue starts them afresh: the command
// holds all its hosts again).
const clearProgressSQL = `progress_done = NULL, progress_total = NULL, last_progress_at = NULL,
		    progress_records = NULL, progress_output_bytes = NULL, progress_cpu_ms = NULL,
		    progress_cpu_mark = NULL, stop_requested_at = NULL, settled_host_keys = NULL`

// livenessReportedSQL: the holder reports per-target progress or liveness
// counters for c, so its stall can be judged (a sensor that reports
// neither, or reports nothing until it exits, is bounded by its overrun,
// lease and the run's cap only).
const livenessReportedSQL = `(c.progress_done > 0 OR c.progress_records > 0
		OR c.progress_output_bytes > 0 OR c.progress_cpu_ms > 0)`

// clampCounter bounds a liveness counter a heartbeat sends.
func clampCounter(v int64) int64 {
	return min(max(v, 0), command.MaxLivenessCounter)
}

// boundReleasedKeys is the released keys of one heartbeat entry: without
// empty or over-long keys, at most politeness.MaxKeys.
func boundReleasedKeys(keys []string) []string {
	out := make([]string, 0, min(len(keys), politeness.MaxKeys))
	for _, k := range keys {
		if len(out) == politeness.MaxKeys {
			break
		}
		if k != "" && len(k) <= command.MaxReleasedKeyLen {
			out = append(out, k)
		}
	}
	return out
}

// RecordProgress records the progress a heartbeat reports for the commands
// sensorID holds in tenantID. Host keys the holder released (its settled
// targets no longer need them) stop holding other work back: only keys of
// the command itself, added to those released before within the claim. Done is clamped to [0, total] and total to the
// command's target count; done and the liveness counters never go down
// within a claim. last_progress_at moves only when a signal moves: done,
// records or output bytes grow, or the CPU time grows by command.CPUMoveMs
// since it last counted; a task that moves again is no longer asked to
// stop. Entries for commands the sensor does not hold are ignored, and so
// are entries where nothing moved (no row is written). Returns the rows
// updated.
func (r *CommandRepository) RecordProgress(ctx context.Context, tenantID, sensorID shared.ID, progress map[string]command.Progress) (int64, error) {
	if len(progress) == 0 {
		return 0, nil
	}
	n := min(len(progress), command.MaxProgressEntries)
	ids := make([]string, 0, n)
	done := make([]int64, 0, n)
	total := make([]int64, 0, n)
	records := make([]int64, 0, n)
	outBytes := make([]int64, 0, n)
	cpu := make([]int64, 0, n)
	released := map[string][]string{}
	for id, p := range progress {
		if len(ids) == command.MaxProgressEntries {
			break
		}
		if _, err := shared.IDFromString(id); err != nil || p.Total <= 0 {
			continue
		}
		ids = append(ids, id)
		done = append(done, int64(max(p.Done, 0)))
		total = append(total, int64(p.Total))
		records = append(records, clampCounter(p.Records))
		outBytes = append(outBytes, clampCounter(p.OutputBytes))
		cpu = append(cpu, clampCounter(p.CPUMs))
		if keys := boundReleasedKeys(p.ReleasedKeys); len(keys) > 0 {
			released[id] = keys
		}
	}
	releasedJSON, err := json.Marshal(released)
	if err != nil {
		return 0, fmt.Errorf("failed to encode released hosts: %w", err)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands c
		SET progress_total = n.total,
		    progress_done = GREATEST(COALESCE(c.progress_done, 0), n.done),
		    progress_records = GREATEST(COALESCE(c.progress_records, 0), n.records),
		    progress_output_bytes = GREATEST(COALESCE(c.progress_output_bytes, 0), n.bytes),
		    progress_cpu_ms = GREATEST(COALESCE(c.progress_cpu_ms, 0), n.cpu),
		    progress_cpu_mark = CASE WHEN c.progress_cpu_mark IS NULL OR n.cpu_moved THEN n.cpu ELSE c.progress_cpu_mark END,
		    last_progress_at = CASE WHEN c.last_progress_at IS NULL OR n.moved THEN NOW() ELSE c.last_progress_at END,
		    stop_requested_at = CASE WHEN n.moved THEN NULL ELSE c.stop_requested_at END,
		    -- Released hosts only grow within a claim, and only keys of the
		    -- command itself count (a sensor frees nothing it does not hold).
		    settled_host_keys = CASE WHEN c.host_keys IS NULL OR NOT ($10::jsonb ? c.id::text)
		        THEN c.settled_host_keys
		        ELSE NULLIF(ARRAY(
		            SELECT DISTINCT k FROM unnest(COALESCE(c.settled_host_keys, '{}'::text[])
		                || ARRAY(SELECT jsonb_array_elements_text($10::jsonb -> c.id::text))) AS k
		            WHERE k = ANY(c.host_keys)
		            ORDER BY k), '{}'::text[]) END
		FROM (
			SELECT m.*,
			       (m.done > COALESCE(m.old_done, 0) OR m.records > COALESCE(m.old_records, 0)
			        OR m.bytes > COALESCE(m.old_bytes, 0) OR m.cpu_moved) AS moved
			FROM (
				SELECT c.id,
				       LEAST(p.total, `+commandTargetCountSQL+`) AS total,
				       LEAST(p.done, p.total, `+commandTargetCountSQL+`) AS done,
				       p.records, p.bytes, p.cpu,
				       c.progress_done AS old_done, c.progress_records AS old_records,
				       c.progress_output_bytes AS old_bytes,
				       (c.progress_cpu_mark IS NOT NULL AND p.cpu >= c.progress_cpu_mark + $9) AS cpu_moved
				FROM unnest($3::text[], $4::bigint[], $5::bigint[], $6::bigint[], $7::bigint[], $8::bigint[])
				     AS p(id, done, total, records, bytes, cpu)
				JOIN commands c ON c.id = p.id::uuid
				WHERE c.tenant_id = $1 AND c.sensor_id = $2
				  AND c.status IN ('acknowledged', 'running')
			) m
		) n
		WHERE c.id = n.id
		  -- Nothing moved: no write (a heartbeat repeats the same progress
		  -- until the task advances).
		  AND (n.moved OR c.progress_total IS DISTINCT FROM n.total
		       OR c.last_progress_at IS NULL OR c.progress_cpu_mark IS NULL
		       OR $10::jsonb ? c.id::text)`,
		tenantID.String(), sensorID.String(), pq.Array(ids), pq.Array(done), pq.Array(total),
		pq.Array(records), pq.Array(outBytes), pq.Array(cpu), command.CPUMoveMs, string(releasedJSON))
	if err != nil {
		return 0, fmt.Errorf("failed to record command progress: %w", err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to read rows affected: %w", err)
	}
	return rows, nil
}

// stalledSQL: running command c (shared jobs included) with a budget, targets left, its
// holder reporting progress or liveness, and none of its signals moved for
// its stall window.
func stalledSQL() string {
	return `c.status = 'running'
		  AND c.started_at IS NOT NULL
		  AND jsonb_typeof(c.payload->'budget') = 'object'
		  AND c.progress_total > 0
		  AND c.progress_done < c.progress_total
		  AND ` + livenessReportedSQL + `
		  AND NOW() > COALESCE(c.last_progress_at, c.started_at) + make_interval(secs => ` + budgetSecondsSQL("stall_seconds", 300, 3600) + `)`
}

// RequestStopForStalled marks every stalled command stop-requested (see
// stalledSQL): its holder's heartbeat answer asks it to stop the task and
// hand back what it finished (stop_command_ids). Nothing else changes: the
// holder keeps the command and its lease, and RequeueStalledCommands takes
// it back if no answer comes within command.StopGraceSeconds.
func (r *CommandRepository) RequestStopForStalled(ctx context.Context) ([]command.RequeuedCommand, error) {
	rows, err := r.db.QueryContext(ctx, `
		UPDATE commands c
		SET stop_requested_at = NOW()
		WHERE c.id IN (
			SELECT c.id FROM commands c
			WHERE c.stop_requested_at IS NULL AND `+stalledSQL()+`
			FOR UPDATE OF c SKIP LOCKED
		)
		RETURNING c.id, c.tenant_id, c.sensor_id, c.lease_epoch`)
	if err != nil {
		return nil, fmt.Errorf("failed to request stops of stalled commands: %w", err)
	}
	return r.collectRequeued(rows)
}

// CommandsToStop returns the commands among ids that sensorID holds in
// tenantID, running and stop-requested.
func (r *CommandRepository) CommandsToStop(ctx context.Context, tenantID, sensorID shared.ID, ids []string) ([]string, error) {
	valid := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, err := shared.IDFromString(id); err == nil {
			valid = append(valid, id)
		}
	}
	if len(valid) == 0 {
		return nil, nil
	}
	rows, err := r.db.QueryContext(ctx, `
		SELECT c.id::text FROM commands c
		WHERE c.tenant_id = $1 AND c.sensor_id = $2 AND c.status = 'running'
		  AND c.stop_requested_at IS NOT NULL
		  AND c.id = ANY($3::uuid[])
		ORDER BY c.id`,
		tenantID.String(), sensorID.String(), pq.Array(valid))
	if err != nil {
		return nil, fmt.Errorf("failed to find commands to stop: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("failed to scan command id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// RequeueStopped re-queues cmd, stop-requested and held under expect, that
// its holder reports failed (it stopped with nothing finished): pending,
// unpinned, one more dispatch attempt, progress cleared, as a stall.
func (r *CommandRepository) RequeueStopped(ctx context.Context, cmd *command.Command, expect command.Fence, message string) (bool, error) {
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands
		SET status = 'pending', sensor_id = NULL,
		    acknowledged_at = NULL, started_at = NULL, lease_expires_at = NULL,
		    dispatch_attempts = dispatch_attempts + 1,
		    `+requeueSQL("")+`,
		    `+clearProgressSQL+`,
		    error_message = $6
		WHERE id = $1 AND tenant_id = $2 AND sensor_id = $3
		  AND status = $4 AND lease_epoch = $5
		  AND stop_requested_at IS NOT NULL`,
		cmd.ID.String(), cmd.TenantID.String(), expect.SensorID, string(expect.Status), expect.Epoch, message)
	if err != nil {
		return false, fmt.Errorf("failed to re-queue a stopped command: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("failed to read rows affected: %w", err)
	}
	if n > 0 {
		r.changedTenant(cmd.TenantID)
	}
	return n > 0, nil
}

// RequeueStalledCommands puts back to pending every running command
// with a budget whose sensor reports progress (so it knows budgets: it
// stops the task itself at its deadline, overrunSecondsSQL) that either ran
// past that deadline plus command.OverrunGraceSeconds, or was asked
// to stop as stalled (RequestStopForStalled) and was not handed back within
// command.StopGraceSeconds. A sensor that reports no progress predates
// budgets: it is bounded by its lease and the run's cap only. Like a lost
// lease: unpinned, one more dispatch attempt (fail_exhausted_commands ends a
// command that keeps stalling), progress cleared, and the holder fenced out
// (its later writes fail the sensor/state/epoch guard; its heartbeat is
// told to cancel).
func (r *CommandRepository) RequeueStalledCommands(ctx context.Context) ([]command.RequeuedCommand, error) {
	overrun := overrunSecondsSQL()
	rows, err := r.db.QueryContext(ctx, `
		UPDATE commands c
		SET status = 'pending', sensor_id = NULL,
		    acknowledged_at = NULL, started_at = NULL,
		    lease_expires_at = NULL,
		    dispatch_attempts = c.dispatch_attempts + 1,
		    `+requeueSQL("c.")+`,
		    `+clearProgressSQL+`,
		    error_message = s.msg
		FROM (
			SELECT c.id, c.sensor_id AS old_sensor_id, c.lease_epoch AS old_epoch,
			       CASE WHEN NOW() > c.started_at + make_interval(secs => (`+overrun+`) + $3)
			            THEN $1 ELSE $2 END AS msg
			FROM commands c
			WHERE c.status = 'running'
				  AND c.started_at IS NOT NULL
			  AND jsonb_typeof(c.payload->'budget') = 'object'
			  AND c.progress_total > 0
			  AND (
			    NOW() > c.started_at + make_interval(secs => (`+overrun+`) + $3)
			    OR NOW() > c.stop_requested_at + make_interval(secs => $4)
			  )
			FOR UPDATE OF c SKIP LOCKED
		) s
		WHERE c.id = s.id
		RETURNING c.id, c.tenant_id, s.old_sensor_id, s.old_epoch`,
		command.OverrunMessage, command.StalledMessage, command.OverrunGraceSeconds, command.StopGraceSeconds)
	if err != nil {
		return nil, fmt.Errorf("failed to re-queue stalled commands: %w", err)
	}
	return r.collectRequeued(rows)
}
