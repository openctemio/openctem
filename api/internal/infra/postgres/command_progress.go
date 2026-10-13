package postgres

// Per-command progress and stall detection: research/122 and
// pkg/domain/command/progress.go.

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var (
	_ command.ProgressRecorder = (*CommandRepository)(nil)
	_ command.StallReaper      = (*CommandRepository)(nil)
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

// RecordProgress records the progress a heartbeat reports for the commands
// sensorID holds in tenantID. Done is clamped to [0, total] and total to the
// command's target count; done never goes down within a claim, and
// last_progress_at moves only when done grows. Entries for commands the
// sensor does not hold are ignored. Returns the rows updated.
func (r *CommandRepository) RecordProgress(ctx context.Context, tenantID, sensorID shared.ID, progress map[string]command.Progress) (int64, error) {
	if len(progress) == 0 {
		return 0, nil
	}
	ids := make([]string, 0, min(len(progress), command.MaxProgressEntries))
	done := make([]int64, 0, cap(ids))
	total := make([]int64, 0, cap(ids))
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
	}
	if len(ids) == 0 {
		return 0, nil
	}
	res, err := r.db.ExecContext(ctx, `
		UPDATE commands c
		SET progress_total = n.total,
		    progress_done = GREATEST(COALESCE(c.progress_done, 0), n.done),
		    last_progress_at = CASE WHEN n.done > COALESCE(c.progress_done, 0) OR c.last_progress_at IS NULL
		                            THEN NOW() ELSE c.last_progress_at END
		FROM (
			SELECT c.id,
			       LEAST(p.total, `+commandTargetCountSQL+`) AS total,
			       LEAST(p.done, p.total, `+commandTargetCountSQL+`) AS done
			FROM unnest($3::text[], $4::bigint[], $5::bigint[]) AS p(id, done, total)
			JOIN commands c ON c.id = p.id::uuid
			WHERE c.tenant_id = $1 AND c.sensor_id = $2
			  AND c.status IN ('acknowledged', 'running')
		) n
		WHERE c.id = n.id`,
		tenantID.String(), sensorID.String(), pq.Array(ids), pq.Array(done), pq.Array(total))
	if err != nil {
		return 0, fmt.Errorf("failed to record command progress: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to read rows affected: %w", err)
	}
	return n, nil
}

// RequeueStalledCommands puts back to pending every running tenant command
// with a budget that either finished no target for its stall window (only
// when its sensor reports progress and targets remain) or ran past twice its
// task budget plus command.OverrunGraceSeconds. Like a lost lease: unpinned,
// one more dispatch attempt (fail_exhausted_commands ends a command that
// keeps stalling), progress cleared, and the holder fenced out (its later
// writes fail the sensor/state/epoch guard; its heartbeat is told to cancel).
func (r *CommandRepository) RequeueStalledCommands(ctx context.Context) ([]command.RequeuedCommand, error) {
	task := budgetSecondsSQL("task_seconds", 300, 86400)
	stall := budgetSecondsSQL("stall_seconds", 300, 3600)
	rows, err := r.db.QueryContext(ctx, `
		UPDATE commands c
		SET status = 'pending', sensor_id = NULL,
		    acknowledged_at = NULL, started_at = NULL,
		    lease_expires_at = NULL,
		    dispatch_attempts = c.dispatch_attempts + 1,
		    progress_done = NULL, progress_total = NULL, last_progress_at = NULL,
		    error_message = s.msg
		FROM (
			SELECT c.id, c.sensor_id AS old_sensor_id, c.lease_epoch AS old_epoch,
			       CASE WHEN NOW() > c.started_at + make_interval(secs => 2 * (`+task+`) + $3)
			            THEN $1 ELSE $2 END AS msg
			FROM commands c
			WHERE c.status = 'running'
			  AND c.is_platform_job = FALSE
			  AND c.started_at IS NOT NULL
			  AND jsonb_typeof(c.payload->'budget') = 'object'
			  AND (
			    NOW() > c.started_at + make_interval(secs => 2 * (`+task+`) + $3)
			    OR (c.progress_total > 0 AND c.progress_done < c.progress_total
			        AND NOW() > COALESCE(c.last_progress_at, c.started_at) + make_interval(secs => `+stall+`))
			  )
			FOR UPDATE OF c SKIP LOCKED
		) s
		WHERE c.id = s.id
		RETURNING c.id, c.tenant_id, s.old_sensor_id, s.old_epoch`,
		command.OverrunMessage, command.StalledMessage, command.OverrunGraceSeconds)
	if err != nil {
		return nil, fmt.Errorf("failed to re-queue stalled commands: %w", err)
	}
	return r.collectRequeued(rows)
}
