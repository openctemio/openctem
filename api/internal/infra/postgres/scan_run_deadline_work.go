package postgres

// A run's deadline counts active work, not queue wait
// (docs/architecture/scan-lifecycle.md, "Deadline"). The configured timeout of a run
// (the workflow's, or the platform's 24 h cap) used to run from the moment
// the run started, so a run whose tasks waited behind other runs on busy
// sensors spent its time in the queue and was ended before a sensor had
// worked on it. Two rules change that, and neither touches a deadline the
// scan's owner set (scan_max_duration is a hard cap):
//
//   - when a sensor claims a task, the run gets at least the time that
//     task's targets need at that sensor's measured speed (its load report's
//     targets per minute for the tool, twice over plus a margin), or, when
//     the sensor reports no speed, the run's configured timeout from the
//     claim; the claimed task's payload deadline follows, so the sensor
//     budgets the job to the new deadline;
//   - a run past its deadline whose open tasks are all waiting for a busy
//     sensor of the organization (one that could take the task is online
//     with no free slot) or for their hosts (another task scans them) is not
//     timed out, and a run waiting like that is not "no sensor picked up
//     this run's work".
//
// Both stay within the platform cap: started_at plus
// AbsoluteRunTimeoutSeconds.

import (
	"context"
	"fmt"
	"strconv"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

var _ command.RunDeadlineExtender = (*CommandRepository)(nil)

// Work estimate bounds, in seconds.
const (
	// workEstimateMinSeconds is the least a claimed task is given.
	workEstimateMinSeconds = 600
	// workEstimateMarginSeconds is added to the estimate (start-up, result
	// upload).
	workEstimateMarginSeconds = 300
	// workEstimateFactor multiplies the measured time: the speed is an
	// average and one slow host can take far longer.
	workEstimateFactor = 2
)

// configuredRunSecondsSQL is the run's configured timeout without the
// scan's own cap (runs with one are never extended): the workflow's
// timeout, else the platform cap.
func configuredRunSecondsSQL(r string) string {
	return `LEAST(COALESCE(` + workflowCapSQL(r+".scan_workflow_id") + `, ` + strconv.Itoa(AbsoluteRunTimeoutSeconds) + `), ` +
		strconv.Itoa(AbsoluteRunTimeoutSeconds) + `)`
}

// extendAtClaimSQL moves the deadline of every open run with a task among
// $3 that sensor $2 of tenant $1 just claimed, and writes the run's new
// deadline into those tasks' payloads. Other tasks' payloads are left as
// they are: a pending task gets its deadline when it is claimed, and a
// running one already budgets to the deadline it was given.
var extendAtClaimSQL = `
	WITH claimed AS (
		SELECT c.id, c.payload->>'scan_run_id' AS run_id,
		       ` + commandTargetCountSQL + ` AS targets,
		       ` + sensorToolThroughputSQL("s", "("+commandToolSQLOf("c")+")") + ` AS per_min
		FROM commands c
		JOIN sensors s ON s.id = $2 AND s.tenant_id = c.tenant_id
		WHERE c.tenant_id = $1 AND c.id = ANY($3::uuid[]) AND c.sensor_id = $2
		  AND c.status IN ('acknowledged', 'running')
		  AND c.payload->>'scan_run_id' ~ '^[0-9a-fA-F-]{36}$'
	), wanted AS (
		SELECT r.id, MAX(NOW() + make_interval(secs => CASE
		           WHEN k.per_min > 0 THEN LEAST(` + configuredRunSecondsSQL("r") + `::float8 * ` + strconv.Itoa(workEstimateFactor) + `,
		                GREATEST(` + strconv.Itoa(workEstimateMinSeconds) + `,
		                         ` + strconv.Itoa(workEstimateMarginSeconds) + ` + ` + strconv.Itoa(workEstimateFactor) + ` * 60.0 * k.targets / k.per_min))
		           ELSE ` + configuredRunSecondsSQL("r") + `::float8 END)) AS want
		FROM claimed k
		JOIN scan_runs r ON r.tenant_id = $1 AND r.id = k.run_id::uuid
		GROUP BY r.id
	), moved AS (
		UPDATE scan_runs r
		SET deadline_at = LEAST(w.want, r.started_at + make_interval(secs => ` + strconv.Itoa(AbsoluteRunTimeoutSeconds) + `)),
		    deadline_reason = '` + scanrun.DeadlineReasonWorkEstimate + `'
		FROM wanted w
		WHERE r.tenant_id = $1 AND r.id = w.id
		  AND r.status IN ('pending', 'running')
		  AND r.started_at IS NOT NULL AND r.deadline_at IS NOT NULL
		  AND r.deadline_reason IS DISTINCT FROM '` + scanrun.DeadlineReasonScanMaxDuration + `'
		  AND LEAST(w.want, r.started_at + make_interval(secs => ` + strconv.Itoa(AbsoluteRunTimeoutSeconds) + `)) > r.deadline_at
		RETURNING r.id, r.deadline_at
	)
	UPDATE commands c
	SET payload = jsonb_set(c.payload, '{deadline}',
	        to_jsonb(to_char(m.deadline_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')))
	FROM moved m, claimed k
	WHERE c.tenant_id = $1 AND c.id = k.id AND k.run_id = m.id::text
	  AND c.sensor_id = $2 AND c.payload ? 'deadline'`

// commandToolSQLOf is commandToolSQL for command alias c.
func commandToolSQLOf(c string) string {
	return `COALESCE(NULLIF(` + c + `.payload->>'scanner', ''), NULLIF(` + c + `.payload->>'preferred_tool', ''))`
}

// ExtendRunDeadlinesAtClaim gives the runs of the tasks sensorID of
// tenantID just claimed the time those tasks need (extendAtClaimSQL).
// Tenant-scoped: a task or run of another tenant is never read or written.
func (r *CommandRepository) ExtendRunDeadlinesAtClaim(ctx context.Context, tenantID, sensorID shared.ID, ids []shared.ID) error {
	if len(ids) == 0 {
		return nil
	}
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = id.String()
	}
	if _, err := r.db.ExecContext(ctx, extendAtClaimSQL, tenantID.String(), sensorID.String(), pq.Array(strs)); err != nil {
		return fmt.Errorf("failed to extend run deadlines at claim: %w", err)
	}
	return nil
}

// queueWaitSQL is true when pending tenant task "commands" waits behind
// other work, not for a sensor that is missing: an online sensor of its
// organization that could claim it (zone, tool, feature, not refused) has
// no free slot, or (withHosts) its hosts are held by another task.
func queueWaitSQL(withHosts bool) string {
	busy := `(NOT COALESCE(commands.is_platform_job, FALSE) AND EXISTS (
			SELECT 1 FROM sensors qs
			WHERE qs.tenant_id = commands.tenant_id
			  AND qs.scope = 'organization' AND qs.status = 'active'
			  AND qs.health IN ` + sensorDispatchableHealthSQL + ` AND qs.last_seen_at IS NOT NULL
			  AND ` + zoneClaimPredicate("qs.id") + `
			  AND ` + toolClaimPredicate("qs.id") + `
			  AND ` + refusedByPredicate("qs.id") + `
			  AND ` + featureClaimPredicate("qs.id") + `
			  AND ` + sensorFreeSlotsSQL("qs") + ` <= 0))`
	if !withHosts {
		return busy
	}
	return `(` + busy + ` OR NOT ` + hostFreePredicate + `)`
}

// runWaitsInQueueSQL is true when open run pr is past its deadline only
// because its work waits in the queue: its deadline is not the scan owner's
// cap, it is within the platform cap, no task of it is acknowledged or
// running, and a pending task of it waits behind other work (queueWaitSQL).
func runWaitsInQueueSQL() string {
	return `(pr.deadline_reason IS DISTINCT FROM '` + scanrun.DeadlineReasonScanMaxDuration + `'
		AND NOW() < pr.started_at + make_interval(secs => ` + strconv.Itoa(AbsoluteRunTimeoutSeconds) + `)
		AND NOT EXISTS (
			SELECT 1 FROM commands
			WHERE commands.tenant_id = pr.tenant_id AND commands.payload->>'scan_run_id' = pr.id::text
			  AND commands.status IN ('acknowledged', 'running'))
		AND EXISTS (
			SELECT 1 FROM commands
			WHERE commands.tenant_id = pr.tenant_id AND commands.payload->>'scan_run_id' = pr.id::text
			  AND commands.status = 'pending'
			  AND ` + queueWaitSQL(true) + `))`
}
