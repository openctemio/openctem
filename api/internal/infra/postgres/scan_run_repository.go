package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/scanprofile"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// ScanRunRepository implements scanrun.RunRepository using PostgreSQL.
type ScanRunRepository struct {
	db *DB
}

// NewScanRunRepository creates a new ScanRunRepository.
func NewScanRunRepository(db *DB) *ScanRunRepository {
	return &ScanRunRepository{db: db}
}

// Create persists a new scan run.
func (r *ScanRunRepository) Create(ctx context.Context, run *scanrun.Run) error {
	context, err := json.Marshal(run.Context)
	if err != nil {
		return fmt.Errorf("failed to marshal context: %w", err)
	}

	var qualityGateResult []byte
	if run.QualityGateResult != nil {
		qualityGateResult, err = json.Marshal(run.QualityGateResult)
		if err != nil {
			return fmt.Errorf("failed to marshal quality_gate_result: %w", err)
		}
	}

	query := `
		INSERT INTO scan_runs (
			id, scan_workflow_id, tenant_id, asset_id, scan_id,
			trigger_type, triggered_by, status, context,
			total_steps, completed_steps, failed_steps, skipped_steps, total_findings,
			started_at, completed_at, error_message,
			scan_profile_id, quality_gate_result,
			retry_attempt,
			created_at, scheduled_for, deadline_at, freeze_override, refusal_code
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22,
		        ` + runDeadlineSQL("$15::timestamptz", "$5::uuid") + `, $23, NULLIF($24, ''))
	`

	_, err = r.db.ExecContext(ctx, query,
		run.ID.String(),
		run.ScanWorkflowID.String(),
		run.TenantID.String(),
		nullID(run.AssetID),
		nullID(run.ScanID),
		string(run.TriggerType),
		run.TriggeredBy,
		string(run.Status),
		context,
		run.TotalSteps,
		run.CompletedSteps,
		run.FailedSteps,
		run.SkippedSteps,
		run.TotalFindings,
		nullTime(run.StartedAt),
		nullTime(run.CompletedAt),
		run.ErrorMessage,
		nullID(run.ScanProfileID),
		nullBytes(qualityGateResult),
		run.RetryAttempt,
		run.CreatedAt,
		nullTime(run.ScheduledFor),
		run.FreezeOverride,
		run.RefusalCode,
	)

	if isOccurrenceConflict(err) {
		return scanrun.ErrOccurrenceAlreadyRun
	}
	if err != nil {
		return fmt.Errorf("failed to create pipeline run: %w", err)
	}

	return nil
}

// GetByID retrieves a run by ID.
func (r *ScanRunRepository) GetByID(ctx context.Context, id shared.ID) (*scanrun.Run, error) {
	query := r.selectQuery() + " WHERE id = $1"
	row := r.db.QueryRowContext(ctx, query, id.String())
	return r.scanRun(row)
}

// GetByTenantAndID retrieves a run by tenant and ID.
func (r *ScanRunRepository) GetByTenantAndID(ctx context.Context, tenantID, id shared.ID) (*scanrun.Run, error) {
	query := r.selectQuery() + " WHERE tenant_id = $1 AND id = $2"
	row := r.db.QueryRowContext(ctx, query, tenantID.String(), id.String())
	return r.scanRun(row)
}

// List lists runs with filters and pagination.
func (r *ScanRunRepository) List(ctx context.Context, filter scanrun.RunFilter, page pagination.Pagination) (pagination.Result[*scanrun.Run], error) {
	var result pagination.Result[*scanrun.Run]

	baseQuery := r.selectQuery()
	countQuery := "SELECT COUNT(*) FROM scan_runs"
	whereClause, args := r.buildWhereClause(filter)

	if whereClause != "" {
		baseQuery += " WHERE " + whereClause
		countQuery += " WHERE " + whereClause
	}

	// Get total count
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total)
	if err != nil {
		return result, fmt.Errorf("failed to count pipeline runs: %w", err)
	}

	// Apply pagination
	offset := (page.Page - 1) * page.PerPage
	// OrderBy is a constant expression chosen from the domain whitelist.
	baseQuery += fmt.Sprintf(" ORDER BY %s LIMIT %d OFFSET %d", filter.Sort.OrderBy(), page.PerPage, offset)

	rows, err := r.db.QueryContext(ctx, baseQuery, args...)
	if err != nil {
		return result, fmt.Errorf("failed to list pipeline runs: %w", err)
	}
	defer rows.Close()

	var runs []*scanrun.Run
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

// Update updates a run.
func (r *ScanRunRepository) Update(ctx context.Context, run *scanrun.Run) error {
	context, err := json.Marshal(run.Context)
	if err != nil {
		return fmt.Errorf("failed to marshal context: %w", err)
	}

	var qualityGateResult []byte
	if run.QualityGateResult != nil {
		qualityGateResult, err = json.Marshal(run.QualityGateResult)
		if err != nil {
			return fmt.Errorf("failed to marshal quality_gate_result: %w", err)
		}
	}

	// A terminal run is final: the guard keeps a stale in-memory copy (a cancel
	// that read the run before it completed, a late write after the reaper
	// marked it timeout) from reopening it or overwriting its outcome.
	query := `
		UPDATE scan_runs
		SET status = $2, context = $3,
		    total_steps = $4, completed_steps = $5, failed_steps = $6, skipped_steps = $7, total_findings = $8,
		    started_at = $9, completed_at = $10, error_message = $11,
		    scan_profile_id = $12, quality_gate_result = $13, retry_attempt = $14,
		    deadline_at = COALESCE(deadline_at, ` + runDeadlineSQL("$9::timestamptz", "scan_runs.scan_id") + `)
		WHERE id = $1
		  AND status NOT IN ` + terminalRunStatusesSQL + `
	`

	result, err := r.db.ExecContext(ctx, query,
		run.ID.String(),
		string(run.Status),
		context,
		run.TotalSteps,
		run.CompletedSteps,
		run.FailedSteps,
		run.SkippedSteps,
		run.TotalFindings,
		nullTime(run.StartedAt),
		nullTime(run.CompletedAt),
		run.ErrorMessage,
		nullID(run.ScanProfileID),
		nullBytes(qualityGateResult),
		run.RetryAttempt,
	)

	if err != nil {
		return fmt.Errorf("failed to update pipeline run: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return r.notUpdatedError(ctx, run.ID)
	}

	return nil
}

// terminalRunStatusesSQL lists the statuses a run never leaves.
const terminalRunStatusesSQL = `('completed', 'partial', 'failed', 'canceled', 'timeout', 'blocked')`

// notUpdatedError explains a guarded UPDATE that touched no row: the run is
// missing, or it already finished.
func (r *ScanRunRepository) notUpdatedError(ctx context.Context, id shared.ID) error {
	var exists bool
	if err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM scan_runs WHERE id = $1)`, id.String()).Scan(&exists); err != nil {
		return fmt.Errorf("failed to check pipeline run: %w", err)
	}
	if !exists {
		return shared.ErrNotFound
	}
	return scanrun.ErrRunAlreadyFinished
}

// Delete deletes a run.
func (r *ScanRunRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM scan_runs WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete pipeline run: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// GetWithStepRuns retrieves a run with its step runs.
func (r *ScanRunRepository) GetWithStepRuns(ctx context.Context, id shared.ID) (*scanrun.Run, error) {
	run, err := r.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	stepRunRepo := NewStepRunRepository(r.db)
	stepRuns, err := stepRunRepo.GetByScanRunID(ctx, id)
	if err != nil {
		return nil, err
	}

	run.StepRuns = stepRuns
	return run, nil
}

// GetActiveByScanWorkflowID retrieves active runs for a scan workflow.
func (r *ScanRunRepository) GetActiveByScanWorkflowID(ctx context.Context, scanWorkflowID shared.ID) ([]*scanrun.Run, error) {
	query := r.selectQuery() + " WHERE scan_workflow_id = $1 AND status IN ('pending', 'running')"
	rows, err := r.db.QueryContext(ctx, query, scanWorkflowID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get active runs: %w", err)
	}
	defer rows.Close()

	var runs []*scanrun.Run
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

// GetActiveByAssetID retrieves active runs for an asset.
func (r *ScanRunRepository) GetActiveByAssetID(ctx context.Context, assetID shared.ID) ([]*scanrun.Run, error) {
	query := r.selectQuery() + " WHERE asset_id = $1 AND status IN ('pending', 'running')"
	rows, err := r.db.QueryContext(ctx, query, assetID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get active runs: %w", err)
	}
	defer rows.Close()

	var runs []*scanrun.Run
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

// CountActiveByScanWorkflowID counts active runs (pending/running) for a scan workflow.
func (r *ScanRunRepository) CountActiveByScanWorkflowID(ctx context.Context, scanWorkflowID shared.ID) (int, error) {
	query := `SELECT COUNT(*) FROM scan_runs WHERE scan_workflow_id = $1 AND status IN ('pending', 'running')`
	var count int
	err := r.db.QueryRowContext(ctx, query, scanWorkflowID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active runs by pipeline: %w", err)
	}
	return count, nil
}

// CountActiveByTenantID counts active runs (pending/running) for a tenant.
func (r *ScanRunRepository) CountActiveByTenantID(ctx context.Context, tenantID shared.ID) (int, error) {
	query := `SELECT COUNT(*) FROM scan_runs WHERE tenant_id = $1 AND status IN ('pending', 'running')`
	var count int
	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active runs by tenant: %w", err)
	}
	return count, nil
}

// CountActiveByScanID counts active runs (pending/running) for a scan config.
func (r *ScanRunRepository) CountActiveByScanID(ctx context.Context, scanID shared.ID) (int, error) {
	query := `SELECT COUNT(*) FROM scan_runs WHERE scan_id = $1 AND status IN ('pending', 'running')`
	var count int
	err := r.db.QueryRowContext(ctx, query, scanID.String()).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count active runs by scan: %w", err)
	}
	return count, nil
}

// UpdateStats updates run statistics.
func (r *ScanRunRepository) UpdateStats(ctx context.Context, id shared.ID, completed, failed, skipped, findings int) error {
	query := `
		UPDATE scan_runs
		SET completed_steps = $2, failed_steps = $3, skipped_steps = $4, total_findings = $5
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id.String(), completed, failed, skipped, findings)
	return err
}

// UpdateStatus updates run status. Only a run that has not finished moves:
// for a terminal run it returns scanrun.ErrRunAlreadyFinished and changes
// nothing, so exactly one caller wins the transition to a terminal state and
// only that caller records the outcome (on the scan, in metrics, in the audit
// log). Two parallel final steps, or a completion racing a cancel or the
// timeout reaper, otherwise each recorded the run once.
func (r *ScanRunRepository) UpdateStatus(ctx context.Context, id shared.ID, status scanrun.RunStatus, errorMessage string) error {
	query := `
		UPDATE scan_runs
		SET status = $2, error_message = $3,
		    completed_at = CASE WHEN $2::varchar IN ` + terminalRunStatusesSQL + ` THEN NOW() ELSE completed_at END
		WHERE id = $1
		  AND status NOT IN ` + terminalRunStatusesSQL + `
	`
	result, err := r.db.ExecContext(ctx, query, id.String(), string(status), errorMessage)
	if err != nil {
		return fmt.Errorf("failed to update pipeline run status: %w", err)
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return r.notUpdatedError(ctx, id)
	}
	return nil
}

// CreateRunIfUnderLimit atomically checks concurrent run limits and creates run if under limit.
// Uses a transaction with row-level locking to prevent race conditions.
func (r *ScanRunRepository) CreateRunIfUnderLimit(ctx context.Context, run *scanrun.Run, maxPerScan, maxPerTenant int) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Serialize concurrent triggers and count the active runs they compete
	// with: per scan config for a scan's run; per scan workflow for a run started
	// directly (POST /scan-workflows/runs, the trigger_pipeline action), which has
	// no scan. Dereferencing the nil scan id made every direct start panic.
	lockQuery := `SELECT id FROM scans WHERE id = $1 FOR UPDATE`
	countQuery := `
		SELECT COUNT(*) FROM scan_runs
		WHERE scan_id = $1 AND status IN ('pending', 'running')
	`
	lockID, limitMsg := "", "maximum concurrent runs (%d) reached for this scan config"
	if run.ScanID != nil {
		lockID = run.ScanID.String()
	} else {
		lockQuery = `SELECT id FROM scan_workflows WHERE id = $1 FOR UPDATE`
		countQuery = `
			SELECT COUNT(*) FROM scan_runs
			WHERE scan_workflow_id = $1 AND scan_id IS NULL AND status IN ('pending', 'running')
		`
		lockID, limitMsg = run.ScanWorkflowID.String(), "maximum concurrent runs (%d) reached for this pipeline"
	}
	if _, err := tx.ExecContext(ctx, lockQuery, lockID); err != nil {
		return fmt.Errorf("failed to lock run owner: %w", err)
	}

	// One run per schedule occurrence. Checked under the scan row lock so a
	// second trigger of the same slot gets this answer rather than a
	// concurrency-limit error; the unique index is the guarantee either way.
	if run.ScanID != nil && run.ScheduledFor != nil {
		var exists bool
		if err := tx.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM scan_runs WHERE scan_id = $1 AND scheduled_for = $2)`,
			run.ScanID.String(), *run.ScheduledFor).Scan(&exists); err != nil {
			return fmt.Errorf("failed to check the schedule occurrence: %w", err)
		}
		if exists {
			return scanrun.ErrOccurrenceAlreadyRun
		}
	}

	// Count active runs (no FOR UPDATE needed - we already hold the lock above)
	var ownerActiveCount int
	if err := tx.QueryRowContext(ctx, countQuery, lockID).Scan(&ownerActiveCount); err != nil {
		return fmt.Errorf("failed to count active runs: %w", err)
	}
	// Overlap policy skip (RFC-046 D4, §6.2): a scheduled run never starts
	// while the scan has an active run. Checked here, under the scan row
	// lock every trigger of the scan takes, so a manual trigger committed
	// between the scheduler's own check and this insert is seen.
	if run.ScanID != nil && run.ScheduledFor != nil && ownerActiveCount > 0 {
		return scanrun.ErrScanRunActive
	}
	if ownerActiveCount >= maxPerScan {
		return shared.NewDomainError(
			"MAX_CONCURRENT_RUNS",
			fmt.Sprintf(limitMsg, maxPerScan),
			shared.ErrValidation,
		)
	}

	// Count active runs for this tenant
	var tenantActiveCount int
	tenantCountQuery := `
		SELECT COUNT(*) FROM scan_runs
		WHERE tenant_id = $1 AND status IN ('pending', 'running')
	`
	if err := tx.QueryRowContext(ctx, tenantCountQuery, run.TenantID.String()).Scan(&tenantActiveCount); err != nil {
		return fmt.Errorf("failed to count active runs for tenant: %w", err)
	}
	if tenantActiveCount >= maxPerTenant {
		return shared.NewDomainError(
			"MAX_CONCURRENT_RUNS",
			fmt.Sprintf("maximum concurrent runs (%d) reached for this tenant", maxPerTenant),
			shared.ErrValidation,
		)
	}

	// Create the run within the same transaction
	context, err := json.Marshal(run.Context)
	if err != nil {
		return fmt.Errorf("failed to marshal context: %w", err)
	}

	var qualityGateResult []byte
	if run.QualityGateResult != nil {
		qualityGateResult, err = json.Marshal(run.QualityGateResult)
		if err != nil {
			return fmt.Errorf("failed to marshal quality_gate_result: %w", err)
		}
	}

	insertQuery := `
		INSERT INTO scan_runs (
			id, scan_workflow_id, tenant_id, asset_id, scan_id,
			trigger_type, triggered_by, status, context,
			total_steps, completed_steps, failed_steps, skipped_steps, total_findings,
			started_at, completed_at, error_message,
			scan_profile_id, quality_gate_result,
			retry_attempt,
			created_at, scheduled_for, deadline_at, freeze_override, refusal_code
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22,
		        ` + runDeadlineSQL("$15::timestamptz", "$5::uuid") + `, $23, NULLIF($24, ''))
	`

	_, err = tx.ExecContext(ctx, insertQuery,
		run.ID.String(),
		run.ScanWorkflowID.String(),
		run.TenantID.String(),
		nullID(run.AssetID),
		nullID(run.ScanID),
		string(run.TriggerType),
		run.TriggeredBy,
		string(run.Status),
		context,
		run.TotalSteps,
		run.CompletedSteps,
		run.FailedSteps,
		run.SkippedSteps,
		run.TotalFindings,
		nullTime(run.StartedAt),
		nullTime(run.CompletedAt),
		run.ErrorMessage,
		nullID(run.ScanProfileID),
		nullBytes(qualityGateResult),
		run.RetryAttempt,
		run.CreatedAt,
		nullTime(run.ScheduledFor),
		run.FreezeOverride,
		run.RefusalCode,
	)
	if isOccurrenceConflict(err) {
		return scanrun.ErrOccurrenceAlreadyRun
	}
	if err != nil {
		return fmt.Errorf("failed to create pipeline run: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// occurrenceIndex is the unique index that keeps one run per schedule
// occurrence of a scan (migration 000351).
const occurrenceIndex = "uq_scan_runs_scan_occurrence"

// isOccurrenceConflict reports whether err is a violation of occurrenceIndex.
func isOccurrenceConflict(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505" && pqErr.Constraint == occurrenceIndex
}

// AbsoluteRunTimeoutSeconds is the longest any scan run may stay
// non-terminal when its own scan cannot supply a timeout — 24 hours, which is
// deliberately the same ceiling chk_scans_timeout_seconds puts on a scan. No
// run outlives the longest timeout a scan is allowed to configure.
//
// It exists because the threshold used to come exclusively from a join against
// the run's scan, so a run with scan_id IS NULL was invisible to the reaper and
// stayed 'running' forever. That is not a hypothetical: fk_scan_runs_scan is
// ON DELETE SET NULL, so deleting a scan while its run is in flight nulls the
// link and orphans the run. Two were found stuck for 14 days that way.
const AbsoluteRunTimeoutSeconds = 24 * 60 * 60

// runDeadlineSQL is the deadline of a run that started at startedAt for the
// scan scanID: the scan timeout, or AbsoluteRunTimeoutSeconds when the run has
// no scan (or the scan none), capped at AbsoluteRunTimeoutSeconds. NULL while
// the run has not started. It is written once, when the run starts, so a scan
// edit never moves the deadline of a run already in flight (RFC-046 §6.3).
func runDeadlineSQL(startedAt, scanID string) string {
	return fmt.Sprintf(`CASE WHEN %[1]s IS NULL THEN NULL ELSE %[1]s + make_interval(secs => LEAST(
		COALESCE((SELECT NULLIF(s.timeout_seconds, 0) FROM scans s WHERE s.id = %[2]s), %[3]d), %[3]d)) END`,
		startedAt, scanID, AbsoluteRunTimeoutSeconds)
}

// MaxUnfinishedTargets bounds the unfinished targets a run records at its
// deadline: the per-run target cap, so a run never records more than it was
// allowed to dispatch.
const MaxUnfinishedTargets = 10000

// MarkTimedOutRuns settles every open run past its deadline (RFC-046 D5).
//
// The deadline is the run's deadline_at, or for runs started before migration
// 000674 the same formula computed now (runDeadlineSQL).
//
// A run that kept results ends 'partial': any of its commands completed, or
// any of its steps completed or ended partial. Otherwise it ends 'timeout' as
// before. Either way, in the same statement:
//   - the targets of its commands still open are recorded in
//     unfinished_targets, in dispatch order, deduplicated, at most
//     MaxUnfinishedTargets; the next scheduled run of the scan plans them
//     first (LatestRollover);
//   - those commands fail and lose their lease, so a sensor still running one
//     is told to stop on its next heartbeat (CommandsToCancel no longer finds
//     the command held), and no sensor picks a pending one up late;
//   - its open steps end 'partial' when one of their commands completed and
//     'timeout' otherwise;
//   - afterwards, each scan's run summary is recomputed from its runs.
//
// Returns the number of runs settled.
func (r *ScanRunRepository) MarkTimedOutRuns(ctx context.Context) (int64, error) {
	// The timeout message says only what is actually known: nothing reported
	// back. An earlier wording ('scan exceeded configured timeout') asserted a
	// cause, and was shown to users whose scanner had in fact failed
	// immediately with a specific error.
	query := `
		WITH due AS (
			SELECT pr.id, pr.tenant_id, pr.scan_id,
			       (EXISTS (SELECT 1 FROM commands c
			                WHERE c.tenant_id = pr.tenant_id
			                  AND c.payload->>'scan_run_id' = pr.id::text
			                  AND c.status = 'completed')
			        OR EXISTS (SELECT 1 FROM scan_run_steps sr
			                   WHERE sr.scan_run_id = pr.id
			                     AND sr.status IN ('completed', 'partial'))) AS kept
			FROM scan_runs pr
			WHERE pr.status IN ('pending', 'running')
			  AND pr.started_at IS NOT NULL
			  AND NOW() > COALESCE(pr.deadline_at, ` + runDeadlineSQL("pr.started_at", "pr.scan_id") + `)
			FOR UPDATE OF pr SKIP LOCKED
		), open_targets AS (
			SELECT d.id,
			       (SELECT jsonb_agg(u.target ORDER BY u.at, u.ord)
			        FROM (
			          SELECT tgt.target, MIN(c.created_at) AS at, MIN(tgt.ord) AS ord
			          FROM commands c
			          CROSS JOIN LATERAL jsonb_array_elements_text(
			              CASE WHEN jsonb_typeof(c.payload->'targets') = 'array' THEN c.payload->'targets'
			                   WHEN jsonb_typeof(c.payload->'target') = 'string' THEN jsonb_build_array(c.payload->'target')
			                   ELSE '[]'::jsonb END
			          ) WITH ORDINALITY AS tgt(target, ord)
			          WHERE c.tenant_id = d.tenant_id
			            AND c.payload->>'scan_run_id' = d.id::text
			            AND c.status IN ('pending', 'acknowledged', 'running')
			            AND tgt.target <> ''
			          GROUP BY tgt.target
			          ORDER BY MIN(c.created_at), MIN(tgt.ord), tgt.target
			          LIMIT $1
			        ) u) AS targets
			FROM due d
		), settled AS (
			UPDATE scan_runs pr
			SET status = CASE WHEN d.kept THEN 'partial' ELSE 'timeout' END,
			    completed_at = NOW(),
			    unfinished_targets = o.targets,
			    error_message = CASE
			        WHEN d.kept THEN 'deadline reached with '
			            || COALESCE(jsonb_array_length(o.targets), 0)::text
			            || ' target(s) unfinished; the results that came back are kept'
			        ELSE 'no result reported before timeout — the sensor may be offline, or never picked up the command'
			    END
			FROM due d
			JOIN open_targets o ON o.id = d.id
			WHERE pr.id = d.id
			  AND pr.status IN ('pending', 'running')
			RETURNING pr.id, pr.tenant_id, pr.scan_id, pr.status
		), closed_commands AS (
			UPDATE commands c
			SET status = 'failed',
			    error_message = 'scan run reached its deadline before this command reported a result',
			    completed_at = NOW(),
			    lease_expires_at = NULL
			FROM settled t
			WHERE c.tenant_id = t.tenant_id
			  AND c.payload->>'scan_run_id' = t.id::text
			  AND c.status IN ('pending', 'acknowledged', 'running')
			RETURNING c.id
		), closed_steps AS (
			UPDATE scan_run_steps sr
			SET status = CASE WHEN EXISTS (
			                 SELECT 1 FROM commands c
			                 WHERE c.tenant_id = t.tenant_id
			                   AND c.payload->>'scan_run_id' = t.id::text
			                   AND c.payload->>'scan_run_step_id' = sr.id::text
			                   AND c.status = 'completed')
			             THEN 'partial' ELSE 'timeout' END,
			    completed_at = NOW()
			FROM settled t
			WHERE sr.scan_run_id = t.id
			  AND sr.status IN ('pending', 'queued', 'running')
			RETURNING sr.id
		)
		SELECT
			(SELECT COUNT(*) FROM settled),
			(SELECT COUNT(*) FROM closed_commands),
			(SELECT COUNT(*) FROM closed_steps),
			COALESCE((SELECT array_agg(DISTINCT scan_id::text) FROM settled WHERE scan_id IS NOT NULL), '{}')
	`

	var (
		runs, commands, steps int64
		scanIDs               []string
	)
	if err := r.db.QueryRowContext(ctx, query, MaxUnfinishedTargets).Scan(&runs, &commands, &steps, pq.Array(&scanIDs)); err != nil {
		return 0, fmt.Errorf("failed to mark timed out runs: %w", err)
	}
	// The scans' summaries are recomputed after the statement: a summary
	// computed inside it would still see the runs as open (one snapshot).
	if err := refreshScanRunSummariesByID(ctx, r.db, scanIDs); err != nil {
		return runs, fmt.Errorf("runs timed out, scan summaries not refreshed: %w", err)
	}
	return runs, nil
}

// GetUnfinishedTargets returns the targets runID recorded as unfinished at its
// deadline (nil when it recorded none). A run of another tenant is
// shared.ErrNotFound.
func (r *ScanRunRepository) GetUnfinishedTargets(ctx context.Context, tenantID, runID shared.ID) ([]string, error) {
	var raw []byte
	err := r.db.QueryRowContext(ctx,
		`SELECT unfinished_targets FROM scan_runs WHERE tenant_id = $1 AND id = $2`,
		tenantID.String(), runID.String()).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read unfinished targets: %w", err)
	}
	return decodeTargets(raw)
}

// LatestRollover returns what the scan's most recent settled run left
// unfinished, when that run was a scheduled run that ended partial. Only the
// latest settled run counts: once a later run settled, the earlier leftovers
// were either planned by it or are covered by its own record.
func (r *ScanRunRepository) LatestRollover(ctx context.Context, tenantID, scanID shared.ID) (*scanrun.Rollover, error) {
	var (
		id          string
		status      string
		triggerType string
		raw         []byte
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT id, status, trigger_type, unfinished_targets
		FROM scan_runs
		WHERE tenant_id = $1 AND scan_id = $2
		  AND status IN `+terminalRunStatusesSQL+`
		ORDER BY completed_at DESC NULLS LAST, created_at DESC
		LIMIT 1`,
		tenantID.String(), scanID.String()).Scan(&id, &status, &triggerType, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read the latest settled run: %w", err)
	}
	if status != string(scanrun.RunStatusPartial) || triggerType != string(scanworkflow.TriggerTypeSchedule) {
		return nil, nil
	}
	targets, err := decodeTargets(raw)
	if err != nil || len(targets) == 0 {
		return nil, err
	}
	runID, err := shared.IDFromString(id)
	if err != nil {
		return nil, fmt.Errorf("invalid run id %q: %w", id, err)
	}
	return &scanrun.Rollover{FromRunID: runID, Targets: targets}, nil
}

func decodeTargets(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var targets []string
	if err := json.Unmarshal(raw, &targets); err != nil {
		return nil, fmt.Errorf("failed to decode unfinished targets: %w", err)
	}
	return targets, nil
}

var _ scanrun.CanceledRunCloser = (*ScanRunRepository)(nil)

// CloseCanceledRun ends the open step runs and commands of a canceled run as
// canceled (RFC-046 §8). It acts only on a run of tenantID whose status is
// canceled, so it can be repeated (a second cancel, a retry after a partial
// failure) and never touches a run that is still open or finished otherwise.
//
// A command belongs to the run through the scan_run_id in its payload
// (scan dispatcher) or through its step run (scan workflow dispatcher). Its lease
// is cleared: the expired-lease sweep only re-queues acknowledged or running
// commands, and the sensor still running one finds it in cancel_command_ids
// on its next heartbeat because it no longer holds it.
func (r *ScanRunRepository) CloseCanceledRun(ctx context.Context, tenantID, runID shared.ID) (scanrun.CanceledRunClosure, error) {
	query := `
		WITH run AS (
			SELECT id, tenant_id FROM scan_runs
			WHERE tenant_id = $1 AND id = $2 AND status = 'canceled'
		), closed_steps AS (
			UPDATE scan_run_steps sr
			SET status = 'canceled', completed_at = NOW()
			FROM run
			WHERE sr.scan_run_id = run.id
			  AND sr.status IN ('pending', 'queued', 'running')
			RETURNING sr.id
		), closed_commands AS (
			UPDATE commands c
			SET status = 'canceled',
			    completed_at = NOW(),
			    lease_expires_at = NULL,
			    error_message = 'scan run canceled'
			FROM run
			WHERE c.tenant_id = run.tenant_id
			  AND c.status IN ('pending', 'acknowledged', 'running')
			  AND (c.payload->>'scan_run_id' = run.id::text
			       OR c.scan_run_step_id IN (SELECT sr.id FROM scan_run_steps sr WHERE sr.scan_run_id = run.id))
			RETURNING c.id, c.sensor_id
		)
		SELECT (SELECT COUNT(*) FROM closed_steps),
		       (SELECT COUNT(*) FROM closed_commands),
		       COALESCE((SELECT array_agg(DISTINCT sensor_id::text) FROM closed_commands WHERE sensor_id IS NOT NULL), '{}')
	`
	var (
		out     scanrun.CanceledRunClosure
		sensors []string
	)
	if err := r.db.QueryRowContext(ctx, query, tenantID.String(), runID.String()).
		Scan(&out.Steps, &out.Commands, pq.Array(&sensors)); err != nil {
		return scanrun.CanceledRunClosure{}, fmt.Errorf("failed to close canceled run: %w", err)
	}
	for _, s := range sensors {
		if id, err := shared.IDFromString(s); err == nil {
			out.Sensors = append(out.Sensors, id)
		}
	}
	return out, nil
}

// AbortUnclaimedRuns ends runs no sensor ever picked up (D8): every command of
// the run is still 'pending' and was never acknowledged or started, and the
// run is older than its threshold (4h scheduled / 1h interactive by default,
// or the scan's own timeout when shorter). Such a run used to wait for the
// generic run timeout and end as "timeout" with no hint that nobody claimed
// the work; it was then even retried. Here the run fails with the reason, its
// open steps fail with NO_SENSOR (a code the retry controller never retries),
// its commands are failed so no sensor picks them up late, and the scan
// summary is recomputed from its runs.
func (r *ScanRunRepository) AbortUnclaimedRuns(ctx context.Context, scheduledAfter, interactiveAfter time.Duration) (int64, error) {
	const query = `
		WITH candidates AS (
			SELECT pr.id,
			       LEAST(
			         CASE WHEN pr.trigger_type = 'schedule' THEN $1::bigint ELSE $2::bigint END,
			         COALESCE((SELECT NULLIF(s.timeout_seconds, 0) FROM scans s WHERE s.id = pr.scan_id), $3::bigint)
			       ) AS after_seconds
			FROM scan_runs pr
			WHERE pr.status IN ('pending', 'running')
			  AND pr.started_at IS NOT NULL
			  AND EXISTS (
			        SELECT 1 FROM commands c
			        WHERE c.tenant_id = pr.tenant_id AND c.payload->>'scan_run_id' = pr.id::text)
			  AND NOT EXISTS (
			        SELECT 1 FROM commands c
			        WHERE c.tenant_id = pr.tenant_id AND c.payload->>'scan_run_id' = pr.id::text
			          AND (c.status <> 'pending' OR c.acknowledged_at IS NOT NULL OR c.started_at IS NOT NULL
			               -- a lease-lost requeue clears the timestamps but not the attempts
			               OR c.dispatch_attempts > 0))
		), unclaimed AS (
			UPDATE scan_runs pr
			SET status = 'failed',
			    completed_at = NOW(),
			    error_message = 'no sensor picked up this run''s work within '
			        || CASE WHEN k.after_seconds % 3600 = 0 THEN (k.after_seconds / 3600)::text || 'h'
			                ELSE (k.after_seconds / 60)::text || 'm' END
			        || ' — check that a sensor with this scanner is online (and in the right zone)'
			FROM candidates k
			WHERE pr.id = k.id
			  AND pr.status IN ('pending', 'running')
			  AND EXTRACT(EPOCH FROM (NOW() - pr.started_at)) > k.after_seconds
			RETURNING pr.id, pr.tenant_id, pr.scan_id, pr.error_message
		), closed_commands AS (
			UPDATE commands c
			SET status = 'failed', error_message = u.error_message, completed_at = NOW()
			FROM unclaimed u
			WHERE c.tenant_id = u.tenant_id
			  AND c.payload->>'scan_run_id' = u.id::text
			  AND c.status = 'pending'
			RETURNING c.id
		), closed_steps AS (
			UPDATE scan_run_steps sr
			SET status = 'failed', error_code = 'NO_SENSOR', error_message = u.error_message, completed_at = NOW()
			FROM unclaimed u
			WHERE sr.scan_run_id = u.id
			  AND sr.status IN ('pending', 'queued', 'running')
			RETURNING sr.id
		)
		SELECT (SELECT COUNT(*) FROM unclaimed), (SELECT COUNT(*) FROM closed_commands),
		       (SELECT COUNT(*) FROM closed_steps),
		       COALESCE((SELECT array_agg(DISTINCT scan_id::text) FROM unclaimed WHERE scan_id IS NOT NULL), '{}')
	`
	var (
		runs, commands, steps int64
		scanIDs               []string
	)
	if err := r.db.QueryRowContext(ctx, query,
		int64(scheduledAfter.Seconds()), int64(interactiveAfter.Seconds()), AbsoluteRunTimeoutSeconds,
	).Scan(&runs, &commands, &steps, pq.Array(&scanIDs)); err != nil {
		return 0, fmt.Errorf("failed to abort unclaimed runs: %w", err)
	}
	if err := refreshScanRunSummariesByID(ctx, r.db, scanIDs); err != nil {
		return runs, fmt.Errorf("unclaimed runs aborted, scan summaries not refreshed: %w", err)
	}
	return runs, nil
}

// ListPendingRetries atomically claims failed scan_runs eligible for automatic retry.
//
// The query finds failed runs whose:
//   - parent scan is active and has max_retries > 0
//   - retry_attempt < scan.max_retries (still has retry budget)
//   - retry_dispatched_at IS NULL (not already claimed by another controller)
//   - exponential backoff window has elapsed (retry_backoff * 2^retry_attempt seconds)
//
// It uses FOR UPDATE SKIP LOCKED + atomic UPDATE to set retry_dispatched_at = NOW(),
// ensuring each failed run is claimed at most once even with concurrent controllers
// or repeated polling cycles. On the SUCCESS path the claim marker stays set
// forever, since the retry creates a NEW pipeline_run that becomes the new
// "latest". If dispatch fails without creating a new run, the caller MUST call
// ResetRetryClaim to release the claim so this run becomes eligible again next
// tick — otherwise a single transient failure permanently stalls auto-retry.
func (r *ScanRunRepository) ListPendingRetries(ctx context.Context, limit int) ([]scanrun.RetryCandidate, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `
		WITH eligible AS (
			SELECT pr.id, pr.scan_id, pr.tenant_id, pr.retry_attempt,
			       s.max_retries, s.retry_backoff_seconds
			FROM scan_runs pr
			JOIN scans s ON s.id = pr.scan_id
			WHERE pr.status IN ('failed', 'timeout')
			  AND pr.retry_dispatched_at IS NULL
			  AND pr.completed_at IS NOT NULL
			  AND s.max_retries > 0
			  -- A timeout (the sensor died, or never reported) is retried at
			  -- most twice; other failures use the scan's own budget (D7).
			  AND pr.retry_attempt < CASE WHEN pr.status = 'timeout' THEN LEAST(s.max_retries, 2) ELSE s.max_retries END
			  -- A failure a retry cannot fix is never retried: no such scanner on
			  -- the sensor, target refused, nothing to scan, no sensor (D7).
			  AND NOT EXISTS (
			        SELECT 1 FROM scan_run_steps sr
			        WHERE sr.scan_run_id = pr.id
			          AND sr.status = 'failed'
			          AND sr.error_code = ANY($2::text[])
			      )
			  AND s.status = 'active'
			  AND NOW() >= pr.completed_at + (s.retry_backoff_seconds * POWER(2, pr.retry_attempt) || ' seconds')::interval
			ORDER BY pr.completed_at ASC
			LIMIT $1
			FOR UPDATE OF pr SKIP LOCKED
		),
		claimed AS (
			UPDATE scan_runs pr
			SET retry_dispatched_at = NOW()
			FROM eligible e
			WHERE pr.id = e.id
			RETURNING e.id, e.scan_id, e.tenant_id, e.retry_attempt, e.max_retries, e.retry_backoff_seconds
		)
		SELECT id, scan_id, tenant_id, retry_attempt, max_retries, retry_backoff_seconds
		FROM claimed
	`

	rows, err := r.db.QueryContext(ctx, query, limit, pq.Array(scanrun.PermanentFailureCodes))
	if err != nil {
		return nil, fmt.Errorf("failed to list pending retries: %w", err)
	}
	defer rows.Close()

	var candidates []scanrun.RetryCandidate
	for rows.Next() {
		var (
			runIDStr, scanIDStr, tenantIDStr string
			retryAttempt                     int
			maxRetries                       int
			backoff                          int
		)
		if err := rows.Scan(&runIDStr, &scanIDStr, &tenantIDStr, &retryAttempt, &maxRetries, &backoff); err != nil {
			return nil, fmt.Errorf("failed to scan retry candidate: %w", err)
		}
		runID, _ := shared.IDFromString(runIDStr)
		scanID, _ := shared.IDFromString(scanIDStr)
		tenantID, _ := shared.IDFromString(tenantIDStr)
		candidates = append(candidates, scanrun.RetryCandidate{
			RunID:               runID,
			ScanID:              scanID,
			TenantID:            tenantID,
			RetryAttempt:        retryAttempt,
			MaxRetries:          maxRetries,
			RetryBackoffSeconds: backoff,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate retry candidates: %w", err)
	}
	return candidates, nil
}

// ReleaseFailedRetryDispatch is the compensating action for a retry that was
// claimed by ListPendingRetries but whose dispatch failed without creating a
// new run (for example no sensor online at that moment). The claim is released
// so the run is retried again after the next backoff, and the attempt counts
// against the budget: retry_attempt moves up, which also doubles the backoff.
// Releasing without spending the attempt (the old behavior) retried a dispatch
// that kept failing every backoff interval, forever.
func (r *ScanRunRepository) ReleaseFailedRetryDispatch(ctx context.Context, runID shared.ID) error {
	const query = `UPDATE scan_runs SET retry_dispatched_at = NULL, retry_attempt = retry_attempt + 1 WHERE id = $1`
	if _, err := r.db.ExecContext(ctx, query, runID.String()); err != nil {
		return fmt.Errorf("failed to release retry claim: %w", err)
	}
	return nil
}

// ListByScanID lists runs for a specific scan with pagination.
func (r *ScanRunRepository) ListByScanID(ctx context.Context, scanID shared.ID, page, perPage int) ([]*scanrun.Run, int64, error) {
	// Get total count
	countQuery := "SELECT COUNT(*) FROM scan_runs WHERE scan_id = $1"
	var total int64
	err := r.db.QueryRowContext(ctx, countQuery, scanID.String()).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count runs: %w", err)
	}

	// Get runs
	offset := (page - 1) * perPage
	if offset < 0 {
		offset = 0
	}
	query := r.selectQuery() + fmt.Sprintf(" WHERE scan_id = $1 ORDER BY created_at DESC LIMIT %d OFFSET %d", perPage, offset)

	rows, err := r.db.QueryContext(ctx, query, scanID.String())
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list runs: %w", err)
	}
	defer rows.Close()

	var runs []*scanrun.Run
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

func (r *ScanRunRepository) selectQuery() string {
	return `
		SELECT id, scan_workflow_id, tenant_id, asset_id, scan_id,
		       trigger_type, triggered_by, status, context,
		       total_steps, completed_steps, failed_steps, skipped_steps, total_findings,
		       started_at, completed_at, error_message,
		       scan_profile_id, quality_gate_result, retry_attempt,
		       created_at, scheduled_for,
		       deadline_at, COALESCE(jsonb_array_length(unfinished_targets), 0), freeze_override,
		       COALESCE(refusal_code, '')
		FROM scan_runs
	`
}

var _ scanrun.RunScanNamer = (*ScanRunRepository)(nil)

// ScanNames returns the names of the scans in scanIDs that belong to
// tenantID, in one query. A scan of another tenant, or a deleted one, is
// simply absent from the map.
func (r *ScanRunRepository) ScanNames(ctx context.Context, tenantID shared.ID, scanIDs []shared.ID) (map[shared.ID]string, error) {
	out := make(map[shared.ID]string, len(scanIDs))
	if len(scanIDs) == 0 {
		return out, nil
	}
	ids := make([]string, len(scanIDs))
	for i, id := range scanIDs {
		ids[i] = id.String()
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT id, name FROM scans WHERE tenant_id = $1 AND id = ANY($2::uuid[])`,
		tenantID.String(), pq.Array(ids))
	if err != nil {
		return nil, fmt.Errorf("failed to name run scans: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, fmt.Errorf("failed to scan run scan name: %w", err)
		}
		if sid, err := shared.IDFromString(id); err == nil {
			out[sid] = name
		}
	}
	return out, rows.Err()
}

func (r *ScanRunRepository) buildWhereClause(filter scanrun.RunFilter) (string, []any) {
	var conditions []string
	var args []any

	if filter.TenantID != nil {
		args = append(args, filter.TenantID.String())
		conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", len(args)))
	}

	if filter.ScanWorkflowID != nil {
		args = append(args, filter.ScanWorkflowID.String())
		conditions = append(conditions, fmt.Sprintf("scan_workflow_id = $%d", len(args)))
	}

	if filter.AssetID != nil {
		args = append(args, filter.AssetID.String())
		conditions = append(conditions, fmt.Sprintf("asset_id = $%d", len(args)))
	}

	if filter.Status != nil {
		args = append(args, string(*filter.Status))
		conditions = append(conditions, fmt.Sprintf("status = $%d", len(args)))
	}

	if filter.TriggerType != nil {
		args = append(args, string(*filter.TriggerType))
		conditions = append(conditions, fmt.Sprintf("trigger_type = $%d", len(args)))
	}

	if len(conditions) == 0 {
		return "", nil
	}

	return strings.Join(conditions, " AND "), args
}

func (r *ScanRunRepository) scanRun(row *sql.Row) (*scanrun.Run, error) {
	run := &scanrun.Run{}
	var (
		id                string
		scanWorkflowID    string
		tenantID          string
		assetID           sql.NullString
		scanID            sql.NullString
		triggerType       string
		status            string
		context           []byte
		startedAt         sql.NullTime
		completedAt       sql.NullTime
		scanProfileID     sql.NullString
		qualityGateResult []byte
		retryAttempt      sql.NullInt64
		scheduledFor      sql.NullTime
		deadlineAt        sql.NullTime
	)

	var triggeredBy, errorMessage sql.NullString
	err := row.Scan(
		&id,
		&scanWorkflowID,
		&tenantID,
		&assetID,
		&scanID,
		&triggerType,
		&triggeredBy,
		&status,
		&context,
		&run.TotalSteps,
		&run.CompletedSteps,
		&run.FailedSteps,
		&run.SkippedSteps,
		&run.TotalFindings,
		&startedAt,
		&completedAt,
		&errorMessage,
		&scanProfileID,
		&qualityGateResult,
		&retryAttempt,
		&run.CreatedAt,
		&scheduledFor,
		&deadlineAt,
		&run.UnfinishedTargetCount,
		&run.FreezeOverride,
		&run.RefusalCode,
	)
	_ = retryAttempt // populated below

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, shared.ErrNotFound
		}
		return nil, fmt.Errorf("failed to scan pipeline run: %w", err)
	}

	run.ID, _ = shared.IDFromString(id)
	run.ScanWorkflowID, _ = shared.IDFromString(scanWorkflowID)
	run.TenantID, _ = shared.IDFromString(tenantID)
	run.TriggerType = scanworkflow.TriggerType(triggerType)
	run.Status = scanrun.RunStatus(status)
	run.TriggeredBy = triggeredBy.String
	run.ErrorMessage = errorMessage.String

	if assetID.Valid {
		aid, _ := shared.IDFromString(assetID.String)
		run.AssetID = &aid
	}

	if scanID.Valid {
		sid, _ := shared.IDFromString(scanID.String)
		run.ScanID = &sid
	}

	if scanProfileID.Valid {
		spid, _ := shared.IDFromString(scanProfileID.String)
		run.ScanProfileID = &spid
	}

	if startedAt.Valid {
		run.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		run.CompletedAt = &completedAt.Time
	}

	if len(context) > 0 {
		_ = json.Unmarshal(context, &run.Context)
	}

	if len(qualityGateResult) > 0 {
		var qgr scanprofile.QualityGateResult
		if err := json.Unmarshal(qualityGateResult, &qgr); err == nil {
			run.QualityGateResult = &qgr
		}
	}

	if retryAttempt.Valid {
		run.RetryAttempt = int(retryAttempt.Int64)
	}
	if scheduledFor.Valid {
		t := scheduledFor.Time
		run.ScheduledFor = &t
	}
	if deadlineAt.Valid {
		t := deadlineAt.Time
		run.DeadlineAt = &t
	}

	return run, nil
}

func (r *ScanRunRepository) scanRunFromRows(rows *sql.Rows) (*scanrun.Run, error) {
	run := &scanrun.Run{}
	var (
		id                string
		scanWorkflowID    string
		tenantID          string
		assetID           sql.NullString
		scanID            sql.NullString
		triggerType       string
		status            string
		context           []byte
		startedAt         sql.NullTime
		completedAt       sql.NullTime
		scanProfileID     sql.NullString
		qualityGateResult []byte
		retryAttempt      sql.NullInt64
		scheduledFor      sql.NullTime
		deadlineAt        sql.NullTime
	)

	var triggeredBy, errorMessage sql.NullString
	err := rows.Scan(
		&id,
		&scanWorkflowID,
		&tenantID,
		&assetID,
		&scanID,
		&triggerType,
		&triggeredBy,
		&status,
		&context,
		&run.TotalSteps,
		&run.CompletedSteps,
		&run.FailedSteps,
		&run.SkippedSteps,
		&run.TotalFindings,
		&startedAt,
		&completedAt,
		&errorMessage,
		&scanProfileID,
		&qualityGateResult,
		&retryAttempt,
		&run.CreatedAt,
		&scheduledFor,
		&deadlineAt,
		&run.UnfinishedTargetCount,
		&run.FreezeOverride,
		&run.RefusalCode,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan pipeline run: %w", err)
	}

	run.ID, _ = shared.IDFromString(id)
	run.ScanWorkflowID, _ = shared.IDFromString(scanWorkflowID)
	run.TenantID, _ = shared.IDFromString(tenantID)
	run.TriggerType = scanworkflow.TriggerType(triggerType)
	run.Status = scanrun.RunStatus(status)
	run.TriggeredBy = triggeredBy.String
	run.ErrorMessage = errorMessage.String

	if assetID.Valid {
		aid, _ := shared.IDFromString(assetID.String)
		run.AssetID = &aid
	}

	if scanID.Valid {
		sid, _ := shared.IDFromString(scanID.String)
		run.ScanID = &sid
	}

	if scanProfileID.Valid {
		spid, _ := shared.IDFromString(scanProfileID.String)
		run.ScanProfileID = &spid
	}

	if startedAt.Valid {
		run.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		run.CompletedAt = &completedAt.Time
	}

	if len(context) > 0 {
		_ = json.Unmarshal(context, &run.Context)
	}

	if len(qualityGateResult) > 0 {
		var qgr scanprofile.QualityGateResult
		if err := json.Unmarshal(qualityGateResult, &qgr); err == nil {
			run.QualityGateResult = &qgr
		}
	}

	if retryAttempt.Valid {
		run.RetryAttempt = int(retryAttempt.Int64)
	}
	if scheduledFor.Valid {
		t := scheduledFor.Time
		run.ScheduledFor = &t
	}
	if deadlineAt.Valid {
		t := deadlineAt.Time
		run.DeadlineAt = &t
	}

	return run, nil
}

// GetStatsByTenant returns aggregated run statistics for a tenant in a single query.
// This is optimized to avoid N+1 queries when fetching stats.
func (r *ScanRunRepository) GetStatsByTenant(ctx context.Context, tenantID shared.ID) (scanrun.RunStats, error) {
	var stats scanrun.RunStats

	// Single aggregation query - much more efficient than N queries
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE status = 'pending') as pending,
			COUNT(*) FILTER (WHERE status = 'running') as running,
			COUNT(*) FILTER (WHERE status = 'completed') as completed,
			COUNT(*) FILTER (WHERE status = 'partial') as partial,
			COUNT(*) FILTER (WHERE status = 'failed' OR status = 'timeout') as failed,
			COUNT(*) FILTER (WHERE status = 'canceled') as canceled
		FROM scan_runs
		WHERE tenant_id = $1
	`

	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(
		&stats.Total,
		&stats.Pending,
		&stats.Running,
		&stats.Completed,
		&stats.Partial,
		&stats.Failed,
		&stats.Canceled,
	)
	if err != nil {
		return stats, fmt.Errorf("failed to get pipeline run stats: %w", err)
	}

	return stats, nil
}

// StepRunRepository implements scanrun.StepRunRepository using PostgreSQL.
type StepRunRepository struct {
	db *DB
}

// NewStepRunRepository creates a new StepRunRepository.
func NewStepRunRepository(db *DB) *StepRunRepository {
	return &StepRunRepository{db: db}
}

// Create persists a new step run.
func (r *StepRunRepository) Create(ctx context.Context, sr *scanrun.StepRun) error {
	output, err := json.Marshal(sr.Output)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	query := `
		INSERT INTO scan_run_steps (
			id, scan_run_id, step_id, step_key, step_order, status,
			sensor_id, command_id, condition_evaluated, condition_result, skip_reason,
			findings_count, output, attempt, max_attempts,
			queued_at, started_at, completed_at, error_message, error_code, created_at,
			step_name, tool, capability
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
	`

	_, err = r.db.ExecContext(ctx, query,
		sr.ID.String(),
		sr.ScanRunID.String(),
		stepRunStepID(sr.StepID),
		sr.StepKey,
		sr.StepOrder,
		string(sr.Status),
		nullID(sr.SensorID),
		nullID(sr.CommandID),
		sr.ConditionEvaluated,
		sr.ConditionResult,
		sr.SkipReason,
		sr.FindingsCount,
		output,
		sr.Attempt,
		sr.MaxAttempts,
		nullTime(sr.QueuedAt),
		nullTime(sr.StartedAt),
		nullTime(sr.CompletedAt),
		sr.ErrorMessage,
		sr.ErrorCode,
		sr.CreatedAt,
		nullString(sr.StepName),
		nullString(sr.Tool),
		nullString(sr.Capability),
	)

	if err != nil {
		return fmt.Errorf("failed to create step run: %w", err)
	}

	return nil
}

// stepRunBatchChunkSize caps rows per multi-row INSERT to stay well under
// PostgreSQL's 65535 bind-parameter limit (24 columns × 100 = 2400 params).
const stepRunBatchChunkSize = 100

// CreateBatch creates multiple step runs in a single multi-row INSERT per chunk.
// This is atomic per chunk (a statement either inserts every row or none) and
// avoids the one-round-trip-per-row cost of looping single-row Create calls.
func (r *StepRunRepository) CreateBatch(ctx context.Context, stepRuns []*scanrun.StepRun) error {
	if len(stepRuns) == 0 {
		return nil
	}

	for chunkStart := 0; chunkStart < len(stepRuns); chunkStart += stepRunBatchChunkSize {
		chunkEnd := chunkStart + stepRunBatchChunkSize
		if chunkEnd > len(stepRuns) {
			chunkEnd = len(stepRuns)
		}
		if err := r.insertStepRunChunk(ctx, stepRuns[chunkStart:chunkEnd]); err != nil {
			return err
		}
	}

	return nil
}

// insertStepRunChunk performs a single multi-row INSERT for a chunk of step runs.
func (r *StepRunRepository) insertStepRunChunk(ctx context.Context, stepRuns []*scanrun.StepRun) error {
	const cols = 24 // number of columns per row — must match the VALUES list below
	valueStrings := make([]string, 0, len(stepRuns))
	valueArgs := make([]interface{}, 0, len(stepRuns)*cols)

	for i, sr := range stepRuns {
		output, err := json.Marshal(sr.Output)
		if err != nil {
			return fmt.Errorf("failed to marshal output for step run %d: %w", i, err)
		}

		offset := i * cols
		placeholders := make([]string, cols)
		for j := range cols {
			placeholders[j] = fmt.Sprintf("$%d", offset+j+1)
		}
		valueStrings = append(valueStrings, "("+strings.Join(placeholders, ", ")+")")
		valueArgs = append(valueArgs,
			sr.ID.String(),
			sr.ScanRunID.String(),
			stepRunStepID(sr.StepID),
			sr.StepKey,
			sr.StepOrder,
			string(sr.Status),
			nullID(sr.SensorID),
			nullID(sr.CommandID),
			sr.ConditionEvaluated,
			sr.ConditionResult,
			sr.SkipReason,
			sr.FindingsCount,
			output,
			sr.Attempt,
			sr.MaxAttempts,
			nullTime(sr.QueuedAt),
			nullTime(sr.StartedAt),
			nullTime(sr.CompletedAt),
			sr.ErrorMessage,
			sr.ErrorCode,
			sr.CreatedAt,
			nullString(sr.StepName),
			nullString(sr.Tool),
			nullString(sr.Capability),
		)
	}

	query := fmt.Sprintf(`
		INSERT INTO scan_run_steps (
			id, scan_run_id, step_id, step_key, step_order, status,
			sensor_id, command_id, condition_evaluated, condition_result, skip_reason,
			findings_count, output, attempt, max_attempts,
			queued_at, started_at, completed_at, error_message, error_code, created_at,
			step_name, tool, capability
		)
		VALUES %s
	`, strings.Join(valueStrings, ", "))

	if _, err := r.db.ExecContext(ctx, query, valueArgs...); err != nil {
		return fmt.Errorf("failed to batch create step runs: %w", err)
	}

	return nil
}

// GetByID retrieves a step run by ID.
func (r *StepRunRepository) GetByID(ctx context.Context, id shared.ID) (*scanrun.StepRun, error) {
	query := r.selectQuery() + " WHERE id = $1"
	rows, err := r.db.QueryContext(ctx, query, id.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get step run: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, shared.ErrNotFound
	}

	return r.scanStepRun(rows)
}

// GetByScanRunID retrieves all step runs for a scan run.
func (r *StepRunRepository) GetByScanRunID(ctx context.Context, scanRunID shared.ID) ([]*scanrun.StepRun, error) {
	query := r.selectQuery() + " WHERE scan_run_id = $1 ORDER BY step_order ASC"
	rows, err := r.db.QueryContext(ctx, query, scanRunID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get step runs: %w", err)
	}
	defer rows.Close()

	var stepRuns []*scanrun.StepRun
	for rows.Next() {
		sr, err := r.scanStepRun(rows)
		if err != nil {
			return nil, err
		}
		stepRuns = append(stepRuns, sr)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return stepRuns, nil
}

// GetByStepKey retrieves a step run by scan run ID and step key.
func (r *StepRunRepository) GetByStepKey(ctx context.Context, scanRunID shared.ID, stepKey string) (*scanrun.StepRun, error) {
	query := r.selectQuery() + " WHERE scan_run_id = $1 AND step_key = $2"
	rows, err := r.db.QueryContext(ctx, query, scanRunID.String(), stepKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get step run: %w", err)
	}
	defer rows.Close()

	if !rows.Next() {
		return nil, shared.ErrNotFound
	}

	return r.scanStepRun(rows)
}

// List lists step runs with filters.
func (r *StepRunRepository) List(ctx context.Context, filter scanrun.StepRunFilter) ([]*scanrun.StepRun, error) {
	query := r.selectQuery()
	var conditions []string
	var args []any

	if filter.ScanRunID != nil {
		args = append(args, filter.ScanRunID.String())
		conditions = append(conditions, fmt.Sprintf("scan_run_id = $%d", len(args)))
	}

	if filter.Status != nil {
		args = append(args, string(*filter.Status))
		conditions = append(conditions, fmt.Sprintf("status = $%d", len(args)))
	}

	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}

	query += " ORDER BY step_order ASC"

	rows, err := r.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list step runs: %w", err)
	}
	defer rows.Close()

	var stepRuns []*scanrun.StepRun
	for rows.Next() {
		sr, err := r.scanStepRun(rows)
		if err != nil {
			return nil, err
		}
		stepRuns = append(stepRuns, sr)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return stepRuns, nil
}

// Update updates a step run. A terminal step run is final, the same rule as
// ScanRunRepository.Update: a stale in-memory copy written back after a
// cancel, the timeout reaper or a duplicate result settled the step must not
// re-queue it, reopen it or overwrite its outcome. Such a write changes
// nothing and returns scanrun.ErrStepRunAlreadyFinished.
func (r *StepRunRepository) Update(ctx context.Context, sr *scanrun.StepRun) error {
	output, err := json.Marshal(sr.Output)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	query := `
		UPDATE scan_run_steps
		SET status = $2, sensor_id = $3, command_id = $4,
		    condition_evaluated = $5, condition_result = $6, skip_reason = $7,
		    findings_count = $8, output = $9, attempt = $10,
		    queued_at = $11, started_at = $12, completed_at = $13,
		    error_message = $14, error_code = $15,
		    tool = COALESCE(NULLIF($16, ''), tool),
		    capability = COALESCE(NULLIF($17, ''), capability)
		WHERE id = $1
		  AND status NOT IN ` + terminalStepRunStatusesSQL + `
	`

	result, err := r.db.ExecContext(ctx, query,
		sr.ID.String(),
		string(sr.Status),
		nullID(sr.SensorID),
		nullID(sr.CommandID),
		sr.ConditionEvaluated,
		sr.ConditionResult,
		sr.SkipReason,
		sr.FindingsCount,
		output,
		sr.Attempt,
		nullTime(sr.QueuedAt),
		nullTime(sr.StartedAt),
		nullTime(sr.CompletedAt),
		sr.ErrorMessage,
		sr.ErrorCode,
		sr.Tool,
		sr.Capability,
	)

	if err != nil {
		return fmt.Errorf("failed to update step run: %w", err)
	}

	if n, _ := result.RowsAffected(); n == 0 {
		return r.notUpdatedError(ctx, sr.ID)
	}

	return nil
}

// terminalStepRunStatusesSQL lists the statuses a step run never leaves.
const terminalStepRunStatusesSQL = `('completed', 'partial', 'failed', 'skipped', 'canceled', 'timeout')`

// notUpdatedError explains a guarded UPDATE that touched no row: the step run
// is missing, or it already finished.
func (r *StepRunRepository) notUpdatedError(ctx context.Context, id shared.ID) error {
	var exists bool
	if err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM scan_run_steps WHERE id = $1)`, id.String()).Scan(&exists); err != nil {
		return fmt.Errorf("failed to check step run: %w", err)
	}
	if !exists {
		return shared.ErrNotFound
	}
	return scanrun.ErrStepRunAlreadyFinished
}

// Delete deletes a step run.
func (r *StepRunRepository) Delete(ctx context.Context, id shared.ID) error {
	query := "DELETE FROM scan_run_steps WHERE id = $1"
	result, err := r.db.ExecContext(ctx, query, id.String())
	if err != nil {
		return fmt.Errorf("failed to delete step run: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return shared.ErrNotFound
	}

	return nil
}

// UpdateStatus updates step run status. Only a step run that has not finished
// moves; for a terminal one it returns scanrun.ErrStepRunAlreadyFinished and
// changes nothing.
func (r *StepRunRepository) UpdateStatus(ctx context.Context, id shared.ID, status scanrun.StepRunStatus, errorMessage, errorCode string) error {
	query := `
		UPDATE scan_run_steps
		SET status = $2, error_message = $3, error_code = $4,
		    completed_at = CASE WHEN $2::varchar IN ` + terminalStepRunStatusesSQL + ` THEN NOW() ELSE completed_at END
		WHERE id = $1
		  AND status NOT IN ` + terminalStepRunStatusesSQL + `
	`
	result, err := r.db.ExecContext(ctx, query, id.String(), string(status), errorMessage, errorCode)
	if err != nil {
		return fmt.Errorf("failed to update step run status: %w", err)
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return r.notUpdatedError(ctx, id)
	}
	return nil
}

// AssignSensor records that a sensor started the step run with the command.
// Only a pending or queued step run changes: a start that arrives after the
// step finished (or after a batch of the same step already started it) is a
// no-op, so it can neither reopen a finished step nor move started_at.
func (r *StepRunRepository) AssignSensor(ctx context.Context, id shared.ID, sensorID, commandID shared.ID) error {
	query := `
		UPDATE scan_run_steps
		SET sensor_id = $2, command_id = $3, status = 'running', started_at = NOW()
		WHERE id = $1 AND status IN ('pending', 'queued')
	`
	_, err := r.db.ExecContext(ctx, query, id.String(), sensorID.String(), commandID.String())
	return err
}

// Complete marks a step run as completed. A step run that already finished is
// left alone and scanrun.ErrStepRunAlreadyFinished is returned.
func (r *StepRunRepository) Complete(ctx context.Context, id shared.ID, findingsCount int, output map[string]any) error {
	outputJSON, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	query := `
		UPDATE scan_run_steps
		SET status = 'completed', findings_count = $2, output = $3, completed_at = NOW()
		WHERE id = $1
		  AND status NOT IN ` + terminalStepRunStatusesSQL + `
	`
	result, err := r.db.ExecContext(ctx, query, id.String(), findingsCount, outputJSON)
	if err != nil {
		return fmt.Errorf("failed to complete step run: %w", err)
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return r.notUpdatedError(ctx, id)
	}
	return nil
}

// GetPendingByDependencies gets step runs that are pending and have their dependencies completed.
func (r *StepRunRepository) GetPendingByDependencies(ctx context.Context, scanRunID shared.ID, completedStepKeys []string) ([]*scanrun.StepRun, error) {
	// This is a simplified implementation. A more complex version would check dependencies.
	query := r.selectQuery() + " WHERE scan_run_id = $1 AND status = 'pending' ORDER BY step_order ASC"
	rows, err := r.db.QueryContext(ctx, query, scanRunID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get pending step runs: %w", err)
	}
	defer rows.Close()

	var stepRuns []*scanrun.StepRun
	for rows.Next() {
		sr, err := r.scanStepRun(rows)
		if err != nil {
			return nil, err
		}
		stepRuns = append(stepRuns, sr)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return stepRuns, nil
}

// GetStatsByTenant returns aggregated step run statistics for a tenant in a single query.
// Uses a JOIN to filter by tenant through the scan_runs table.
func (r *StepRunRepository) GetStatsByTenant(ctx context.Context, tenantID shared.ID) (scanrun.RunStats, error) {
	var stats scanrun.RunStats

	// Single aggregation query with JOIN - avoids N+1 queries
	query := `
		SELECT
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE sr.status = 'pending') as pending,
			COUNT(*) FILTER (WHERE sr.status IN ('queued', 'running')) as running,
			COUNT(*) FILTER (WHERE sr.status = 'completed') as completed,
			COUNT(*) FILTER (WHERE sr.status = 'partial') as partial,
			COUNT(*) FILTER (WHERE sr.status IN ('failed', 'timeout')) as failed,
			COUNT(*) FILTER (WHERE sr.status IN ('canceled', 'skipped')) as canceled
		FROM scan_run_steps sr
		JOIN scan_runs pr ON sr.scan_run_id = pr.id
		WHERE pr.tenant_id = $1
	`

	err := r.db.QueryRowContext(ctx, query, tenantID.String()).Scan(
		&stats.Total,
		&stats.Pending,
		&stats.Running,
		&stats.Completed,
		&stats.Partial,
		&stats.Failed,
		&stats.Canceled,
	)
	if err != nil {
		return stats, fmt.Errorf("failed to get step run stats: %w", err)
	}

	return stats, nil
}

func (r *StepRunRepository) selectQuery() string {
	return `
		SELECT id, scan_run_id, step_id, step_key, step_order, status,
		       sensor_id, command_id, condition_evaluated, condition_result, skip_reason,
		       findings_count, output, attempt, max_attempts,
		       queued_at, started_at, completed_at, error_message, error_code, created_at,
		       step_name, tool, capability
		FROM scan_run_steps
	`
}

func (r *StepRunRepository) scanStepRun(rows *sql.Rows) (*scanrun.StepRun, error) {
	sr := &scanrun.StepRun{}
	var (
		id              string
		scanRunID       string
		stepID          sql.NullString
		stepName        sql.NullString
		stepTool        sql.NullString
		stepCapability  sql.NullString
		status          string
		sensorID        sql.NullString
		commandID       sql.NullString
		conditionResult sql.NullBool
		output          []byte
		queuedAt        sql.NullTime
		startedAt       sql.NullTime
		completedAt     sql.NullTime
	)

	var skipReason, errorMessage, errorCode sql.NullString

	err := rows.Scan(
		&id,
		&scanRunID,
		&stepID,
		&sr.StepKey,
		&sr.StepOrder,
		&status,
		&sensorID,
		&commandID,
		&sr.ConditionEvaluated,
		&conditionResult,
		&skipReason,
		&sr.FindingsCount,
		&output,
		&sr.Attempt,
		&sr.MaxAttempts,
		&queuedAt,
		&startedAt,
		&completedAt,
		&errorMessage,
		&errorCode,
		&sr.CreatedAt,
		&stepName,
		&stepTool,
		&stepCapability,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to scan step run: %w", err)
	}

	sr.ID, _ = shared.IDFromString(id)
	sr.ScanRunID, _ = shared.IDFromString(scanRunID)
	if stepID.Valid {
		sr.StepID, _ = shared.IDFromString(stepID.String)
	}
	sr.StepName = stepName.String
	sr.Tool = stepTool.String
	sr.Capability = stepCapability.String
	sr.Status = scanrun.StepRunStatus(status)
	sr.SkipReason = skipReason.String
	sr.ErrorMessage = errorMessage.String
	sr.ErrorCode = errorCode.String

	if sensorID.Valid {
		wid, _ := shared.IDFromString(sensorID.String)
		sr.SensorID = &wid
	}
	if commandID.Valid {
		cid, _ := shared.IDFromString(commandID.String)
		sr.CommandID = &cid
	}
	if conditionResult.Valid {
		sr.ConditionResult = &conditionResult.Bool
	}
	if queuedAt.Valid {
		sr.QueuedAt = &queuedAt.Time
	}
	if startedAt.Valid {
		sr.StartedAt = &startedAt.Time
	}
	if completedAt.Valid {
		sr.CompletedAt = &completedAt.Time
	}

	if len(output) > 0 {
		_ = json.Unmarshal(output, &sr.Output)
	}

	return sr, nil
}

// stepRunStepID is the step_id column value: NULL for a step run whose step
// was removed from the scan workflow (zero StepID).
func stepRunStepID(id shared.ID) sql.NullString {
	if id.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: id.String(), Valid: true}
}
