package postgres

import (
	"context"
	"fmt"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A scan's run summary (last_run_id, last_run_at, last_run_status and the run
// counters) is a cache of its runs, never a second record. Every writer used
// to bump it on its own: the trigger set last_run_at when a run started, the
// completion counted the run when it finished, the reapers counted again in
// their own SQL, and a refused scheduled trigger moved last_run_at with no run
// at all. The list then showed "Last run: today" next to "Runs: 0".
//
// Now every change recomputes the whole summary from scan_runs in one
// statement, so the three numbers on a scan row always describe the same set
// of runs. Migration 001157 ran the same statement once over every scan.
//
// Counted: total = every run (running and blocked ones too, as the run list
// shows them); successful = completed; failed = failed + timeout; partial;
// blocked. Canceled runs count only in total.
const scanRunSummaryUpdateSQL = `
	UPDATE scans s
	SET (last_run_id, last_run_at, last_run_status,
	     total_runs, successful_runs, failed_runs, partial_runs, blocked_runs) = (
		SELECT l.id, l.created_at, l.status,
		       a.total, a.successful, a.failed, a.partial, a.blocked
		FROM (
			SELECT COUNT(*)::int AS total,
			       (COUNT(*) FILTER (WHERE pr.status = 'completed'))::int AS successful,
			       (COUNT(*) FILTER (WHERE pr.status IN ('failed', 'timeout')))::int AS failed,
			       (COUNT(*) FILTER (WHERE pr.status = 'partial'))::int AS partial,
			       (COUNT(*) FILTER (WHERE pr.status = 'blocked'))::int AS blocked
			FROM scan_runs pr
			WHERE pr.tenant_id = s.tenant_id AND pr.scan_id = s.id
		) a
		LEFT JOIN LATERAL (
			SELECT pr.id, pr.created_at, pr.status
			FROM scan_runs pr
			WHERE pr.tenant_id = s.tenant_id AND pr.scan_id = s.id
			ORDER BY pr.created_at DESC, pr.id DESC
			LIMIT 1
		) l ON true
	)
`

// The two scan selections a refresh runs on, each as a lock statement and
// the update (constant SQL, no string built at run time).
const (
	scanRunSummaryWhereOne  = ` WHERE s.tenant_id = $1 AND s.id = $2`
	scanRunSummaryWhereMany = ` WHERE s.id = ANY($1::uuid[])`
	scanRunSummaryLock      = `SELECT 1 FROM scans s`
	scanRunSummaryLockOrder = ` ORDER BY s.id FOR UPDATE`
)

var (
	scanRunSummaryOne = scanRunSummaryStatements{
		lock:   scanRunSummaryLock + scanRunSummaryWhereOne + scanRunSummaryLockOrder,
		update: scanRunSummaryUpdateSQL + scanRunSummaryWhereOne,
	}
	scanRunSummaryMany = scanRunSummaryStatements{
		lock:   scanRunSummaryLock + scanRunSummaryWhereMany + scanRunSummaryLockOrder,
		update: scanRunSummaryUpdateSQL + scanRunSummaryWhereMany,
	}
)

type scanRunSummaryStatements struct{ lock, update string }

// RefreshRunSummary recomputes the scan's run summary from its runs. Call it
// after any change to a run of the scan (created, blocked, finished,
// canceled). Idempotent; a scan of another tenant is left untouched.
func (r *ScanRepository) RefreshRunSummary(ctx context.Context, tenantID, id shared.ID) error {
	return refreshScanRunSummaries(ctx, r.db, scanRunSummaryOne, tenantID.String(), id.String())
}

// refreshScanRunSummariesByID recomputes the summary of every scan in ids,
// whatever its tenant: for the reapers, which settle runs of all tenants and
// know only the scan ids. Each scan's summary still reads only its own
// tenant's runs.
func refreshScanRunSummariesByID(ctx context.Context, db *DB, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	return refreshScanRunSummaries(ctx, db, scanRunSummaryMany, pq.Array(ids))
}

// refreshScanRunSummaries locks the matched scan rows, then recomputes them.
// The lock comes first, in its own statement, so the UPDATE's snapshot is
// taken after every transaction that held the row (a run insert holds it, see
// CreateRunIfUnderLimit) has committed: two refreshes racing cannot write a
// summary older than the runs they were called for.
func refreshScanRunSummaries(ctx context.Context, db *DB, q scanRunSummaryStatements, args ...any) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("refresh scan run summary: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, q.lock, args...); err != nil {
		return fmt.Errorf("refresh scan run summary: lock: %w", err)
	}
	if _, err := tx.ExecContext(ctx, q.update, args...); err != nil {
		return fmt.Errorf("refresh scan run summary: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("refresh scan run summary: commit: %w", err)
	}
	return nil
}
