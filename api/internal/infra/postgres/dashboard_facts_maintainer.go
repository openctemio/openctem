package postgres

// Dashboard facts maintainer storage (docs/architecture/dashboards.md,
// "Facts maintainer"): the dirty-queue claim, full runs with drift
// detection, age-band marking, F2 partition upkeep and the rebuild request.
// The per-tenant methods take the tenant from the caller; the methods that
// work across tenants end in ForPlatform and are called only by the
// controllers.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/dashboardfact"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// maxDashboardClaim bounds one claim of the dirty queue.
const maxDashboardClaim = 5000

func requireFactTenant(tenantID shared.ID) error {
	if tenantID.IsZero() {
		return fmt.Errorf("%w: tenant id is required", shared.ErrValidation)
	}
	return nil
}

// ProcessDirty claims up to limit of the tenant's dirty rows, recomputes the
// marked assets and deletes exactly the claimed rows, all in one
// transaction (dash_process_dirty).
func (r *DashboardFactsRepository) ProcessDirty(ctx context.Context, tenantID shared.ID, limit int) (dashboardfact.DirtyBatch, error) {
	var b dashboardfact.DirtyBatch
	if err := requireFactTenant(tenantID); err != nil {
		return b, err
	}
	limit = min(max(limit, 1), maxDashboardClaim)
	var oldest sql.NullTime
	if err := r.db.QueryRowContext(ctx,
		`SELECT claimed, assets, recomputed, changed, oldest_marked_at FROM dash_process_dirty($1, $2)`,
		tenantID.String(), limit).Scan(&b.Claimed, &b.Assets, &b.Recomputed, &b.Changed, &oldest); err != nil {
		return b, fmt.Errorf("process dashboard dirty queue: %w", err)
	}
	if oldest.Valid {
		b.OldestMarkedAt = oldest.Time
	}
	return b, nil
}

// TenantsWithDirtyForPlatform lists the tenants that have unprocessed change
// marks, in tenant id order (the controller rotates through them).
func (r *DashboardFactsRepository) TenantsWithDirtyForPlatform(ctx context.Context, limit int) ([]shared.ID, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT DISTINCT tenant_id FROM dash_dirty_assets ORDER BY tenant_id LIMIT $1`, max(limit, 1))
	if err != nil {
		return nil, fmt.Errorf("list tenants with dashboard changes: %w", err)
	}
	defer rows.Close()
	return scanFactIDs(rows)
}

// QueueStatsForPlatform returns the dirty queue's size and the time of its
// oldest mark (zero when empty), for the lag and depth metrics.
func (r *DashboardFactsRepository) QueueStatsForPlatform(ctx context.Context) (int, time.Time, error) {
	var n int
	var oldest sql.NullTime
	if err := r.db.QueryRowContext(ctx,
		`SELECT count(*), min(marked_at) FROM dash_dirty_assets`).Scan(&n, &oldest); err != nil {
		return 0, time.Time{}, fmt.Errorf("dashboard dirty queue stats: %w", err)
	}
	if !oldest.Valid {
		return n, time.Time{}, nil
	}
	return n, oldest.Time, nil
}

// PendingRunsForPlatform lists tenants whose facts need a full run, most
// urgent first: runs in progress, then requested rebuilds, then tenants never
// built, then tenants not reconciled for nightlyEvery (least recently
// reconciled first).
func (r *DashboardFactsRepository) PendingRunsForPlatform(ctx context.Context, nightlyEvery time.Duration, limit int) ([]dashboardfact.PendingRun, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, kind, in_progress FROM (
			SELECT t.id,
			       CASE
			           WHEN s.run_kind IS NOT NULL THEN s.run_kind
			           WHEN s.rebuild_requested_at > COALESCE(s.run_started_at, '-infinity'::timestamptz) THEN 'requested'
			           WHEN s.rebuilt_at IS NULL THEN 'initial'
			           WHEN COALESCE(s.reconciled_at, s.rebuilt_at) < now() - make_interval(secs => $1) THEN 'nightly'
			       END AS kind,
			       s.run_kind IS NOT NULL AS in_progress,
			       COALESCE(s.reconciled_at, s.rebuilt_at) AS last_run
			FROM tenants t
			LEFT JOIN dash_fact_status s ON s.tenant_id = t.id
		) p
		WHERE kind IS NOT NULL
		ORDER BY in_progress DESC,
		         CASE kind WHEN 'requested' THEN 0 WHEN 'initial' THEN 1 ELSE 2 END,
		         last_run NULLS FIRST, id
		LIMIT $2`, nightlyEvery.Seconds(), max(limit, 1))
	if err != nil {
		return nil, fmt.Errorf("list pending dashboard fact runs: %w", err)
	}
	defer rows.Close()
	var out []dashboardfact.PendingRun
	for rows.Next() {
		var p dashboardfact.PendingRun
		var id, kind string
		if err := rows.Scan(&id, &kind, &p.InProgress); err != nil {
			return nil, err
		}
		tid, err := shared.IDFromString(id)
		if err != nil {
			return nil, err
		}
		p.TenantID, p.Kind = tid, dashboardfact.RunKind(kind)
		out = append(out, p)
	}
	return out, rows.Err()
}

// StartRun begins a full run of the tenant's facts (cursor at the start,
// drift zero) unless one is already in progress. It reports whether it
// started one.
func (r *DashboardFactsRepository) StartRun(ctx context.Context, tenantID shared.ID, kind dashboardfact.RunKind) (bool, error) {
	if err := requireFactTenant(tenantID); err != nil {
		return false, err
	}
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO dash_fact_status AS s (tenant_id, run_kind, run_started_at, run_cursor, run_drift)
		VALUES ($1, $2, now(), NULL, 0)
		ON CONFLICT (tenant_id) DO UPDATE
		    SET run_kind = EXCLUDED.run_kind, run_started_at = now(), run_cursor = NULL, run_drift = 0
		    WHERE s.run_kind IS NULL`, tenantID.String(), string(kind))
	if err != nil {
		return false, fmt.Errorf("start dashboard fact run: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// RunStep runs one step (batchSize assets) of the tenant's full run.
func (r *DashboardFactsRepository) RunStep(ctx context.Context, tenantID shared.ID, batchSize int) (dashboardfact.RunStep, error) {
	var s dashboardfact.RunStep
	if err := requireFactTenant(tenantID); err != nil {
		return s, err
	}
	if batchSize <= 0 {
		batchSize = DefaultDashboardRebuildBatch
	}
	batchSize = min(batchSize, maxDashboardRebuildBatch)
	var kind string
	if err := r.db.QueryRowContext(ctx, `SELECT done, run_kind, step_drift FROM dash_fact_run_step($1, $2)`,
		tenantID.String(), batchSize).Scan(&s.Done, &kind, &s.Drift); err != nil {
		return s, fmt.Errorf("dashboard fact run step: %w", err)
	}
	s.Kind = dashboardfact.RunKind(kind)
	return s, nil
}

// AgedMarkingDueForPlatform lists the tenants with built facts whose
// age-band marking is older than every (since = the last marking, or the
// last full run when there was none).
func (r *DashboardFactsRepository) AgedMarkingDueForPlatform(ctx context.Context, every time.Duration, limit int) ([]dashboardfact.AgedMarkingDue, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT tenant_id, COALESCE(aged_marked_at, rebuilt_at)
		FROM dash_fact_status
		WHERE rebuilt_at IS NOT NULL
		  AND COALESCE(aged_marked_at, rebuilt_at) < now() - make_interval(secs => $1)
		ORDER BY 2, 1
		LIMIT $2`, every.Seconds(), max(limit, 1))
	if err != nil {
		return nil, fmt.Errorf("list dashboard age marking due: %w", err)
	}
	defer rows.Close()
	var out []dashboardfact.AgedMarkingDue
	for rows.Next() {
		var id string
		var d dashboardfact.AgedMarkingDue
		if err := rows.Scan(&id, &d.Since); err != nil {
			return nil, err
		}
		if d.TenantID, err = shared.IDFromString(id); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// MaintainPartitionsForPlatform creates the coming F2 partitions and drops
// those past the history window (dash_asset_day_maintain).
func (r *DashboardFactsRepository) MaintainPartitionsForPlatform(ctx context.Context) (created, dropped, moved int, err error) {
	if err = r.db.QueryRowContext(ctx, `SELECT created, dropped, moved FROM dash_asset_day_maintain()`).
		Scan(&created, &dropped, &moved); err != nil {
		return 0, 0, 0, fmt.Errorf("maintain dashboard day partitions: %w", err)
	}
	return created, dropped, moved, nil
}

// RequestRebuild records a rebuild request of the tenant unless one was
// recorded less than interval ago; then it returns a *TooSoonError with the
// time the next one is accepted. The check and the write are one statement,
// so two concurrent requests cannot both pass.
func (r *DashboardFactsRepository) RequestRebuild(ctx context.Context, tenantID shared.ID, interval time.Duration) (time.Time, error) {
	if err := requireFactTenant(tenantID); err != nil {
		return time.Time{}, err
	}
	var at time.Time
	err := r.db.QueryRowContext(ctx, `
		INSERT INTO dash_fact_status AS s (tenant_id, rebuild_requested_at) VALUES ($1, now())
		ON CONFLICT (tenant_id) DO UPDATE SET rebuild_requested_at = now()
		    WHERE s.rebuild_requested_at IS NULL OR s.rebuild_requested_at <= now() - make_interval(secs => $2)
		RETURNING rebuild_requested_at`, tenantID.String(), interval.Seconds()).Scan(&at)
	if err == nil {
		return at, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, fmt.Errorf("request dashboard rebuild: %w", err)
	}
	var last time.Time
	if err := r.db.QueryRowContext(ctx,
		`SELECT rebuild_requested_at FROM dash_fact_status WHERE tenant_id = $1`, tenantID.String()).Scan(&last); err != nil {
		return time.Time{}, fmt.Errorf("read dashboard rebuild request: %w", err)
	}
	return time.Time{}, &dashboardfact.TooSoonError{RetryAt: last.Add(interval)}
}

// Status returns the tenant's fact status. interval is the rebuild request
// interval (for NextRebuildAt).
func (r *DashboardFactsRepository) Status(ctx context.Context, tenantID shared.ID, interval time.Duration) (dashboardfact.Status, error) {
	var st dashboardfact.Status
	if err := requireFactTenant(tenantID); err != nil {
		return st, err
	}
	var rebuilt, reconciled, requested, started sql.NullTime
	var drift sql.NullInt64
	var running sql.NullString
	err := r.db.QueryRowContext(ctx, `
		SELECT s.rebuilt_at, s.reconciled_at, s.last_drift, s.rebuild_requested_at, s.run_kind, s.run_started_at
		FROM dash_fact_status s WHERE s.tenant_id = $1`, tenantID.String()).
		Scan(&rebuilt, &reconciled, &drift, &requested, &running, &started)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return st, fmt.Errorf("read dashboard fact status: %w", err)
	}
	if err := r.db.QueryRowContext(ctx,
		`SELECT count(*) FROM dash_dirty_assets WHERE tenant_id = $1`, tenantID.String()).Scan(&st.QueueDepth); err != nil {
		return st, fmt.Errorf("count dashboard changes: %w", err)
	}
	st.RebuiltAt = factTimePtr(rebuilt)
	st.ReconciledAt = factTimePtr(reconciled)
	st.RebuildRequestedAt = factTimePtr(requested)
	if drift.Valid {
		d := int(drift.Int64)
		st.LastDrift = &d
	}
	st.Running = dashboardfact.RunKind(running.String)
	st.Pending = requested.Valid && (!started.Valid || requested.Time.After(started.Time))
	if requested.Valid {
		if next := requested.Time.Add(interval); next.After(time.Now()) {
			st.NextRebuildAt = &next
		}
	}
	return st, nil
}

func factTimePtr(t sql.NullTime) *time.Time {
	if !t.Valid {
		return nil
	}
	v := t.Time
	return &v
}

func scanFactIDs(rows *sql.Rows) ([]shared.ID, error) {
	var out []shared.ID
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		id, err := shared.IDFromString(s)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
