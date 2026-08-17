package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/ctemcycle"
	"github.com/openctemio/api/pkg/domain/shared"
)

// CTEMCycleMetricsRepository computes, persists and reads per-cycle CTEM
// metrics against the ctem_cycle_metrics table.
//
// ctem_cycle_metrics has no tenant_id column, so every operation is
// tenant-scoped by joining ctem_cycles (which does). See RFC-005.
//
// Per-metric SQL source (all over the active window
// [COALESCE(activated_at, created_at), COALESCE(closed_at, NOW())]):
//   - mttr_hours          AVG(resolved_at − created_at) over findings resolved in window
//   - findings_opened     COUNT(findings) created in window
//   - findings_resolved   COUNT(findings) resolved in window
//   - p_class_churn        COUNT(priority_class_audit_log) rows in window
//   - validation_coverage  % of findings resolved in window with ≥1 validation_evidence row
//   - scope_drift_size     0 — scope-change event emitter deferred (see scope_delta.go)
type CTEMCycleMetricsRepository struct {
	db *DB
}

// NewCTEMCycleMetricsRepository creates the repository.
func NewCTEMCycleMetricsRepository(db *DB) *CTEMCycleMetricsRepository {
	return &CTEMCycleMetricsRepository{db: db}
}

// Ensure the repo satisfies the domain interface.
var _ ctemcycle.MetricsRepository = (*CTEMCycleMetricsRepository)(nil)

// window resolves a cycle's active window, tenant-scoped. Returns
// shared.ErrNotFound when the cycle does not belong to the tenant.
func (r *CTEMCycleMetricsRepository) window(
	ctx context.Context, tenantID, cycleID shared.ID,
) (start, end time.Time, err error) {
	const q = `
		SELECT COALESCE(activated_at, created_at) AS window_start,
		       COALESCE(closed_at, NOW())         AS window_end
		  FROM ctem_cycles
		 WHERE id = $1 AND tenant_id = $2
	`
	err = r.db.QueryRowContext(ctx, q, cycleID.String(), tenantID.String()).Scan(&start, &end)
	if errors.Is(err, sql.ErrNoRows) {
		return start, end, shared.ErrNotFound
	}
	if err != nil {
		return start, end, fmt.Errorf("resolve cycle window: %w", err)
	}
	return start, end, nil
}

// Compute runs the metric queries over the cycle's active window and
// returns the values without persisting them.
func (r *CTEMCycleMetricsRepository) Compute(
	ctx context.Context, tenantID, cycleID shared.ID,
) (ctemcycle.CycleMetricSet, error) {
	start, end, err := r.window(ctx, tenantID, cycleID)
	if err != nil {
		return nil, err
	}
	tid := tenantID.String()
	out := ctemcycle.CycleMetricSet{}

	// mttr_hours — mean hours from finding creation to resolution, for
	// findings resolved within the window.
	var mttr float64
	if err := r.db.QueryRowContext(ctx, `
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 3600.0), 0)::double precision
		  FROM findings
		 WHERE tenant_id = $1
		   AND resolved_at IS NOT NULL
		   AND resolved_at >= $2 AND resolved_at < $3
	`, tid, start, end).Scan(&mttr); err != nil {
		return nil, fmt.Errorf("compute mttr_hours: %w", err)
	}
	out[ctemcycle.MetricMTTRHours] = mttr

	// findings_opened — findings created within the window.
	var opened int64
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM findings
		 WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3
	`, tid, start, end).Scan(&opened); err != nil {
		return nil, fmt.Errorf("compute findings_opened: %w", err)
	}
	out[ctemcycle.MetricFindingsOpened] = float64(opened)

	// findings_resolved — findings resolved within the window.
	var resolved int64
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM findings
		 WHERE tenant_id = $1
		   AND resolved_at IS NOT NULL
		   AND resolved_at >= $2 AND resolved_at < $3
	`, tid, start, end).Scan(&resolved); err != nil {
		return nil, fmt.Errorf("compute findings_resolved: %w", err)
	}
	out[ctemcycle.MetricFindingsResolved] = float64(resolved)

	// p_class_churn — count of priority-class transitions in the window.
	var churn int64
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM priority_class_audit_log
		 WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3
	`, tid, start, end).Scan(&churn); err != nil {
		return nil, fmt.Errorf("compute p_class_churn: %w", err)
	}
	out[ctemcycle.MetricPClassChurn] = float64(churn)

	// validation_coverage — % of findings resolved in the window that
	// carry at least one validation_evidence record.
	var totalClosed, withEvidence int64
	if err := r.db.QueryRowContext(ctx, `
		SELECT
		  COUNT(*) AS total,
		  COUNT(*) FILTER (
		    WHERE EXISTS (
		      SELECT 1 FROM validation_evidence v
		       WHERE v.tenant_id = f.tenant_id AND v.finding_id = f.id
		    )
		  ) AS with_ev
		FROM findings f
		WHERE f.tenant_id = $1
		  AND f.resolved_at IS NOT NULL
		  AND f.resolved_at >= $2 AND f.resolved_at < $3
	`, tid, start, end).Scan(&totalClosed, &withEvidence); err != nil {
		return nil, fmt.Errorf("compute validation_coverage: %w", err)
	}
	coverage := 0.0
	if totalClosed > 0 {
		coverage = 100.0 * float64(withEvidence) / float64(totalClosed)
	}
	out[ctemcycle.MetricValidationCoverage] = coverage

	// scope_drift_size — deferred: no scope-change event source is wired
	// yet (ctem_cycle_scope_changes table + emitter). Record 0 so the
	// metric exists and the series is complete.
	out[ctemcycle.MetricScopeDriftSize] = 0

	return out, nil
}

// UpsertBatch replaces the stored metric rows for one cycle with the
// given set, inside a transaction (delete-then-insert). Tenant-scoped.
func (r *CTEMCycleMetricsRepository) UpsertBatch(
	ctx context.Context, tenantID, cycleID shared.ID, metrics ctemcycle.CycleMetricSet,
) error {
	if len(metrics) == 0 {
		return nil
	}

	var owned bool
	if err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM ctem_cycles WHERE id = $1 AND tenant_id = $2)`,
		cycleID.String(), tenantID.String(),
	).Scan(&owned); err != nil {
		return fmt.Errorf("verify cycle ownership: %w", err)
	}
	if !owned {
		return shared.ErrNotFound
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin metrics tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`DELETE FROM ctem_cycle_metrics WHERE cycle_id = $1`, cycleID.String(),
	); err != nil {
		return fmt.Errorf("clear existing metrics: %w", err)
	}

	const ins = `
		INSERT INTO ctem_cycle_metrics (cycle_id, metric_type, value, computed_at)
		VALUES ($1, $2, $3, NOW())
	`
	for metricType, value := range metrics {
		if _, err := tx.ExecContext(ctx, ins, cycleID.String(), metricType, value); err != nil {
			return fmt.Errorf("insert metric %s: %w", metricType, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit metrics tx: %w", err)
	}
	return nil
}

// Get returns the persisted metric rows for one cycle, newest first.
func (r *CTEMCycleMetricsRepository) Get(
	ctx context.Context, tenantID, cycleID shared.ID,
) ([]ctemcycle.StoredMetric, error) {
	const q = `
		SELECT m.metric_type, m.value::double precision, m.computed_at
		  FROM ctem_cycle_metrics m
		  JOIN ctem_cycles c ON c.id = m.cycle_id AND c.tenant_id = $1
		 WHERE m.cycle_id = $2
		 ORDER BY m.computed_at DESC, m.metric_type
	`
	rows, err := r.db.QueryContext(ctx, q, tenantID.String(), cycleID.String())
	if err != nil {
		return nil, fmt.Errorf("query cycle metrics: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]ctemcycle.StoredMetric, 0, 6)
	for rows.Next() {
		var m ctemcycle.StoredMetric
		if err := rows.Scan(&m.MetricType, &m.Value, &m.ComputedAt); err != nil {
			return nil, fmt.Errorf("scan cycle metric: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cycle metrics: %w", err)
	}
	return out, nil
}

// ListClosedForTenant batch-loads every closed cycle's latest metrics in
// a single query, ordered by closed_at ascending. No N+1.
func (r *CTEMCycleMetricsRepository) ListClosedForTenant(
	ctx context.Context, tenantID shared.ID,
) ([]ctemcycle.CycleMetrics, error) {
	const q = `
		SELECT c.id,
		       c.name,
		       COALESCE(c.closed_at, c.updated_at) AS closed_at,
		       m.metric_type,
		       m.value::double precision,
		       m.computed_at
		  FROM ctem_cycles c
		  JOIN ctem_cycle_metrics m ON m.cycle_id = c.id
		 WHERE c.tenant_id = $1 AND c.status = 'closed'
		 ORDER BY closed_at ASC, c.id, m.computed_at DESC
	`
	rows, err := r.db.QueryContext(ctx, q, tenantID.String())
	if err != nil {
		return nil, fmt.Errorf("query closed cycle metrics: %w", err)
	}
	defer func() { _ = rows.Close() }()

	// Preserve closed_at ordering while grouping metric rows per cycle.
	order := make([]string, 0)
	byID := make(map[string]*ctemcycle.CycleMetrics)
	for rows.Next() {
		var (
			idStr, name, metricType string
			closedAt, computedAt    time.Time
			value                   float64
		)
		if err := rows.Scan(&idStr, &name, &closedAt, &metricType, &value, &computedAt); err != nil {
			return nil, fmt.Errorf("scan closed cycle metric: %w", err)
		}
		cm, ok := byID[idStr]
		if !ok {
			cid, perr := shared.IDFromString(idStr)
			if perr != nil {
				return nil, fmt.Errorf("parse cycle id: %w", perr)
			}
			cm = &ctemcycle.CycleMetrics{
				CycleID:  cid,
				Name:     name,
				ClosedAt: closedAt,
				Metrics:  make(map[string]float64),
			}
			byID[idStr] = cm
			order = append(order, idStr)
		}
		// computed_at DESC in the query means the first row per
		// (cycle, metric) is the latest — keep it, ignore older ones.
		if _, seen := cm.Metrics[metricType]; !seen {
			cm.Metrics[metricType] = value
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate closed cycle metrics: %w", err)
	}

	out := make([]ctemcycle.CycleMetrics, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out, nil
}
