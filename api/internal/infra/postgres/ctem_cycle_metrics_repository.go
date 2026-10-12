package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	"github.com/openctemio/openctem/api/pkg/domain/ctemcycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
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
//   - scope_drift_size     COUNT(external-surface assets: domain, subdomain, ip_address,
//     certificate) first seen in window, not deleted, not rejected (RFC-036 §6.9)
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
		 WHERE tenant_id = $1 AND NOT branch_only
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
		 WHERE tenant_id = $1 AND NOT branch_only AND created_at >= $2 AND created_at < $3
	`, tid, start, end).Scan(&opened); err != nil {
		return nil, fmt.Errorf("compute findings_opened: %w", err)
	}
	out[ctemcycle.MetricFindingsOpened] = float64(opened)

	// findings_resolved — findings resolved within the window.
	var resolved int64
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM findings
		 WHERE tenant_id = $1 AND NOT branch_only
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
		WHERE f.tenant_id = $1 AND NOT f.branch_only
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

	// scope_drift_size — new external attack surface this cycle (RFC-036
	// §6.9): external-surface assets first seen in the window. Names a person
	// marked as not the tenant's are not drift.
	var drift int64
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		  FROM assets a
		 WHERE a.tenant_id = $1
		   AND a.deleted_at IS NULL
		   AND a.asset_type = ANY($4)
		   AND a.first_seen >= $2 AND a.first_seen < $3
		   AND NOT EXISTS (SELECT 1 FROM asset_attributions rj
		                    WHERE rj.asset_id = a.id AND rj.tenant_id = a.tenant_id AND rj.state = 'rejected')
	`, tid, start, end, pq.Array(EASMSurfaceTypes)).Scan(&drift); err != nil {
		return nil, fmt.Errorf("scope_drift_size: %w", err)
	}
	out[ctemcycle.MetricScopeDriftSize] = float64(drift)

	// p0_resolved / p1_resolved — findings of that priority class resolved
	// within the window. Priority class is read as it is now; a finding
	// re-classified after it was resolved counts under its current class.
	var p0Resolved, p1Resolved int64
	if err := r.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FILTER (WHERE priority_class = 'P0'),
		       COUNT(*) FILTER (WHERE priority_class = 'P1')
		  FROM findings
		 WHERE tenant_id = $1 AND NOT branch_only
		   AND resolved_at IS NOT NULL
		   AND resolved_at >= $2 AND resolved_at < $3
	`, tid, start, end).Scan(&p0Resolved, &p1Resolved); err != nil {
		return nil, fmt.Errorf("compute p0/p1_resolved: %w", err)
	}
	out[ctemcycle.MetricP0Resolved] = float64(p0Resolved)
	out[ctemcycle.MetricP1Resolved] = float64(p1Resolved)

	if err := r.computeRiskSnapshotMetrics(ctx, tid, start, end, out); err != nil {
		return nil, err
	}

	return out, nil
}

// computeRiskSnapshotMetrics reads the tenant's daily risk_snapshots to
// derive the point-in-time metrics a window query cannot: risk at the start
// and end of the cycle, and the open P0/P1 backlog at close.
//
//   - risk_before: risk_score_avg of the latest snapshot on or before the
//     window-start date
//   - risk_after / p0_open_at_close / p1_open_at_close: the latest snapshot on
//     or before the window-end date
//   - risk_reduction_pct: (before − after) / before × 100
//
// Reading snapshots (not live tables) keeps the values reproducible: a lazy
// recompute months after close yields the same numbers as the close itself.
// Metrics are only emitted when the snapshot exists — a missing value makes
// a criterion "not measurable" rather than silently passing on a 0. Risk
// before/after/reduction are also skipped when both ends resolve to the same
// snapshot day, which would report a meaningless 0% change.
func (r *CTEMCycleMetricsRepository) computeRiskSnapshotMetrics(
	ctx context.Context, tid string, start, end time.Time, out ctemcycle.CycleMetricSet,
) error {
	const q = `
		SELECT snapshot_date, risk_score_avg::double precision, p0_open, p1_open
		  FROM risk_snapshots
		 WHERE tenant_id = $1 AND snapshot_date <= $2::date
		 ORDER BY snapshot_date DESC
		 LIMIT 1
	`
	type snap struct {
		day            time.Time
		risk           float64
		p0Open, p1Open int64
	}
	load := func(at time.Time) (*snap, error) {
		var s snap
		var p0, p1 sql.NullInt64
		var risk sql.NullFloat64
		err := r.db.QueryRowContext(ctx, q, tid, at.UTC().Format("2006-01-02")).
			Scan(&s.day, &risk, &p0, &p1)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		s.risk, s.p0Open, s.p1Open = risk.Float64, p0.Int64, p1.Int64
		return &s, nil
	}

	after, err := load(end)
	if err != nil {
		return fmt.Errorf("compute risk snapshot at close: %w", err)
	}
	if after == nil {
		return nil
	}
	out[ctemcycle.MetricP0OpenAtClose] = float64(after.p0Open)
	out[ctemcycle.MetricP1OpenAtClose] = float64(after.p1Open)

	before, err := load(start)
	if err != nil {
		return fmt.Errorf("compute risk snapshot at start: %w", err)
	}
	if before == nil || !before.day.Before(after.day) {
		return nil
	}
	out[ctemcycle.MetricRiskBefore] = before.risk
	out[ctemcycle.MetricRiskAfter] = after.risk
	if before.risk > 0 {
		out[ctemcycle.MetricRiskReductionPct] = 100 * (before.risk - after.risk) / before.risk
	}
	return nil
}

// GetSuccessCriteria returns the success criteria on the cycle's charter,
// tenant-scoped.
func (r *CTEMCycleMetricsRepository) GetSuccessCriteria(
	ctx context.Context, tenantID, cycleID shared.ID,
) ([]ctemcycle.CharterSuccessCriterion, error) {
	var raw []byte
	err := r.db.QueryRowContext(ctx,
		`SELECT COALESCE(charter, '{}'::jsonb) FROM ctem_cycles WHERE id = $1 AND tenant_id = $2`,
		cycleID.String(), tenantID.String(),
	).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, shared.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("load cycle charter: %w", err)
	}
	var charter struct {
		SuccessCriteria []ctemcycle.CharterSuccessCriterion `json:"success_criteria"`
	}
	if err := json.Unmarshal(raw, &charter); err != nil {
		return nil, fmt.Errorf("decode cycle charter: %w", err)
	}
	return charter.SuccessCriteria, nil
}

// SaveCharterEvaluation stores the close-time verdicts on the cycle row,
// tenant-scoped: a foreign cycle matches no row and yields ErrNotFound.
func (r *CTEMCycleMetricsRepository) SaveCharterEvaluation(
	ctx context.Context, tenantID, cycleID shared.ID, ev ctemcycle.CharterEvaluation,
) error {
	raw, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("encode charter evaluation: %w", err)
	}
	res, err := r.db.ExecContext(ctx,
		`UPDATE ctem_cycles SET charter_evaluation = $3::jsonb
		  WHERE id = $1 AND tenant_id = $2`,
		cycleID.String(), tenantID.String(), raw,
	)
	if err != nil {
		return fmt.Errorf("save charter evaluation: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("save charter evaluation rows: %w", err)
	}
	if n == 0 {
		return shared.ErrNotFound
	}
	return nil
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
