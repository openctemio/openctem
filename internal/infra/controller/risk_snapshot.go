package controller

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// RiskSnapshotController computes daily risk snapshots for all tenants.
// Runs every 6 hours, but only inserts one row per tenant per day (UPSERT).
//
// RFC-005 Gap 4: Risk Trend / Outcome Metrics.
type RiskSnapshotController struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewRiskSnapshotController creates a new controller.
func NewRiskSnapshotController(db *sql.DB, log *logger.Logger) *RiskSnapshotController {
	return &RiskSnapshotController{db: db, logger: log}
}

// Name returns the controller name.
func (c *RiskSnapshotController) Name() string { return "risk-snapshot" }

// Interval returns 6 hours (computes at most once per day per tenant via UPSERT).
func (c *RiskSnapshotController) Interval() time.Duration { return 6 * time.Hour }

// Reconcile computes and persists risk snapshots for all tenants.
// Uses pre-aggregated CTEs with GROUP BY tenant_id for O(1) queries regardless of tenant count.
func (c *RiskSnapshotController) Reconcile(ctx context.Context) (int, error) {
	today := time.Now().Format("2006-01-02")

	// Pre-aggregate all metrics with GROUP BY tenant_id, then JOIN to tenants.
	// This executes a fixed number of table scans regardless of tenant count.
	query := `
		WITH asset_metrics AS (
			SELECT tenant_id,
				COALESCE(AVG(risk_score) FILTER(WHERE risk_score > 0), 0) AS avg_risk,
				COALESCE(MAX(risk_score), 0) AS max_risk,
				CASE WHEN COUNT(*) = 0 THEN 0
					ELSE COUNT(*) FILTER(WHERE owner_id IS NOT NULL) * 100.0 / COUNT(*)
				END AS ownership_pct
			FROM assets GROUP BY tenant_id
		),
		finding_metrics AS (
			SELECT tenant_id,
				COUNT(*) FILTER(WHERE status NOT IN ('closed','resolved','false_positive','verified')) AS open_count,
				COUNT(*) FILTER(WHERE resolved_at >= CURRENT_DATE AND resolved_at < CURRENT_DATE + 1) AS closed_today,
				COUNT(*) FILTER(WHERE priority_class = 'P0' AND status NOT IN ('closed','resolved','false_positive','verified')) AS p0,
				COUNT(*) FILTER(WHERE priority_class = 'P1' AND status NOT IN ('closed','resolved','false_positive','verified')) AS p1,
				COUNT(*) FILTER(WHERE priority_class = 'P2' AND status NOT IN ('closed','resolved','false_positive','verified')) AS p2,
				COUNT(*) FILTER(WHERE priority_class = 'P3' AND status NOT IN ('closed','resolved','false_positive','verified')) AS p3,
				CASE WHEN COUNT(*) FILTER(WHERE sla_deadline IS NOT NULL AND status NOT IN ('closed','resolved','false_positive','verified')) = 0 THEN 100
					ELSE COUNT(*) FILTER(WHERE sla_status != 'breached' AND sla_deadline IS NOT NULL AND status NOT IN ('closed','resolved','false_positive','verified'))
						* 100.0 / NULLIF(COUNT(*) FILTER(WHERE sla_deadline IS NOT NULL AND status NOT IN ('closed','resolved','false_positive','verified')), 0)
				END AS sla_pct
			FROM findings GROUP BY tenant_id
		),
		mttr_metrics AS (
			SELECT tenant_id,
				AVG(EXTRACT(epoch FROM resolved_at - first_detected_at)/3600) FILTER(WHERE severity = 'critical') AS mttr_c,
				AVG(EXTRACT(epoch FROM resolved_at - first_detected_at)/3600) FILTER(WHERE severity = 'high') AS mttr_h,
				AVG(EXTRACT(epoch FROM resolved_at - first_detected_at)/3600) FILTER(WHERE severity = 'medium') AS mttr_m,
				AVG(EXTRACT(epoch FROM resolved_at - first_detected_at)/3600) FILTER(WHERE severity = 'low') AS mttr_l
			FROM findings
			WHERE resolved_at >= CURRENT_DATE - 30
			GROUP BY tenant_id
		),
		exposure_metrics AS (
			SELECT tenant_id, COUNT(*) AS active_count
			FROM exposure_events WHERE state = 'active'
			GROUP BY tenant_id
		)
		INSERT INTO risk_snapshots (
			tenant_id, snapshot_date,
			risk_score_avg, risk_score_max,
			findings_open, findings_closed_today,
			exposures_active, sla_compliance_pct,
			mttr_critical_hours, mttr_high_hours, mttr_medium_hours, mttr_low_hours,
			p0_open, p1_open, p2_open, p3_open,
			asset_ownership_pct, created_at
		)
		SELECT
			t.id, $1::date,
			COALESCE(a.avg_risk, 0), COALESCE(a.max_risk, 0),
			COALESCE(f.open_count, 0), COALESCE(f.closed_today, 0),
			COALESCE(e.active_count, 0), COALESCE(f.sla_pct, 100),
			m.mttr_c, m.mttr_h, m.mttr_m, m.mttr_l,
			COALESCE(f.p0, 0), COALESCE(f.p1, 0), COALESCE(f.p2, 0), COALESCE(f.p3, 0),
			COALESCE(a.ownership_pct, 0), NOW()
		FROM tenants t
		LEFT JOIN asset_metrics a ON a.tenant_id = t.id
		LEFT JOIN finding_metrics f ON f.tenant_id = t.id
		LEFT JOIN mttr_metrics m ON m.tenant_id = t.id
		LEFT JOIN exposure_metrics e ON e.tenant_id = t.id
		ON CONFLICT (tenant_id, snapshot_date)
		DO UPDATE SET
			risk_score_avg = EXCLUDED.risk_score_avg,
			risk_score_max = EXCLUDED.risk_score_max,
			findings_open = EXCLUDED.findings_open,
			findings_closed_today = EXCLUDED.findings_closed_today,
			exposures_active = EXCLUDED.exposures_active,
			sla_compliance_pct = EXCLUDED.sla_compliance_pct,
			mttr_critical_hours = EXCLUDED.mttr_critical_hours,
			mttr_high_hours = EXCLUDED.mttr_high_hours,
			mttr_medium_hours = EXCLUDED.mttr_medium_hours,
			mttr_low_hours = EXCLUDED.mttr_low_hours,
			p0_open = EXCLUDED.p0_open,
			p1_open = EXCLUDED.p1_open,
			p2_open = EXCLUDED.p2_open,
			p3_open = EXCLUDED.p3_open,
			asset_ownership_pct = EXCLUDED.asset_ownership_pct
	`

	result, err := c.db.ExecContext(ctx, query, today)
	if err != nil {
		return 0, fmt.Errorf("risk snapshot: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows > 0 {
		c.logger.Info("risk snapshots computed", "tenants", rows, "date", today)
	}
	return int(rows), nil
}
