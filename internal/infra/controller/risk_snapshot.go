package controller

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// RiskSnapshotController computes daily risk snapshots for all tenants.
// Runs every 6 hours, but only inserts one row per tenant per day.
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
func (c *RiskSnapshotController) Reconcile(ctx context.Context) (int, error) {
	today := time.Now().Format("2006-01-02")

	// Single query: compute all metrics per tenant and upsert
	query := `
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
			t.id,
			$1::date,
			-- Risk scores from assets
			COALESCE((SELECT AVG(risk_score) FROM assets WHERE tenant_id = t.id AND risk_score > 0), 0),
			COALESCE((SELECT MAX(risk_score) FROM assets WHERE tenant_id = t.id), 0),
			-- Finding counts
			COALESCE((SELECT COUNT(*) FROM findings WHERE tenant_id = t.id
				AND status NOT IN ('closed','resolved','false_positive','verified')), 0),
			COALESCE((SELECT COUNT(*) FROM findings WHERE tenant_id = t.id
				AND resolved_at >= CURRENT_DATE AND resolved_at < CURRENT_DATE + 1), 0),
			-- Exposures
			COALESCE((SELECT COUNT(*) FROM exposure_events WHERE tenant_id = t.id
				AND state = 'active'), 0),
			-- SLA compliance (% of findings with sla_status != 'breached')
			COALESCE((
				SELECT CASE WHEN COUNT(*) = 0 THEN 100
					ELSE COUNT(*) FILTER(WHERE sla_status != 'breached') * 100.0 / COUNT(*)
				END
				FROM findings WHERE tenant_id = t.id
				AND sla_deadline IS NOT NULL
				AND status NOT IN ('closed','resolved','false_positive','verified')
			), 100),
			-- MTTR by severity (hours, from findings resolved in last 30 days)
			(SELECT AVG(EXTRACT(epoch FROM resolved_at - first_detected_at)/3600)
				FROM findings WHERE tenant_id = t.id AND severity = 'critical'
				AND resolved_at >= CURRENT_DATE - 30),
			(SELECT AVG(EXTRACT(epoch FROM resolved_at - first_detected_at)/3600)
				FROM findings WHERE tenant_id = t.id AND severity = 'high'
				AND resolved_at >= CURRENT_DATE - 30),
			(SELECT AVG(EXTRACT(epoch FROM resolved_at - first_detected_at)/3600)
				FROM findings WHERE tenant_id = t.id AND severity = 'medium'
				AND resolved_at >= CURRENT_DATE - 30),
			(SELECT AVG(EXTRACT(epoch FROM resolved_at - first_detected_at)/3600)
				FROM findings WHERE tenant_id = t.id AND severity = 'low'
				AND resolved_at >= CURRENT_DATE - 30),
			-- Priority class distribution
			COALESCE((SELECT COUNT(*) FROM findings WHERE tenant_id = t.id
				AND priority_class = 'P0' AND status NOT IN ('closed','resolved','false_positive','verified')), 0),
			COALESCE((SELECT COUNT(*) FROM findings WHERE tenant_id = t.id
				AND priority_class = 'P1' AND status NOT IN ('closed','resolved','false_positive','verified')), 0),
			COALESCE((SELECT COUNT(*) FROM findings WHERE tenant_id = t.id
				AND priority_class = 'P2' AND status NOT IN ('closed','resolved','false_positive','verified')), 0),
			COALESCE((SELECT COUNT(*) FROM findings WHERE tenant_id = t.id
				AND priority_class = 'P3' AND status NOT IN ('closed','resolved','false_positive','verified')), 0),
			-- Asset ownership %
			COALESCE((
				SELECT CASE WHEN COUNT(*) = 0 THEN 0
					ELSE COUNT(*) FILTER(WHERE owner_id IS NOT NULL) * 100.0 / COUNT(*)
				END FROM assets WHERE tenant_id = t.id
			), 0),
			NOW()
		FROM tenants t
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
