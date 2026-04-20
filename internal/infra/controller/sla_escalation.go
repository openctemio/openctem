package controller

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// SLABreachEvent is emitted once per finding on the transition into
// the `breached` SLA state. Downstream consumers (notification outbox,
// Jira commenter, PagerDuty router) subscribe via the publisher.
//
// B4 (Q1/WS-E): closes the feedback edge where SLA status was
// previously computed but never acted on. Dedup via the SLA breach
// transition itself — a second controller run won't re-emit because
// rows already in `breached` state don't match the UPDATE WHERE clause.
type SLABreachEvent struct {
	TenantID        shared.ID
	FindingID       shared.ID
	SLADeadline     time.Time
	OverdueDuration time.Duration
	At              time.Time
}

// SLABreachPublisher delivers breach events to downstream consumers.
// Optional — nil publisher means "log only" (legacy behaviour).
type SLABreachPublisher interface {
	Publish(ctx context.Context, event SLABreachEvent) error
}

// SLAEscalationController periodically checks for overdue findings
// and updates their sla_status to 'breached'. Runs every 15 minutes.
//
// Note: This operates across all tenants intentionally — it's a system-level
// background job that marks overdue findings within their own rows.
// Each finding's tenant_id remains unchanged.
//
// RFC-005 Gap 7 + B4 (Q1/WS-E): Automated SLA Escalation with publisher.
type SLAEscalationController struct {
	db     *sql.DB
	logger *logger.Logger
	// B4: optional publisher that fires one event per newly-breached
	// finding. Nil → legacy log-only behaviour.
	publisher SLABreachPublisher
}

// NewSLAEscalationController creates a new SLA escalation controller.
func NewSLAEscalationController(db *sql.DB, log *logger.Logger) *SLAEscalationController {
	return &SLAEscalationController{
		db:     db,
		logger: log,
	}
}

// SetBreachPublisher wires the breach-event publisher. Safe after
// construction; nil disables publishing.
func (c *SLAEscalationController) SetBreachPublisher(p SLABreachPublisher) {
	c.publisher = p
}

// Name returns the controller name.
func (c *SLAEscalationController) Name() string { return "sla-escalation" }

// Interval returns 15 minutes.
func (c *SLAEscalationController) Interval() time.Duration { return 15 * time.Minute }

// Reconcile checks for overdue findings and marks them as breached.
//
// B4: For every row newly-transitioned into `breached`, a SLABreachEvent
// is emitted via the publisher. Dedup is structural — the WHERE clause
// excludes rows already in `breached`, so a second run won't re-emit.
func (c *SLAEscalationController) Reconcile(ctx context.Context) (int, error) {
	// Mark overdue findings as breached (operates on individual rows,
	// tenant_id unchanged). RETURNING carries the fields the publisher
	// needs — no second query.
	breachQuery := `
		UPDATE findings SET
			sla_status = 'breached',
			updated_at = NOW()
		WHERE sla_deadline < NOW()
		  AND sla_deadline IS NOT NULL
		  AND (sla_status IS NULL OR sla_status NOT IN ('breached', 'not_applicable'))
		  AND status NOT IN ('closed', 'resolved', 'false_positive', 'verified')
		RETURNING tenant_id, id, sla_deadline
	`

	rows, err := c.db.QueryContext(ctx, breachQuery)
	if err != nil {
		return 0, fmt.Errorf("sla escalation: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type breachRow struct {
		tenantID    string
		findingID   string
		slaDeadline time.Time
	}
	var breaches []breachRow
	breachedByTenant := make(map[string]int)
	for rows.Next() {
		var br breachRow
		if err := rows.Scan(&br.tenantID, &br.findingID, &br.slaDeadline); err != nil {
			c.logger.Warn("scan breach row", "error", err)
			continue
		}
		breaches = append(breaches, br)
		breachedByTenant[br.tenantID]++
	}
	total := len(breaches)

	for tid, count := range breachedByTenant {
		c.logger.Warn("SLA breached findings detected",
			"tenant_id", tid, "count", count,
		)
	}

	// B4: fire one event per breached finding. Publisher errors are
	// logged but do not fail the reconcile — escalation is advisory.
	if c.publisher != nil {
		now := time.Now().UTC()
		for _, br := range breaches {
			tid, err := shared.IDFromString(br.tenantID)
			if err != nil {
				continue
			}
			fid, err := shared.IDFromString(br.findingID)
			if err != nil {
				continue
			}
			ev := SLABreachEvent{
				TenantID:        tid,
				FindingID:       fid,
				SLADeadline:     br.slaDeadline,
				OverdueDuration: now.Sub(br.slaDeadline),
				At:              now,
			}
			if err := c.publisher.Publish(ctx, ev); err != nil {
				c.logger.Warn("sla breach publish failed",
					"finding_id", br.findingID, "error", err)
			}
		}
	}

	// Mark findings approaching deadline (within 3 days) as warning
	warningQuery := `
		UPDATE findings SET
			sla_status = 'warning',
			updated_at = NOW()
		WHERE sla_deadline IS NOT NULL
		  AND sla_deadline > NOW()
		  AND sla_deadline < NOW() + INTERVAL '3 days'
		  AND (sla_status IS NULL OR sla_status = 'on_track')
		  AND status NOT IN ('closed', 'resolved', 'false_positive', 'verified')
	`

	warningResult, err := c.db.ExecContext(ctx, warningQuery)
	if err != nil {
		c.logger.Warn("sla warning update failed", "error", err)
	} else {
		warned, _ := warningResult.RowsAffected()
		if warned > 0 {
			c.logger.Info("SLA warning findings updated", "count", warned)
		}
	}

	return total, nil
}
