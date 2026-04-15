package controller

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// SLAEscalationController periodically checks for overdue findings
// and updates their sla_status to 'breached'. Runs every 15 minutes.
//
// RFC-005 Gap 7: Automated SLA Escalation.
type SLAEscalationController struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewSLAEscalationController creates a new SLA escalation controller.
func NewSLAEscalationController(db *sql.DB, log *logger.Logger) *SLAEscalationController {
	return &SLAEscalationController{
		db:     db,
		logger: log,
	}
}

// Name returns the controller name.
func (c *SLAEscalationController) Name() string { return "sla-escalation" }

// Interval returns 15 minutes.
func (c *SLAEscalationController) Interval() time.Duration { return 15 * time.Minute }

// Reconcile checks for overdue findings and marks them as breached.
func (c *SLAEscalationController) Reconcile(ctx context.Context) (int, error) {
	// Find findings past SLA deadline that aren't already breached
	query := `
		UPDATE findings SET
			sla_status = 'breached',
			updated_at = NOW()
		WHERE sla_deadline < NOW()
		  AND sla_deadline IS NOT NULL
		  AND (sla_status IS NULL OR sla_status NOT IN ('breached', 'not_applicable'))
		  AND status NOT IN ('closed', 'resolved', 'false_positive', 'verified')
	`

	result, err := c.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("sla escalation: %w", err)
	}

	breached, _ := result.RowsAffected()
	if breached > 0 {
		c.logger.Warn("SLA breached findings detected",
			"count", breached,
		)
	}

	// Also mark findings approaching deadline as warning
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

	return int(breached), nil
}
