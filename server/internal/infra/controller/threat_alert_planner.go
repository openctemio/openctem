package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/app/threatalert"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// threatAlertBudget is how long one planner pass may run; work left over
// continues on the next tick.
const threatAlertBudget = 2 * time.Minute

// ThreatAlertPlannerController plans and delivers emerging-threat alerts
// (docs/rfcs/RFC-117-emerging-threat-alerts.md): vulnerability events and
// matched findings to alerts, pending immediate messages, daily digests.
type ThreatAlertPlannerController struct {
	planner *threatalert.Planner
	logger  *logger.Logger
}

// NewThreatAlertPlannerController creates the controller.
func NewThreatAlertPlannerController(p *threatalert.Planner, log *logger.Logger) *ThreatAlertPlannerController {
	return &ThreatAlertPlannerController{planner: p, logger: log}
}

// Name returns the controller name.
func (c *ThreatAlertPlannerController) Name() string { return "threat-alert-planner" }

// Interval: every minute, so an urgent alert leaves within minutes of its
// event and the digest goes at the organization's hour.
func (c *ThreatAlertPlannerController) Interval() time.Duration { return time.Minute }

// ReconcileTimeout leaves room for the budget.
func (c *ThreatAlertPlannerController) ReconcileTimeout() time.Duration {
	return threatAlertBudget + time.Minute
}

// Exclusive: one replica plans (two would send the same message twice).
func (c *ThreatAlertPlannerController) Exclusive() bool { return true }

// Reconcile runs one pass.
func (c *ThreatAlertPlannerController) Reconcile(ctx context.Context) (int, error) {
	st, err := c.planner.Run(ctx, threatAlertBudget)
	if st.Events > 0 || st.Planned > 0 || st.Baselined > 0 || st.Immediate > 0 || st.Digests > 0 {
		c.logger.Info("emerging-threat alerts", "events", st.Events, "planned", st.Planned, "baselined", st.Baselined,
			"immediate", st.Immediate, "digests", st.Digests)
	}
	if err != nil {
		c.logger.Warn("emerging-threat planning failed", "error", err)
	}
	return st.Planned + st.Immediate + st.Digests, nil
}
