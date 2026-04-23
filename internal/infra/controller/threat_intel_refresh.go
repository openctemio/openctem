package controller

import (
	"github.com/openctemio/api/internal/app/threat"
	"context"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// ThreatIntelRefreshController periodically refreshes EPSS scores and KEV catalog.
// Runs every 24 hours. Fetches latest data from FIRST.org (EPSS) and CISA (KEV),
// then persists to database via ThreatIntelService.SyncAll().
// After sync, auto-escalates findings whose CVEs appear in the KEV catalog.
type ThreatIntelRefreshController struct {
	service   *threat.IntelService
	escalator threat.KEVEscalator
	logger    *logger.Logger
}

// NewThreatIntelRefreshController creates a new controller.
func NewThreatIntelRefreshController(service *threat.IntelService, escalator threat.KEVEscalator, log *logger.Logger) *ThreatIntelRefreshController {
	return &ThreatIntelRefreshController{service: service, escalator: escalator, logger: log}
}

// Name returns the controller name.
func (c *ThreatIntelRefreshController) Name() string { return "threat-intel-refresh" }

// Interval returns 24 hours — daily refresh.
func (c *ThreatIntelRefreshController) Interval() time.Duration { return 24 * time.Hour }

// Reconcile fetches and persists latest EPSS + KEV data, then auto-escalates findings.
func (c *ThreatIntelRefreshController) Reconcile(ctx context.Context) (int, error) {
	results := c.service.SyncAll(ctx)

	processed := 0
	for _, r := range results {
		if r.Error != nil {
			c.logger.Warn("threat intel sync failed", "source", r.Source, "error", r.Error)
		} else {
			processed += r.RecordsSynced
			c.logger.Info("threat intel synced", "source", r.Source, "records", r.RecordsSynced, "duration_ms", r.DurationMs)
		}
	}

	// After KEV sync, auto-escalate findings with CVEs in the KEV catalog
	if c.escalator != nil {
		escalated, err := c.escalator.EscalateKEVFindings(ctx)
		if err != nil {
			c.logger.Warn("KEV auto-escalation failed", "error", err)
		} else if escalated > 0 {
			c.logger.Info("KEV auto-escalation completed", "findings_escalated", escalated)
			processed += escalated
		}
	}

	return processed, nil
}
