package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/logger"
)

// ThreatIntelRefreshController periodically refreshes EPSS scores and KEV catalog.
// Runs every 24 hours. Fetches latest data from FIRST.org (EPSS) and CISA (KEV),
// then persists to database via ThreatIntelService.SyncAll().
type ThreatIntelRefreshController struct {
	service *app.ThreatIntelService
	logger  *logger.Logger
}

// NewThreatIntelRefreshController creates a new controller.
func NewThreatIntelRefreshController(service *app.ThreatIntelService, log *logger.Logger) *ThreatIntelRefreshController {
	return &ThreatIntelRefreshController{service: service, logger: log}
}

// Name returns the controller name.
func (c *ThreatIntelRefreshController) Name() string { return "threat-intel-refresh" }

// Interval returns 24 hours — daily refresh.
func (c *ThreatIntelRefreshController) Interval() time.Duration { return 24 * time.Hour }

// Reconcile fetches and persists latest EPSS + KEV data.
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

	return processed, nil
}
