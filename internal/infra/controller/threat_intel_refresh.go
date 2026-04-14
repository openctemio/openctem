package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/logger"
)

// ThreatIntelRefreshController periodically refreshes EPSS scores and KEV catalog.
// Runs every 24 hours. Fetches latest data from FIRST.org (EPSS) and CISA (KEV).
type ThreatIntelRefreshController struct {
	refresher *app.ThreatIntelRefresher
	logger    *logger.Logger
}

// NewThreatIntelRefreshController creates a new controller.
func NewThreatIntelRefreshController(refresher *app.ThreatIntelRefresher, log *logger.Logger) *ThreatIntelRefreshController {
	return &ThreatIntelRefreshController{refresher: refresher, logger: log}
}

// Name returns the controller name.
func (c *ThreatIntelRefreshController) Name() string { return "threat-intel-refresh" }

// Interval returns 24 hours — daily refresh.
func (c *ThreatIntelRefreshController) Interval() time.Duration { return 24 * time.Hour }

// Reconcile fetches latest EPSS + KEV data.
func (c *ThreatIntelRefreshController) Reconcile(ctx context.Context) (int, error) {
	processed := 0

	// Fetch EPSS scores
	epss, err := c.refresher.FetchEPSSScores(ctx)
	if err != nil {
		c.logger.Warn("EPSS refresh failed", "error", err)
	} else {
		processed += len(epss)
		c.logger.Info("EPSS scores refreshed", "count", len(epss))
	}

	// Fetch KEV catalog
	kev, err := c.refresher.FetchKEVCatalog(ctx)
	if err != nil {
		c.logger.Warn("KEV refresh failed", "error", err)
	} else {
		processed += len(kev)
		c.logger.Info("KEV catalog refreshed", "count", len(kev))
	}

	return processed, nil
}
