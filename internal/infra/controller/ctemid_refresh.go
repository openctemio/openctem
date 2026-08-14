package controller

import (
	"context"
	"time"

	ctemidapp "github.com/openctemio/api/internal/app/ctemid"
	"github.com/openctemio/api/pkg/logger"
)

// CTEMIDRefreshController periodically mirrors the CTEM-ID catalog from its
// external JSON feed into local reference storage, mirroring the threat-intel
// (EPSS/KEV) daily refresh. It is fail-open: a feed outage is logged and the
// reconcile returns success so the controller manager does not treat a transient
// upstream failure as a controller error.
type CTEMIDRefreshController struct {
	service *ctemidapp.Service
	logger  *logger.Logger
}

// NewCTEMIDRefreshController creates the controller.
func NewCTEMIDRefreshController(service *ctemidapp.Service, log *logger.Logger) *CTEMIDRefreshController {
	return &CTEMIDRefreshController{service: service, logger: log}
}

// Name returns the controller name.
func (c *CTEMIDRefreshController) Name() string { return "ctem-id-refresh" }

// Interval returns 24 hours — daily refresh, matching threat-intel.
func (c *CTEMIDRefreshController) Interval() time.Duration { return 24 * time.Hour }

// Reconcile fetches and persists the latest CTEM-ID catalog. Fail-open.
func (c *CTEMIDRefreshController) Reconcile(ctx context.Context) (int, error) {
	if c.service == nil {
		return 0, nil
	}
	n, err := c.service.SyncCatalog(ctx)
	if err != nil {
		c.logger.Warn("ctem-id catalog refresh failed", "error", err)
		return 0, nil
	}
	if n > 0 {
		c.logger.Info("ctem-id catalog refreshed", "records", n)
	}
	return n, nil
}
