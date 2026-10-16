package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/internal/app/versioncheck"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// VersionCheckController runs the version check when it is due
// (docs/rfcs/RFC-105-version-check-and-usage-telemetry.md). It wakes every
// hour; the service decides from the shared state whether a check is due
// (daily with jitter, weekly after repeated failures) and which replica
// fetches. Fail-open: an offline instance only records the failure.
type VersionCheckController struct {
	service *versioncheck.Service
	logger  *logger.Logger
}

// NewVersionCheckController creates the controller.
func NewVersionCheckController(service *versioncheck.Service, log *logger.Logger) *VersionCheckController {
	return &VersionCheckController{service: service, logger: log}
}

// Name returns the controller name.
func (c *VersionCheckController) Name() string { return "version-check" }

// Interval returns how often the controller looks whether a check is due.
func (c *VersionCheckController) Interval() time.Duration { return time.Hour }

// Reconcile runs a due check. A storage error is logged, never fatal.
func (c *VersionCheckController) Reconcile(ctx context.Context) (int, error) {
	if c.service == nil {
		return 0, nil
	}
	if err := c.service.RunDue(ctx); err != nil {
		c.logger.Warn("version check failed", "error", err)
	}
	return 0, nil
}
