package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// AIUseCaseDowngrader falls AI use cases back from auto-apply to suggest when
// people overrode too many of their results
// (tenantai.Service.SweepUseCaseDowngrades).
type AIUseCaseDowngrader interface {
	SweepUseCaseDowngrades(ctx context.Context) (int, error)
}

// AIUseCaseDowngradeController runs the automatic downgrade of AI use cases
// (docs/architecture/ai-use-cases.md).
type AIUseCaseDowngradeController struct {
	service  AIUseCaseDowngrader
	interval time.Duration
	logger   *logger.Logger
}

// NewAIUseCaseDowngradeController creates the controller.
func NewAIUseCaseDowngradeController(service AIUseCaseDowngrader, interval time.Duration, log *logger.Logger) *AIUseCaseDowngradeController {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &AIUseCaseDowngradeController{service: service, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *AIUseCaseDowngradeController) Name() string { return "ai-use-case-downgrade" }

// Interval returns the reconciliation interval.
func (c *AIUseCaseDowngradeController) Interval() time.Duration { return c.interval }

// Reconcile runs one sweep.
func (c *AIUseCaseDowngradeController) Reconcile(ctx context.Context) (int, error) {
	if c.service == nil {
		return 0, nil
	}
	n, err := c.service.SweepUseCaseDowngrades(ctx)
	if err != nil {
		c.logger.Error("AI use case downgrade sweep failed", "error", err)
		return 0, err
	}
	if n > 0 {
		c.logger.Info("AI use cases fell back to suggest", "count", n)
	}
	return n, nil
}
