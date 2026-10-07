package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// EvidenceSweeper deletes expired evidence secrets and old evidence.
type EvidenceSweeper interface {
	Sweep(ctx context.Context) error
}

// EvidenceRetentionController runs the finding-evidence retention sweep
// (docs/architecture/finding-evidence.md): encrypted secret values past
// their tenant's secret retention, and evidence records past the platform
// retention, are deleted.
type EvidenceRetentionController struct {
	sweeper  EvidenceSweeper
	interval time.Duration
	logger   *logger.Logger
}

// NewEvidenceRetentionController builds the controller (interval 0 = 1 h).
func NewEvidenceRetentionController(s EvidenceSweeper, interval time.Duration, log *logger.Logger) *EvidenceRetentionController {
	if interval <= 0 {
		interval = time.Hour
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &EvidenceRetentionController{sweeper: s, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *EvidenceRetentionController) Name() string { return "finding-evidence-retention" }

// Interval returns the reconciliation interval.
func (c *EvidenceRetentionController) Interval() time.Duration { return c.interval }

// Reconcile runs one sweep.
func (c *EvidenceRetentionController) Reconcile(ctx context.Context) (int, error) {
	if err := c.sweeper.Sweep(ctx); err != nil {
		c.logger.Error("finding evidence retention sweep failed", "error", logger.SanitizeError(err))
		return 0, err
	}
	return 0, nil
}
