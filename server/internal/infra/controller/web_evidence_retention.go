package controller

// Web evidence retention (docs/rfcs/RFC-081-web-evidence-screenshots.md):
// screenshots after 30 days, files of deleted rows, capture text after a year.

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// WebEvidenceSweeper deletes expired web evidence.
type WebEvidenceSweeper interface {
	Sweep(ctx context.Context) (int, error)
}

// WebEvidenceRetentionController runs the sweep hourly.
type WebEvidenceRetentionController struct {
	sweeper  WebEvidenceSweeper
	interval time.Duration
	logger   *logger.Logger
}

// NewWebEvidenceRetentionController creates the controller (interval 0 = 1h).
func NewWebEvidenceRetentionController(s WebEvidenceSweeper, interval time.Duration, log *logger.Logger) *WebEvidenceRetentionController {
	if interval <= 0 {
		interval = time.Hour
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &WebEvidenceRetentionController{sweeper: s, interval: interval, logger: log.With("controller", "web-evidence-retention")}
}

// Name implements Controller.
func (c *WebEvidenceRetentionController) Name() string { return "web-evidence-retention" }

// Interval implements Controller.
func (c *WebEvidenceRetentionController) Interval() time.Duration { return c.interval }

// Reconcile implements Controller. Returns how many files were deleted.
func (c *WebEvidenceRetentionController) Reconcile(ctx context.Context) (int, error) {
	if c.sweeper == nil {
		return 0, nil
	}
	return c.sweeper.Sweep(ctx)
}
