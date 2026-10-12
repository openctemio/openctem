package controller

import (
	"context"
	"errors"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/attachment"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AttachmentScanner scans pending attachments for malware
// (api/docs/architecture/file-storage.md, "Malware scanning").
type AttachmentScanner interface {
	ScanPending(ctx context.Context) (int, error)
}

// AttachmentScanController runs the malware scan of new uploads when a
// scanner (STORAGE_CLAMD_ADDRESS) is configured.
type AttachmentScanController struct {
	scanner  AttachmentScanner
	interval time.Duration
	logger   *logger.Logger
}

// NewAttachmentScanController builds the controller (interval 0 = 30 s).
func NewAttachmentScanController(s AttachmentScanner, interval time.Duration, log *logger.Logger) *AttachmentScanController {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &AttachmentScanController{scanner: s, interval: interval, logger: log}
}

// Name returns the controller name.
func (c *AttachmentScanController) Name() string { return "attachment-malware-scan" }

// Interval returns the reconciliation interval.
func (c *AttachmentScanController) Interval() time.Duration { return c.interval }

// Exclusive: one replica scans at a time, so a file is scanned once.
func (c *AttachmentScanController) Exclusive() bool { return true }

// ReconcileTimeout covers one batch of scans.
func (c *AttachmentScanController) ReconcileTimeout() time.Duration { return 10 * time.Minute }

// Reconcile scans one batch. An unreachable scanner is logged, not failed:
// the files stay pending and the next tick retries.
func (c *AttachmentScanController) Reconcile(ctx context.Context) (int, error) {
	n, err := c.scanner.ScanPending(ctx)
	if errors.Is(err, attachment.ErrScannerUnavailable) {
		return n, nil
	}
	if err != nil {
		c.logger.Error("attachment malware scan failed", "error", logger.SanitizeError(err))
	}
	return n, err
}
