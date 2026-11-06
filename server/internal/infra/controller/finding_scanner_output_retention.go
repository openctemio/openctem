package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScannerOutputRetentionStore is the part of the finding repository the
// scanner output retention controller needs.
type ScannerOutputRetentionStore interface {
	ClearScannerOutputClosedBefore(ctx context.Context, before time.Time, limit int) (int64, error)
}

// ScannerOutputRetentionConfig configures ScannerOutputRetentionController.
type ScannerOutputRetentionConfig struct {
	// Interval between runs (default 24h).
	Interval time.Duration
	// RetentionDays after a finding was closed (default 365, owner decision C9).
	RetentionDays int
	// BatchSize bounds one UPDATE (default 2000); a run stops after MaxBatches
	// (default 25) or the first batch that is not full.
	BatchSize  int
	MaxBatches int
	Logger     *logger.Logger
}

// ScannerOutputRetentionController drops the scanner output (plugin output)
// of findings closed more than RetentionDays ago (research 24 P0-2, owner
// decision C9). The finding itself is kept; only the bulky, untrusted text
// goes, which keeps the disk in check.
type ScannerOutputRetentionController struct {
	repo   ScannerOutputRetentionStore
	config *ScannerOutputRetentionConfig
	logger *logger.Logger
	now    func() time.Time
}

// NewScannerOutputRetentionController builds the controller with defaults
// for zero-valued settings.
func NewScannerOutputRetentionController(repo ScannerOutputRetentionStore, config *ScannerOutputRetentionConfig) *ScannerOutputRetentionController {
	if config == nil {
		config = &ScannerOutputRetentionConfig{}
	}
	if config.Interval <= 0 {
		config.Interval = 24 * time.Hour
	}
	if config.RetentionDays <= 0 {
		config.RetentionDays = vulnerability.ScannerOutputRetentionDays
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 2000
	}
	if config.MaxBatches <= 0 {
		config.MaxBatches = 25
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}
	return &ScannerOutputRetentionController{repo: repo, config: config, logger: config.Logger, now: time.Now}
}

// Name returns the controller name.
func (c *ScannerOutputRetentionController) Name() string { return "finding-scanner-output-retention" }

// Interval returns the reconciliation interval.
func (c *ScannerOutputRetentionController) Interval() time.Duration { return c.config.Interval }

// Reconcile clears expired scanner output, in batches.
func (c *ScannerOutputRetentionController) Reconcile(ctx context.Context) (int, error) {
	cutoff := c.now().AddDate(0, 0, -c.config.RetentionDays)
	var total int64
	for i := 0; i < c.config.MaxBatches; i++ {
		n, err := c.repo.ClearScannerOutputClosedBefore(ctx, cutoff, c.config.BatchSize)
		if err != nil {
			c.logger.Error("failed to clear expired scanner output", "error", err, "cutoff", cutoff)
			return int(total), err
		}
		total += n
		if n < int64(c.config.BatchSize) {
			break
		}
	}
	if total > 0 {
		c.logger.Info("cleared expired scanner output", "count", total, "cutoff", cutoff,
			"retention_days", c.config.RetentionDays)
	}
	return int(total), nil
}

// Exclusive: one API replica at a time (controller lease, RFC-046 P1.8).
func (c *ScannerOutputRetentionController) Exclusive() bool { return true }
