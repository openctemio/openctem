package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// DeletedAssetPurger is the part of the asset repository the purge needs.
type DeletedAssetPurger interface {
	PurgeDeleted(ctx context.Context, before time.Time, limit int) (int, error)
}

// AssetPurgeConfig configures AssetPurgeController.
type AssetPurgeConfig struct {
	// Interval between runs (default 24h).
	Interval time.Duration
	// RetentionDays: soft-deleted assets older than this are purged
	// (default 30).
	RetentionDays int
	// BatchSize bounds one delete statement (default 500); a run purges
	// batches until one is not full, at most MaxBatches (default 20).
	BatchSize  int
	MaxBatches int
	Logger     *logger.Logger
}

// AssetPurgeController hard-deletes assets a person deleted (soft delete,
// owner decision O3) once the retention period is over. Only assets without
// findings are ever soft-deleted, and the purge skips any that gained one
// since (findings.asset_id is ON DELETE NO ACTION, so a purge can never take
// findings with it either).
type AssetPurgeController struct {
	repo   DeletedAssetPurger
	config *AssetPurgeConfig
	logger *logger.Logger
	now    func() time.Time
}

// NewAssetPurgeController builds the controller with defaults for zero-valued
// settings.
func NewAssetPurgeController(repo DeletedAssetPurger, config *AssetPurgeConfig) *AssetPurgeController {
	if config == nil {
		config = &AssetPurgeConfig{}
	}
	if config.Interval <= 0 {
		config.Interval = 24 * time.Hour
	}
	if config.RetentionDays <= 0 {
		config.RetentionDays = 30
	}
	if config.BatchSize <= 0 {
		config.BatchSize = 500
	}
	if config.MaxBatches <= 0 {
		config.MaxBatches = 20
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}
	return &AssetPurgeController{repo: repo, config: config, logger: config.Logger, now: time.Now}
}

// Name returns the controller name.
func (c *AssetPurgeController) Name() string { return "asset-purge" }

// Interval returns the reconciliation interval.
func (c *AssetPurgeController) Interval() time.Duration { return c.config.Interval }

// Reconcile purges soft-deleted assets past the retention period, in batches.
func (c *AssetPurgeController) Reconcile(ctx context.Context) (int, error) {
	cutoff := c.now().AddDate(0, 0, -c.config.RetentionDays)
	total := 0
	for i := 0; i < c.config.MaxBatches; i++ {
		n, err := c.repo.PurgeDeleted(ctx, cutoff, c.config.BatchSize)
		if err != nil {
			c.logger.Error("failed to purge deleted assets", "error", err, "cutoff", cutoff)
			return total, err
		}
		total += n
		if n < c.config.BatchSize {
			break
		}
	}
	if total > 0 {
		c.logger.Info("purged deleted assets", "count", total, "cutoff", cutoff)
	}
	return total, nil
}

// Exclusive: it runs on one API replica at a time (controller lease, RFC-046
// P1.8); two replicas sweeping at once would delete or fetch twice.
func (c *AssetPurgeController) Exclusive() bool { return true }
