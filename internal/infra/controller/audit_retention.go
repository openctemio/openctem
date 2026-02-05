package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/logger"
)

// AuditRetentionControllerConfig configures the AuditRetentionController.
type AuditRetentionControllerConfig struct {
	// Interval is how often to run the retention check.
	// Default: 24 hours (once a day).
	Interval time.Duration

	// RetentionDays is how long to keep audit logs.
	// Logs older than this will be deleted.
	// Default: 365 days (1 year).
	RetentionDays int

	// BatchSize is the maximum number of logs to delete in one batch.
	// This prevents long-running transactions.
	// Default: 10000.
	BatchSize int

	// DryRun if true, only counts logs that would be deleted without actually deleting.
	// Useful for testing retention policies.
	// Default: false.
	DryRun bool

	// Logger for logging.
	Logger *logger.Logger
}

// AuditRetentionController manages audit log retention.
// This is a compliance-critical controller that:
// 1. Deletes audit logs older than the retention period
// 2. Logs deletion activities for meta-audit purposes
//
// The retention period should be configured based on compliance requirements:
// - GDPR: Typically 2-7 years depending on data type
// - SOC 2: At least 1 year
// - PCI DSS: At least 1 year
// - HIPAA: 6 years
//
// IMPORTANT: Ensure proper backup before running this controller.
// Deleted audit logs cannot be recovered.
type AuditRetentionController struct {
	auditRepo admin.AuditLogRepository
	config    *AuditRetentionControllerConfig
	logger    *logger.Logger
}

// NewAuditRetentionController creates a new AuditRetentionController.
func NewAuditRetentionController(
	auditRepo admin.AuditLogRepository,
	config *AuditRetentionControllerConfig,
) *AuditRetentionController {
	if config == nil {
		config = &AuditRetentionControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 24 * time.Hour
	}
	if config.RetentionDays == 0 {
		config.RetentionDays = 365 // 1 year default
	}
	if config.BatchSize == 0 {
		config.BatchSize = 10000
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}

	return &AuditRetentionController{
		auditRepo: auditRepo,
		config:    config,
		logger:    config.Logger,
	}
}

// Name returns the controller name.
func (c *AuditRetentionController) Name() string {
	return "audit-retention"
}

// Interval returns the reconciliation interval.
func (c *AuditRetentionController) Interval() time.Duration {
	return c.config.Interval
}

// Reconcile deletes audit logs older than the retention period.
func (c *AuditRetentionController) Reconcile(ctx context.Context) (int, error) {
	cutoffTime := time.Now().AddDate(0, 0, -c.config.RetentionDays)

	// First, count how many logs would be affected
	count, err := c.auditRepo.CountOlderThan(ctx, cutoffTime)
	if err != nil {
		c.logger.Error("failed to count old audit logs",
			"error", err,
			"cutoff_time", cutoffTime,
		)
		return 0, err
	}

	if count == 0 {
		return 0, nil
	}

	c.logger.Info("found audit logs for retention cleanup",
		"count", count,
		"cutoff_time", cutoffTime,
		"retention_days", c.config.RetentionDays,
		"dry_run", c.config.DryRun,
	)

	// If dry run, just return the count
	if c.config.DryRun {
		c.logger.Info("dry run - would delete audit logs",
			"count", count,
		)
		return int(count), nil
	}

	// Delete old logs
	deleted, err := c.auditRepo.DeleteOlderThan(ctx, cutoffTime)
	if err != nil {
		c.logger.Error("failed to delete old audit logs",
			"error", err,
			"cutoff_time", cutoffTime,
		)
		return 0, err
	}

	c.logger.Info("deleted old audit logs",
		"count", deleted,
		"cutoff_time", cutoffTime,
		"retention_days", c.config.RetentionDays,
	)

	return int(deleted), nil
}
