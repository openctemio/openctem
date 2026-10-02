package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/scope"
	"github.com/openctemio/api/pkg/domain/suppression"
	"github.com/openctemio/api/pkg/logger"
)

// DataExpirationControllerConfig configures the DataExpirationController.
type DataExpirationControllerConfig struct {
	// Interval is how often to run the expiration check.
	// Default: 1 hour.
	Interval time.Duration

	// AuditRetentionDays is how long to keep audit logs.
	// Logs older than this will be deleted.
	// Default: 365 days (1 year).
	AuditRetentionDays int

	// Logger for logging.
	Logger *logger.Logger
}

// DataExpirationController handles periodic expiration of stale data:
//   - Suppression rules past their expires_at
//   - Scope exclusions past their expires_at
//   - Audit logs older than the retention period
//
// Without this controller, expired suppression rules and scope exclusions
// remain in 'active'/'approved' status indefinitely, and audit logs
// accumulate without bounds.
type DataExpirationController struct {
	suppressionRepo suppression.Repository
	exclusionRepo   scope.ExclusionRepository
	auditRepo       audit.Repository
	config          *DataExpirationControllerConfig
	logger          *logger.Logger
}

// NewDataExpirationController creates a new DataExpirationController.
func NewDataExpirationController(
	suppressionRepo suppression.Repository,
	exclusionRepo scope.ExclusionRepository,
	auditRepo audit.Repository,
	config *DataExpirationControllerConfig,
) *DataExpirationController {
	if config == nil {
		config = &DataExpirationControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 1 * time.Hour
	}
	if config.AuditRetentionDays == 0 {
		config.AuditRetentionDays = 365
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}

	return &DataExpirationController{
		suppressionRepo: suppressionRepo,
		exclusionRepo:   exclusionRepo,
		auditRepo:       auditRepo,
		config:          config,
		logger:          config.Logger,
	}
}

// Name returns the controller name.
func (c *DataExpirationController) Name() string {
	return "data-expiration"
}

// Interval returns the reconciliation interval.
func (c *DataExpirationController) Interval() time.Duration {
	return c.config.Interval
}

// Reconcile expires stale suppression rules, scope exclusions, and old audit logs.
func (c *DataExpirationController) Reconcile(ctx context.Context) (int, error) {
	totalProcessed := 0

	// Step 1: Expire suppression rules past their expires_at
	expiredRules, err := c.suppressionRepo.ExpireRules(ctx)
	if err != nil {
		c.logger.Error("failed to expire suppression rules", "error", err)
		// Continue with other tasks
	} else if expiredRules > 0 {
		c.logger.Info("expired suppression rules", "count", expiredRules)
		totalProcessed += int(expiredRules)
	}

	// Step 2: Expire scope exclusions past their expires_at
	if err := c.exclusionRepo.ExpireOld(ctx); err != nil {
		c.logger.Error("failed to expire scope exclusions", "error", err)
		// Continue with other tasks
	}

	// Step 3: Clean up old audit logs
	cutoff := time.Now().AddDate(0, 0, -c.config.AuditRetentionDays)
	deletedLogs, err := c.auditRepo.DeleteOlderThan(ctx, cutoff)
	if err != nil {
		c.logger.Error("failed to delete old audit logs",
			"error", err,
			"cutoff", cutoff,
		)
	} else if deletedLogs > 0 {
		c.logger.Info("deleted old audit logs",
			"count", deletedLogs,
			"retention_days", c.config.AuditRetentionDays,
		)
		totalProcessed += int(deletedLogs)
	}

	return totalProcessed, nil
}
