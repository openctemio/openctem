package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/logger"
)

// F-13: retention for priority_class_audit_log.
//
// Every priority classification logs an entry in priority_class_audit_log
// (see internal/app/priority_classification_service.go). On busy tenants this
// table grows fast — dozens to thousands of rows per hour. Without retention
// its index hot-paths slow down and the table bloats indefinitely.
//
// This controller mirrors AuditRetentionController: count → optional dry-run
// → bulk delete older than the configured window. Default window is 180 days
// (shorter than general audit retention because priority changes are
// operational signal, not compliance evidence).

// PriorityAuditRetentionStore is the subset of PriorityAuditRepository that
// this controller needs. Defined locally so we don't depend on the app layer.
type PriorityAuditRetentionStore interface {
	CountOlderThan(ctx context.Context, before time.Time) (int64, error)
	DeleteOlderThan(ctx context.Context, before time.Time) (int64, error)
}

// PriorityAuditRetentionConfig configures the controller.
type PriorityAuditRetentionConfig struct {
	// Interval between runs (default 24h).
	Interval time.Duration
	// RetentionDays — rows older than this are deleted (default 180).
	RetentionDays int
	// DryRun skips deletion and only reports count.
	DryRun bool
	// Logger for logging.
	Logger *logger.Logger
}

// PriorityAuditRetentionController implements the background controller
// contract (Name / Interval / Reconcile).
type PriorityAuditRetentionController struct {
	repo   PriorityAuditRetentionStore
	config *PriorityAuditRetentionConfig
	logger *logger.Logger
}

// NewPriorityAuditRetentionController constructs the controller with sensible
// defaults for any zero-valued config fields.
func NewPriorityAuditRetentionController(
	repo PriorityAuditRetentionStore,
	config *PriorityAuditRetentionConfig,
) *PriorityAuditRetentionController {
	if config == nil {
		config = &PriorityAuditRetentionConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 24 * time.Hour
	}
	if config.RetentionDays == 0 {
		config.RetentionDays = 180
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}
	return &PriorityAuditRetentionController{
		repo:   repo,
		config: config,
		logger: config.Logger,
	}
}

// Name returns the controller name.
func (c *PriorityAuditRetentionController) Name() string {
	return "priority-audit-retention"
}

// Interval returns the reconciliation interval.
func (c *PriorityAuditRetentionController) Interval() time.Duration {
	return c.config.Interval
}

// Reconcile deletes rows older than the configured retention window.
func (c *PriorityAuditRetentionController) Reconcile(ctx context.Context) (int, error) {
	cutoff := time.Now().AddDate(0, 0, -c.config.RetentionDays)

	count, err := c.repo.CountOlderThan(ctx, cutoff)
	if err != nil {
		c.logger.Error("failed to count old priority audit rows", "error", err, "cutoff", cutoff)
		return 0, err
	}
	if count == 0 {
		return 0, nil
	}

	c.logger.Info("priority audit rows eligible for retention cleanup",
		"count", count,
		"cutoff", cutoff,
		"retention_days", c.config.RetentionDays,
		"dry_run", c.config.DryRun,
	)

	if c.config.DryRun {
		return int(count), nil
	}

	deleted, err := c.repo.DeleteOlderThan(ctx, cutoff)
	if err != nil {
		c.logger.Error("failed to delete old priority audit rows", "error", err, "cutoff", cutoff)
		return 0, err
	}
	c.logger.Info("deleted old priority audit rows",
		"count", deleted,
		"cutoff", cutoff,
		"retention_days", c.config.RetentionDays,
	)
	return int(deleted), nil
}
