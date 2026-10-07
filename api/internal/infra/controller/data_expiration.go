package controller

import (
	"context"
	"errors"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// DataExpirationControllerConfig configures the DataExpirationController.
type DataExpirationControllerConfig struct {
	// Interval is how often to run the expiration check.
	// Default: 1 hour.
	Interval time.Duration

	// AuditRetentionDays is how long audit logs stay online. Older entries
	// are archived and pruned from the front of each hash chain. Values
	// below 365 are raised to 365 (audit.MinAuditRetentionDays).
	AuditRetentionDays int

	// AuditArchiveDir receives the gzip JSONL archive of pruned entries.
	// Empty: nothing is pruned (logged once).
	AuditArchiveDir string

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
	auditPruner     AuditChainPruner
	targetExpirer   ScopeTargetExpirer
	config          *DataExpirationControllerConfig
	logger          *logger.Logger
	warnedNoArchive bool
}

// ScopeTargetExpirer marks scope entries past their expiry as expired
// (*postgres.ScopeTargetRepository, RFC-054). The reads already ignore them;
// the sweep makes the status say so.
type ScopeTargetExpirer interface {
	ExpireOld(ctx context.Context) (int64, error)
}

// SetScopeTargetExpirer adds the scope-entry sweep (nil: none).
func (c *DataExpirationController) SetScopeTargetExpirer(e ScopeTargetExpirer) *DataExpirationController {
	c.targetExpirer = e
	return c
}

// AuditChainPruner archives and prunes audit chain entries past retention
// (*auditapp.AuditService).
type AuditChainPruner interface {
	PruneExpiredChains(ctx context.Context, cfg auditapp.RetentionConfig) (auditapp.RetentionResult, error)
}

// NewDataExpirationController creates a new DataExpirationController.
func NewDataExpirationController(
	suppressionRepo suppression.Repository,
	exclusionRepo scope.ExclusionRepository,
	auditPruner AuditChainPruner,
	config *DataExpirationControllerConfig,
) *DataExpirationController {
	if config == nil {
		config = &DataExpirationControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 1 * time.Hour
	}
	config.AuditRetentionDays = auditapp.EffectiveRetentionDays(config.AuditRetentionDays)
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}

	return &DataExpirationController{
		suppressionRepo: suppressionRepo,
		exclusionRepo:   exclusionRepo,
		auditPruner:     auditPruner,
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
	if c.targetExpirer != nil {
		if n, err := c.targetExpirer.ExpireOld(ctx); err != nil {
			c.logger.Error("failed to expire scope entries", "error", err)
		} else if n > 0 {
			c.logger.Info("expired scope entries", "count", n)
			totalProcessed += int(n)
		}
	}

	// Step 3: Audit retention. Archive and prune the oldest prefix of each
	// hash chain past the retention window (deleting rows in place broke the
	// chain's foreign key and failed every run).
	if c.auditPruner != nil {
		res, err := c.auditPruner.PruneExpiredChains(ctx, auditapp.RetentionConfig{
			RetentionDays: c.config.AuditRetentionDays,
			ArchiveDir:    c.config.AuditArchiveDir,
		})
		switch {
		case errors.Is(err, auditapp.ErrNoAuditArchiveDir):
			if !c.warnedNoArchive {
				c.logger.Warn("audit retention is off: set AUDIT_ARCHIVE_DIR to archive and prune audit logs older than the retention window",
					"retention_days", c.config.AuditRetentionDays)
				c.warnedNoArchive = true
			}
		case err != nil:
			c.logger.Error("audit retention failed", "error", err)
		case res.Pruned > 0:
			c.logger.Info("audit retention pruned chains",
				"chains", res.Chains, "pruned", res.Pruned, "archives", len(res.Archives),
				"retention_days", c.config.AuditRetentionDays)
			totalProcessed += res.Pruned
		}
	}

	return totalProcessed, nil
}

// Exclusive: it runs on one API replica at a time (controller lease, RFC-046
// P1.8); two replicas sweeping at once would delete or fetch twice.
func (c *DataExpirationController) Exclusive() bool { return true }
