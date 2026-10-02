package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/accesscontrol"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// ScopeReconciliationControllerConfig configures the ScopeReconciliationController.
type ScopeReconciliationControllerConfig struct {
	// Interval is how often to run the reconciliation.
	// Default: 30 minutes.
	Interval time.Duration

	// Logger for logging.
	Logger *logger.Logger
}

// scopeGroupReconciler is the interface for reconciling a single access control group.
type scopeGroupReconciler interface {
	ReconcileGroupByIDs(ctx context.Context, tenantID, groupID shared.ID) error
}

// ScopeReconciliationController periodically reconciles scope rule assignments
// as a safety net for the real-time event-driven hooks.
//
// This controller:
// 1. Lists all tenants with active scope rules
// 2. For each tenant, lists all groups with active scope rules
// 3. Reconciles each group by re-evaluating matching assets
//
// Design: This is a background safety net (K8s-style eventual consistency).
// The primary path is real-time hooks in AssetService and AssetGroupService.
type ScopeReconciliationController struct {
	acRepo     accesscontrol.Repository
	reconciler scopeGroupReconciler
	config     *ScopeReconciliationControllerConfig
	logger     *logger.Logger
}

// NewScopeReconciliationController creates a new ScopeReconciliationController.
func NewScopeReconciliationController(
	acRepo accesscontrol.Repository,
	reconciler scopeGroupReconciler,
	config *ScopeReconciliationControllerConfig,
) *ScopeReconciliationController {
	if config == nil {
		config = &ScopeReconciliationControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 30 * time.Minute
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}

	return &ScopeReconciliationController{
		acRepo:     acRepo,
		reconciler: reconciler,
		config:     config,
		logger:     config.Logger,
	}
}

// Name returns the controller name.
func (c *ScopeReconciliationController) Name() string {
	return "scope-reconciliation"
}

// Interval returns the reconciliation interval.
func (c *ScopeReconciliationController) Interval() time.Duration {
	return c.config.Interval
}

// Reconcile performs periodic scope rule reconciliation across all tenants.
// Returns the number of groups reconciled and any error encountered.
func (c *ScopeReconciliationController) Reconcile(ctx context.Context) (int, error) {
	tenantIDs, err := c.acRepo.ListTenantsWithActiveScopeRules(ctx)
	if err != nil {
		c.logger.Error("failed to list tenants with active scope rules", "error", err)
		return 0, err
	}

	if len(tenantIDs) == 0 {
		return 0, nil
	}

	reconciledCount := 0
	for _, tenantID := range tenantIDs {
		groupIDs, err := c.acRepo.ListGroupsWithActiveScopeRules(ctx, tenantID)
		if err != nil {
			c.logger.Error("failed to list groups with active scope rules",
				"tenant_id", tenantID.String(), "error", err)
			continue
		}

		for _, groupID := range groupIDs {
			if err := c.reconciler.ReconcileGroupByIDs(ctx, tenantID, groupID); err != nil {
				c.logger.Warn("scope reconciliation failed for group",
					"tenant_id", tenantID.String(),
					"group_id", groupID.String(),
					"error", err)
				continue
			}
			reconciledCount++
		}
	}

	if reconciledCount > 0 {
		c.logger.Info("scope reconciliation completed",
			"groups_reconciled", reconciledCount,
			"tenants_checked", len(tenantIDs),
		)
	}

	return reconciledCount, nil
}
