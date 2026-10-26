package controller

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetGroupRuleEvaluator evaluates the rule groups of a tenant, or of every
// tenant for a zero ID (*asset.AssetGroupService), and returns how many
// groups changed.
type AssetGroupRuleEvaluator interface {
	EvaluateTenant(ctx context.Context, tenantID shared.ID) (int, error)
}

// AssetGroupRulesController is the full recompute of every group that fills
// itself by a rule. Asset changes already trigger a debounced evaluation of
// the tenant's groups; this is the safety net for a change that was missed or
// whose evaluation failed (and for an editor whose access changed).
// Idempotent: a group already up to date is not touched.
type AssetGroupRulesController struct {
	eval     AssetGroupRuleEvaluator
	interval time.Duration
}

// NewAssetGroupRulesController creates the controller. interval 0 = 1 h.
func NewAssetGroupRulesController(eval AssetGroupRuleEvaluator, interval time.Duration) *AssetGroupRulesController {
	if interval <= 0 {
		interval = time.Hour
	}
	return &AssetGroupRulesController{eval: eval, interval: interval}
}

// Name implements Controller.
func (c *AssetGroupRulesController) Name() string { return "asset-group-rules" }

// Interval implements Controller.
func (c *AssetGroupRulesController) Interval() time.Duration { return c.interval }

// Reconcile implements Controller: the number of groups that changed.
func (c *AssetGroupRulesController) Reconcile(ctx context.Context) (int, error) {
	if c.eval == nil {
		return 0, nil
	}
	return c.eval.EvaluateTenant(ctx, shared.ID{})
}
