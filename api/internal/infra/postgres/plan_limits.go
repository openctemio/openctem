package postgres

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// planLimits is embedded by the repositories whose inserts count against an
// organization's plan limit (docs/architecture/plans-and-limits.md). The
// check sits at the insert so every path that adds a member, an invitation,
// an asset, a sensor, an API key or a CI trust passes it. Nil: no plans.
//
// The check reads usage before the insert, outside its transaction: two
// concurrent additions can each pass at limit-1. The limit is a commercial
// cap, not a security boundary, so that overshoot by the concurrency is
// accepted.
type planLimits struct {
	limits plan.Checker
}

// SetPlanLimits makes the repository's inserts pass the plan limits.
func (p *planLimits) SetPlanLimits(c plan.Checker) { p.limits = c }

func (p *planLimits) checkLimit(ctx context.Context, tenantID shared.ID, key plan.Key, delta int) error {
	if p.limits == nil || delta <= 0 {
		return nil
	}
	return p.limits.Check(ctx, tenantID, key, delta)
}
