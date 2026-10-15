package postgres

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// limitChecks is embedded by the repositories whose inserts count against an
// organization's limit (docs/architecture/limits.md). The check sits at the
// insert so every path that adds a member, an invitation, an asset, a
// sensor, an API key, a CI trust or a finding passes it. Nil: no limits.
//
// The check reads usage before the insert, outside its transaction: two
// concurrent additions can each pass at limit-1. The limit is a commercial
// cap, not a security boundary, so that overshoot by the concurrency is
// accepted.
type limitChecks struct {
	limits limits.Checker
}

// SetLimits makes the repository's inserts pass the organization's limits.
func (p *limitChecks) SetLimits(c limits.Checker) { p.limits = c }

func (p *limitChecks) checkLimit(ctx context.Context, tenantID shared.ID, key limits.Key, delta int) error {
	if p.limits == nil || delta <= 0 {
		return nil
	}
	return p.limits.Check(ctx, tenantID, key, delta)
}

// headroom returns how many more of key may be added: limits.Unlimited when
// no limit applies (or no checker is wired).
func (p *limitChecks) headroom(ctx context.Context, tenantID shared.ID, key limits.Key) (int, error) {
	if p.limits == nil {
		return limits.Unlimited, nil
	}
	return p.limits.Headroom(ctx, tenantID, key)
}

func (p *limitChecks) recordRefusals(key limits.Key, n int) {
	if p.limits != nil {
		p.limits.RecordRefusals(key, n)
	}
}
