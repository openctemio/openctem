package scan

// Limits of shared (platform) sensor scanning
// (docs/rfcs/RFC-100-shared-sensors.md §10): the generic per-organization
// limit platform_scans_per_day, read through the entitlement service by key,
// never by plan. A self-hosted organization has no limit unless the instance
// administrator sets one; the hosted service's control plane writes them.
// The concurrent limit is enforced where shared jobs are claimed.

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SharedScanLimits checks an organization's shared-sensor limits
// (*entitlement.Service).
type SharedScanLimits interface {
	Check(ctx context.Context, tenantID shared.ID, key plan.Key, delta int) error
}

// WithSharedScanLimits wires the limit check. Without it no scan goes to
// shared sensors (fail closed).
func WithSharedScanLimits(l SharedScanLimits) ServiceOption {
	return func(s *Service) { s.sharedLimits = l }
}

// sharedLimitRefusal is nil when one more scan may go to shared sensors
// today, else the refusal naming the limit. A limit that cannot be read
// refuses (fail closed).
func (s *Service) sharedLimitRefusal(ctx context.Context, tenantID shared.ID) error {
	if s.sharedLimits == nil {
		return shared.NewDomainError(codePlatformRefused,
			"shared platform sensor limits cannot be checked on this instance", shared.ErrValidation)
	}
	err := s.sharedLimits.Check(ctx, tenantID, plan.PlatformScansPerDay, 1)
	if err == nil {
		return nil
	}
	var lim *plan.ErrLimitReached
	if errors.As(err, &lim) && !lim.Unavailable {
		return shared.NewDomainError(codePlatformRefused, fmt.Sprintf(
			"your organization has started its %d scans on shared platform sensors for today (UTC); run this scan on your own sensors or wait until tomorrow",
			lim.Limit), shared.ErrValidation)
	}
	s.logger.Warn("shared sensor limit check failed; refusing (fail closed)", "tenant_id", tenantID.String(), "error", err)
	return shared.NewDomainError(codePlatformRefused,
		"the shared platform sensor limit could not be checked right now; try again later or run the scan on your own sensors",
		shared.ErrValidation)
}
