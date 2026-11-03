package scan

// Passive only (docs/architecture/limits.md, "Passive only"): an
// organization whose entitlements deny limits.FeatureActiveScanning may
// create, change and run only scans whose tier is passive. This is the early,
// explained refusal; the dispatch re-check (command.Service) enforces the
// same for every command and is never replaced by this.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/limits"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// CodeActiveScanningNotEntitled is the validation error code of a scan above
// passive for an organization without active scanning.
const CodeActiveScanningNotEntitled = "ACTIVE_SCANNING_NOT_ENTITLED"

// FeatureAllower reads whether an organization may use a named feature
// (*entitlement.Service).
type FeatureAllower interface {
	Allowed(ctx context.Context, tenantID shared.ID, feature string) (bool, error)
}

// requireActiveScanning refuses sc when its tier (its intensity, or the tier
// of its tools when higher: the same value the governance rules read,
// computed here, never taken from a request) is above passive and the
// organization may not scan actively. A lookup that fails refuses a tier
// above passive (fail closed); passive scans are never affected.
func (s *Service) requireActiveScanning(ctx context.Context, sc *scan.Scan) error {
	if s.activeScan == nil {
		return nil
	}
	_, _, toolTier, err := s.governanceTools(ctx, sc)
	if err != nil {
		return err
	}
	if max(sc.EffectiveIntensity().MaxTier(), toolTier) == 0 {
		return nil
	}
	ok, err := s.activeScan.Allowed(ctx, sc.TenantID, limits.FeatureActiveScanning)
	if err != nil {
		s.logger.Warn("cannot read the active scanning entitlement; refusing a scan above passive",
			"tenant_id", sc.TenantID.String(), "error", err)
		return shared.NewDomainError(CodeActiveScanningNotEntitled,
			"the active scanning entitlement could not be checked right now; try again later or use passive intensity", shared.ErrValidation)
	}
	if !ok {
		return shared.NewDomainError(CodeActiveScanningNotEntitled,
			"your organization's plan allows passive scanning only; set the intensity to passive and use passive tools", shared.ErrValidation)
	}
	return nil
}
