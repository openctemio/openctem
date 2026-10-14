package coverage

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ModeSource is the scan approval mode in force for a tenant.
type ModeSource interface {
	EffectiveMode(ctx context.Context, tenantID shared.ID) (scangov.Mode, string, scangov.PlatformPolicy, error)
}

// GovernanceSwitch turns automatic coverage off for a tenant whose scan
// approval mode in force is Strict (owner decision D1: Strict-governance
// organizations are off until they enable it).
type GovernanceSwitch struct{ Modes ModeSource }

// CoverageEnabled reports whether automatic coverage runs for the tenant.
func (g GovernanceSwitch) CoverageEnabled(ctx context.Context, tenantID shared.ID) (bool, error) {
	m, _, _, err := g.Modes.EffectiveMode(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return m.Normalized() != scangov.ModeStrict, nil
}
