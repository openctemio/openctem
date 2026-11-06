package coverage

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// ModeSource is the scan approval mode in force for a tenant.
type ModeSource interface {
	EffectiveMode(ctx context.Context, tenantID shared.ID) (scangov.Mode, string, scangov.PlatformPolicy, error)
}

// ScopeSettingsReader reads the organization's scope settings.
type ScopeSettingsReader interface {
	GetScopeSettings(ctx context.Context, tenantID string) (*tenant.ScopeSettings, error)
}

// GovernanceSwitch decides automatic coverage per tenant: the
// organization's choice (scope settings, auto_coverage), else on unless the
// scan approval mode in force is Strict (owner decision D1). A read error
// is off (fail closed).
type GovernanceSwitch struct {
	Modes    ModeSource
	Settings ScopeSettingsReader // nil: the default only
}

// CoverageEnabled reports whether automatic coverage runs for the tenant.
func (g GovernanceSwitch) CoverageEnabled(ctx context.Context, tenantID shared.ID) (bool, error) {
	m, _, _, err := g.Modes.EffectiveMode(ctx, tenantID)
	if err != nil {
		return false, err
	}
	strict := m.Normalized() == scangov.ModeStrict
	if g.Settings == nil {
		return !strict, nil
	}
	ss, err := g.Settings.GetScopeSettings(ctx, tenantID.String())
	if err != nil {
		return false, err
	}
	if ss == nil {
		return !strict, nil
	}
	return ss.AutoCoverageOn(strict), nil
}
