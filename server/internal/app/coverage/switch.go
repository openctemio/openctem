package coverage

import (
	"context"
	"time"

	covdom "github.com/openctemio/openctem/server/pkg/domain/coverage"

	"github.com/openctemio/openctem/server/pkg/domain/scangov"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
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

// InfoPolicy is the organization's info pass setting (scope settings
// info_coverage and info_coverage_days): on, every 30 days by default. Where
// the settings cannot be read it returns the error and the caller leaves the
// info pass out of that pass.
func (g GovernanceSwitch) InfoPolicy(ctx context.Context, tenantID shared.ID) (covdom.InfoPolicy, error) {
	if g.Settings == nil {
		return covdom.DefaultInfoPolicy(), nil
	}
	ss, err := g.Settings.GetScopeSettings(ctx, tenantID.String())
	if err != nil {
		return covdom.InfoPolicy{}, err
	}
	if ss == nil {
		return covdom.DefaultInfoPolicy(), nil
	}
	return covdom.InfoPolicy{On: ss.InfoCoverageOn(), Every: time.Duration(ss.InfoCoverageEvery()) * 24 * time.Hour}, nil
}
