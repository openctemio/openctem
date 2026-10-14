package coverage

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type modeOf struct {
	m   scangov.Mode
	err error
}

func (m modeOf) EffectiveMode(context.Context, shared.ID) (scangov.Mode, string, scangov.PlatformPolicy, error) {
	return m.m, "", "", m.err
}

type settingsOf struct {
	ss  *tenant.ScopeSettings
	err error
}

func (s settingsOf) GetScopeSettings(context.Context, string) (*tenant.ScopeSettings, error) {
	return s.ss, s.err
}

// Owner decision D1: on by default, off under Strict until the organization
// turns it on; an explicit choice wins either way; a read error is off.
func TestGovernanceSwitch(t *testing.T) {
	on, off := true, false
	for name, c := range map[string]struct {
		g    GovernanceSwitch
		want bool
		err  bool
	}{
		"default off-mode":    {GovernanceSwitch{Modes: modeOf{m: scangov.ModeOff}, Settings: settingsOf{ss: &tenant.ScopeSettings{}}}, true, false},
		"default on-mode":     {GovernanceSwitch{Modes: modeOf{m: scangov.ModeOn}, Settings: settingsOf{ss: &tenant.ScopeSettings{}}}, true, false},
		"default strict":      {GovernanceSwitch{Modes: modeOf{m: scangov.ModeStrict}, Settings: settingsOf{ss: &tenant.ScopeSettings{}}}, false, false},
		"strict, turned on":   {GovernanceSwitch{Modes: modeOf{m: scangov.ModeStrict}, Settings: settingsOf{ss: &tenant.ScopeSettings{AutoCoverage: &on}}}, true, false},
		"turned off":          {GovernanceSwitch{Modes: modeOf{m: scangov.ModeOff}, Settings: settingsOf{ss: &tenant.ScopeSettings{AutoCoverage: &off}}}, false, false},
		"mode read error":     {GovernanceSwitch{Modes: modeOf{err: errors.New("db")}}, false, true},
		"settings read error": {GovernanceSwitch{Modes: modeOf{m: scangov.ModeOff}, Settings: settingsOf{err: errors.New("db")}}, false, true},
		"no settings reader":  {GovernanceSwitch{Modes: modeOf{m: scangov.ModeOff}}, true, false},
	} {
		got, err := c.g.CoverageEnabled(context.Background(), shared.NewID())
		if got != c.want || (err != nil) != c.err {
			t.Errorf("%s: %v, %v; want %v (error %v)", name, got, err, c.want, c.err)
		}
	}
}
