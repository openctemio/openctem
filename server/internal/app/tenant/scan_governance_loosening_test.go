package tenant

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

func TestScanGovernanceLoosened(t *testing.T) {
	rules := scangov.Preset(scangov.PresetLight)
	if len(rules) == 0 {
		t.Fatal("light preset has no rule")
	}
	st := func(m scangov.Mode, rs []scangov.Rule) tenantdom.ScanGovernanceSettings {
		return tenantdom.ScanGovernanceSettings{Mode: m, Rules: append([]scangov.Rule(nil), rs...)}
	}
	edited := append([]scangov.Rule(nil), rules...)
	edited[0].Name += " (edited)"
	monitor := append([]scangov.Rule(nil), rules...)
	monitor[0].Monitor = true
	cases := []struct {
		name           string
		before, after  tenantdom.ScanGovernanceSettings
		wantMode, want bool
	}{
		{"strict to on", st(scangov.ModeStrict, rules), st(scangov.ModeOn, rules), true, false},
		{"on to off", st(scangov.ModeOn, rules), st(scangov.ModeOff, rules), true, false},
		{"off to on", st(scangov.ModeOff, nil), st(scangov.ModeOn, rules), false, false},
		{"same", st(scangov.ModeOn, rules), st(scangov.ModeOn, rules), false, false},
		{"rule removed", st(scangov.ModeOn, rules), st(scangov.ModeOn, rules[1:]), false, true},
		{"rule to monitor", st(scangov.ModeOn, rules), st(scangov.ModeOn, monitor), false, true},
		{"rule edited", st(scangov.ModeOn, rules), st(scangov.ModeOn, edited), false, true},
		{"rule added", st(scangov.ModeOn, rules[1:]), st(scangov.ModeOn, rules), false, false},
		{"rules while off", st(scangov.ModeOff, rules), st(scangov.ModeOff, nil), false, false},
	}
	for _, c := range cases {
		m, r := scanGovernanceLoosened(c.before, c.after)
		if m != c.wantMode || r != c.want {
			t.Errorf("%s: mode lowered %v rules loosened %v, want %v %v", c.name, m, r, c.wantMode, c.want)
		}
	}
}
