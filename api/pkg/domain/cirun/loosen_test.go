package cirun

import (
	"slices"
	"testing"
)

func TestLoosens(t *testing.T) {
	base := func() GatePolicy { return DefaultGatePolicy() }
	epss := func(v float64) *float64 { return &v }
	cases := []struct {
		name   string
		before func() GatePolicy
		edit   func(p *GatePolicy)
		want   []string
	}{
		{"no change", base, func(*GatePolicy) {}, nil},
		{"enforce to warn", base, func(p *GatePolicy) { p.Mode = ModeWarn }, []string{"mode"}},
		{"higher threshold", base, func(p *GatePolicy) { p.FailOnSeverity = "critical" }, []string{"fail_on_severity"}},
		{"threshold none", base, func(p *GatePolicy) { p.FailOnSeverity = SeverityNone }, []string{"fail_on_severity"}},
		{"lower threshold tightens", base, func(p *GatePolicy) { p.FailOnSeverity = "medium" }, nil},
		{"new findings only", func() GatePolicy { p := base(); p.NewFindingsOnly = false; return p },
			func(p *GatePolicy) { p.NewFindingsOnly = true }, []string{"new_findings_only"}},
		{"all findings tightens", base, func(p *GatePolicy) { p.NewFindingsOnly = false }, nil},
		{"KEV off", base, func(p *GatePolicy) { p.FailOnKEV = false }, []string{"fail_on_kev"}},
		{"EPSS cleared", func() GatePolicy { p := base(); p.EPSSThreshold = epss(0.5); return p },
			func(p *GatePolicy) { p.EPSSThreshold = nil }, []string{"epss_threshold"}},
		{"EPSS raised", func() GatePolicy { p := base(); p.EPSSThreshold = epss(0.5); return p },
			func(p *GatePolicy) { p.EPSSThreshold = epss(0.9) }, []string{"epss_threshold"}},
		{"EPSS added tightens", base, func(p *GatePolicy) { p.EPSSThreshold = epss(0.5) }, nil},
		{"capability to monitor", base, func(p *GatePolicy) {
			p.Modes = PolicyModes{Capabilities: map[string]string{"sast": FindingModeMonitor}}
		}, []string{"modes"}},
		{"capability back to block tightens", func() GatePolicy {
			p := base()
			p.Modes = PolicyModes{Capabilities: map[string]string{"sast": FindingModeComment}}
			return p
		}, func(p *GatePolicy) { p.Modes = PolicyModes{} }, nil},
		{"new rule exception", base, func(p *GatePolicy) {
			p.Modes = PolicyModes{Rules: map[string]string{"go.sqli": FindingModeComment}}
		}, []string{"modes"}},
		{"rule weaker", func() GatePolicy {
			p := base()
			p.Modes = PolicyModes{Rules: map[string]string{"r": FindingModeComment}}
			return p
		}, func(p *GatePolicy) { p.Modes = PolicyModes{Rules: map[string]string{"r": FindingModeMonitor}} }, []string{"modes"}},
		{"blocking rule override removed under a monitored capability", func() GatePolicy {
			p := base()
			p.Modes = PolicyModes{Capabilities: map[string]string{"sast": FindingModeMonitor}, Rules: map[string]string{"r": FindingModeBlock}}
			return p
		}, func(p *GatePolicy) {
			p.Modes = PolicyModes{Capabilities: map[string]string{"sast": FindingModeMonitor}}
		}, []string{"modes"}},
		{"weak rule override removed tightens", func() GatePolicy {
			p := base()
			p.Modes = PolicyModes{Rules: map[string]string{"r": FindingModeMonitor}}
			return p
		}, func(p *GatePolicy) { p.Modes = PolicyModes{} }, nil},
		{"several at once", base, func(p *GatePolicy) { p.Mode = ModeWarn; p.FailOnKEV = false },
			[]string{"mode", "fail_on_kev"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.before()
			after := tc.before()
			tc.edit(&after)
			if got := Loosens(before, after); !slices.Equal(got, tc.want) {
				t.Fatalf("Loosens = %v, want %v", got, tc.want)
			}
		})
	}
}
