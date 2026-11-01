package tenant

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestAutoTriageLoosened(t *testing.T) {
	p := func(on bool, sev ...string) AutoTriagePolicy { return AutoTriagePolicy{Enabled: on, Severities: sev} }
	cases := []struct {
		name          string
		before, after AutoTriagePolicy
		want          bool
	}{
		{"turn on", p(false, "critical"), p(true, "critical"), true},
		{"add a severity", p(true, "critical"), p(true, "critical", "high"), true},
		{"swap a severity", p(true, "critical"), p(true, "high"), true},
		{"turn off", p(true, "critical"), p(false, "critical", "high", "low"), false},
		{"remove a severity", p(true, "critical", "high"), p(true, "critical"), false},
		{"same", p(true, "critical"), p(true, "CRITICAL"), false},
		{"widen while off", p(false, "critical"), p(false, "critical", "low"), false},
		{"delay only", AutoTriagePolicy{Enabled: true, Severities: []string{"high"}, DelaySeconds: 600},
			AutoTriagePolicy{Enabled: true, Severities: []string{"high"}}, false},
	}
	for _, c := range cases {
		if got := AutoTriageLoosened(c.before, c.after); got != c.want {
			t.Errorf("%s: loosened = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAutoTriagePolicyNormalized(t *testing.T) {
	got, err := AutoTriagePolicy{Enabled: true, Severities: []string{"low", " High ", "critical", "high"}, DelaySeconds: 60}.Normalized()
	if err != nil || len(got.Severities) != 3 || got.Severities[0] != "critical" || got.Severities[1] != "high" || got.Severities[2] != "low" {
		t.Fatalf("normalized = %+v %v", got, err)
	}
	for name, bad := range map[string]AutoTriagePolicy{
		"unknown severity":  {Severities: []string{"urgent"}},
		"negative delay":    {DelaySeconds: -1},
		"delay over max":    {DelaySeconds: MaxAutoTriageDelaySeconds + 1},
		"on, no severities": {Enabled: true},
	} {
		if _, err := bad.Normalized(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: err = %v, want validation", name, err)
		}
	}
}
