package ticketpolicy

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestEvaluate(t *testing.T) {
	def := Default()
	off := Policy{MinSeverity: vulnerability.SeverityInfo}
	strict := Policy{MinSeverity: vulnerability.SeverityCritical, MinPriorityClass: "P0"}
	cases := []struct {
		name   string
		p      Policy
		s      Signals
		pass   bool
		reason string
	}{
		{"medium passes the default", def, Signals{Severity: "medium", Open: true}, true, "severity"},
		{"low P3 is held", def, Signals{Severity: "low", PriorityClass: "P3", Open: true}, false, ReasonBelowThreshold},
		{"info is held", def, Signals{Severity: "info", Open: true}, false, ReasonBelowThreshold},
		{"low P1 passes by class", def, Signals{Severity: "low", PriorityClass: "P1", Open: true}, true, "priority_class"},
		{"low P2 passes by class (inclusive)", def, Signals{Severity: "low", PriorityClass: "p2", Open: true}, true, "priority_class"},
		{"low KEV passes", def, Signals{Severity: "low", InKEV: true, Open: true}, true, "kev"},
		{"KEV not always", Policy{MinSeverity: "high"}, Signals{Severity: "low", InKEV: true, Open: true}, false, ReasonBelowThreshold},
		{"closed critical is not ticketed", def, Signals{Severity: "critical", Open: false}, false, "not_open"},
		{"info floor lets none through", off, Signals{Severity: "none", Open: true}, true, "severity"},
		{"strict holds high P1", strict, Signals{Severity: "high", PriorityClass: "P1", Open: true}, false, ReasonBelowThreshold},
		{"strict passes P0", strict, Signals{Severity: "low", PriorityClass: "P0", Open: true}, true, "priority_class"},
		{"no class floor ignores class", Policy{MinSeverity: "high"}, Signals{Severity: "low", PriorityClass: "P0", Open: true}, false, ReasonBelowThreshold},
	}
	for _, c := range cases {
		v := c.p.Evaluate(c.s)
		if v.Pass != c.pass || v.Reason != c.reason {
			t.Errorf("%s: got %+v, want pass=%v reason=%s", c.name, v, c.pass, c.reason)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := []Policy{Default(), {MinSeverity: "info"}, {MinSeverity: "critical", MinPriorityClass: "P3", DailyCap: MaxDailyCap}}
	for _, p := range ok {
		if err := p.Validate(); err != nil {
			t.Errorf("%+v: %v", p, err)
		}
	}
	bad := []Policy{{MinSeverity: ""}, {MinSeverity: "none"}, {MinSeverity: "high", MinPriorityClass: "P4"},
		{MinSeverity: "high", DailyCap: -1}, {MinSeverity: "high", DailyCap: MaxDailyCap + 1}}
	for _, p := range bad {
		if err := p.Validate(); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%+v: want validation error, got %v", p, err)
		}
	}
	if n := (Policy{MinSeverity: " HIGH ", MinPriorityClass: " p1 "}).Normalize(); n.MinSeverity != "high" || n.MinPriorityClass != "P1" {
		t.Errorf("normalize: %+v", n)
	}
}

func TestAllowedLists(t *testing.T) {
	if got := (Policy{MinSeverity: "medium"}).AllowedSeverities(); len(got) != 3 || got[2] != "medium" {
		t.Errorf("medium: %v", got)
	}
	if got := (Policy{MinSeverity: "info"}).AllowedSeverities(); len(got) != 6 {
		t.Errorf("info: %v", got)
	}
	if got := (Policy{MinPriorityClass: "P1"}).AllowedClasses(); len(got) != 2 || got[1] != "P1" {
		t.Errorf("P1: %v", got)
	}
	if got := (Policy{}).AllowedClasses(); got != nil {
		t.Errorf("none: %v", got)
	}
}
