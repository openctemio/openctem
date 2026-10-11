package cirun

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestRepoPolicyOnlyTightens(t *testing.T) {
	p := DefaultGatePolicy()
	p.Modes = PolicyModes{Rules: map[string]string{"go.weak": FindingModeComment}}
	f, tr, epss := false, true, 0.5
	got := p.Tighten(&RepoPolicy{FailOnSeverity: "medium", NewFindingsOnly: &f, FailOnKEV: &tr, EPSSThreshold: &epss,
		BlockRules: []string{"go.weak"}})
	if got.FailOnSeverity != "medium" || got.NewFindingsOnly || !got.FailOnKEV || got.EPSSThreshold == nil ||
		*got.EPSSThreshold != 0.5 || got.Modes.Rules["go.weak"] != FindingModeBlock {
		t.Fatalf("tightened = %+v", got)
	}
	// Looser values are ignored.
	tr2 := true
	strict := DefaultGatePolicy()
	strict.FailOnSeverity, strict.NewFindingsOnly = "low", false
	low := 0.1
	strict.EPSSThreshold = &low
	got = strict.Tighten(&RepoPolicy{FailOnSeverity: "critical", NewFindingsOnly: &tr2, EPSSThreshold: &epss})
	if got.FailOnSeverity != "low" || got.NewFindingsOnly || *got.EPSSThreshold != 0.1 {
		t.Fatalf("loosened = %+v", got)
	}
	// The original policy's rule map is not changed.
	if p.Modes.Rules["go.weak"] != FindingModeComment {
		t.Fatal("Tighten changed the resolved policy's modes")
	}
}

func TestRepoPolicyValidate(t *testing.T) {
	now := time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC)
	ok := RepoPolicy{FailOnSeverity: "medium", Exceptions: []RepoException{{RuleID: "go.sqli", Path: "legacy/**",
		Reason: "legacy code being removed", Expires: "2026-12-01"}}}
	if err := ok.Validate(now); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]RepoPolicy{
		"severity":   {FailOnSeverity: "info"},
		"epss":       {EPSSThreshold: func() *float64 { v := 2.0; return &v }()},
		"no rule":    {Exceptions: []RepoException{{Reason: "long enough reason", Expires: "2026-11-01"}}},
		"short why":  {Exceptions: []RepoException{{RuleID: "r", Reason: "short", Expires: "2026-11-01"}}},
		"past":       {Exceptions: []RepoException{{RuleID: "r", Reason: "long enough reason", Expires: "2026-10-01"}}},
		"too far":    {Exceptions: []RepoException{{RuleID: "r", Reason: "long enough reason", Expires: "2027-06-01"}}},
		"control":    {BlockRules: []string{"a\nb"}},
		"many rules": {BlockRules: strings.Split(strings.Repeat("r,", MaxRepoBlockRules+1), ",")},
	} {
		if err := bad.Validate(now); !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
}
