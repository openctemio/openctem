package scanprofile_test

import (
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scannertemplate"
	"github.com/openctemio/openctem/api/pkg/domain/scanprofile"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestProfileRuleSources(t *testing.T) {
	p, err := scanprofile.NewScanProfile(shared.NewID(), "p", "", nil, scanprofile.IntensityMedium, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.RuleSources != scannertemplate.RuleSourcesBoth {
		t.Fatalf("new profile = %q, want both", p.RuleSources)
	}
	if err := p.SetRuleSources("tenant"); err != nil || p.RuleSources != scannertemplate.RuleSourcesTenant {
		t.Fatalf("set tenant: %q, %v", p.RuleSources, err)
	}
	if c, _ := p.Clone("copy", nil); c.RuleSources != scannertemplate.RuleSourcesTenant {
		t.Fatalf("clone lost rule sources: %q", c.RuleSources)
	}
	if err := p.SetRuleSources(""); err != nil || p.RuleSources != scannertemplate.RuleSourcesBoth {
		t.Fatalf("empty must reset to both: %q, %v", p.RuleSources, err)
	}
	if err := p.SetRuleSources("everything"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown value: %v", err)
	}
	p.IsSystem = true
	if err := p.SetRuleSources("platform"); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("system profile changed: %v", err)
	}
}
