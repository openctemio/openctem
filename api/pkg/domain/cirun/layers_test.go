package cirun

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func layer(scope string, fields []string, set func(*GatePolicy)) GatePolicy {
	p := DefaultGatePolicy()
	p.ID = shared.NewID()
	p.ScopeType = scope
	p.Fields = fields
	if scope != ScopeTenant {
		id := shared.NewID()
		p.ScopeID = &id
	}
	if set != nil {
		set(&p)
	}
	return p
}

func TestResolve_PerFieldInheritance(t *testing.T) {
	now := time.Now()
	org := layer(ScopeTenant, PolicyFields, func(p *GatePolicy) { p.FailOnSeverity = "medium"; p.FailOnKEV = false })
	// The repository sets only the severity; KEV keeps following the org.
	repo := layer(ScopeRepository, []string{FieldFailOnSeverity}, func(p *GatePolicy) { p.FailOnSeverity = "low"; p.FailOnKEV = true })
	res := Resolve([]GatePolicy{org, repo}, now)
	if res.Policy.FailOnSeverity != "low" || res.Field(FieldFailOnSeverity).Source != ScopeRepository {
		t.Fatalf("severity %s from %s", res.Policy.FailOnSeverity, res.Field(FieldFailOnSeverity).Source)
	}
	if res.Policy.FailOnKEV || res.Field(FieldFailOnKEV).Source != ScopeTenant {
		t.Fatalf("an unset field was not inherited: kev=%v from %s", res.Policy.FailOnKEV, res.Field(FieldFailOnKEV).Source)
	}
	if res.Source != ScopeRepository || res.Inherited.FailOnSeverity != "medium" {
		t.Fatalf("source %s inherited %s", res.Source, res.Inherited.FailOnSeverity)
	}
	// No policy at all: the built-in default.
	if d := Resolve(nil, now); d.Source != ScopeDefault || d.Policy.FailOnSeverity != "high" {
		t.Fatalf("default: %+v", d)
	}
}

func TestResolve_LockIsAFloor(t *testing.T) {
	now := time.Now()
	org := layer(ScopeTenant, PolicyFields, func(p *GatePolicy) { p.LockedFields = []string{FieldFailOnSeverity, FieldMode} })
	looser := layer(ScopeRepository, []string{FieldFailOnSeverity, FieldMode, FieldFailOnKEV}, func(p *GatePolicy) {
		p.FailOnSeverity, p.Mode, p.FailOnKEV = "critical", ModeWarn, false
	})
	res := Resolve([]GatePolicy{org, looser}, now)
	if res.Policy.FailOnSeverity != "high" || res.Policy.Mode != ModeEnforce {
		t.Fatalf("a locked field was loosened: %s %s", res.Policy.FailOnSeverity, res.Policy.Mode)
	}
	if fr := res.Field(FieldFailOnSeverity); !fr.Ignored || fr.LockedBy != ScopeTenant || fr.Source != ScopeTenant {
		t.Fatalf("severity resolution %+v", fr)
	}
	// An unlocked field is the repository's.
	if res.Policy.FailOnKEV || res.Field(FieldFailOnKEV).Source != ScopeRepository {
		t.Fatal("unlocked field not overridden")
	}
	// Tightening a locked field is allowed.
	stricter := layer(ScopeRepository, []string{FieldFailOnSeverity}, func(p *GatePolicy) { p.FailOnSeverity = "low" })
	if res := Resolve([]GatePolicy{org, stricter}, now); res.Policy.FailOnSeverity != "low" || res.Field(FieldFailOnSeverity).Ignored {
		t.Fatalf("tightening a locked field: %s", res.Policy.FailOnSeverity)
	}
	// A business unit lock binds the repository too, and a business unit
	// cannot loosen what the organization locks.
	unit := layer(ScopeBusinessUnit, []string{FieldFailOnSeverity, FieldNewFindingsOnly}, func(p *GatePolicy) {
		p.FailOnSeverity, p.NewFindingsOnly, p.LockedFields = "critical", false, []string{FieldNewFindingsOnly}
	})
	repoAll := layer(ScopeRepository, []string{FieldNewFindingsOnly}, func(p *GatePolicy) { p.NewFindingsOnly = true })
	res = Resolve([]GatePolicy{org, unit, repoAll}, now)
	if res.Policy.FailOnSeverity != "high" || !res.Field(FieldFailOnSeverity).Ignored {
		t.Fatalf("business unit loosened an org lock: %s", res.Policy.FailOnSeverity)
	}
	if res.Policy.NewFindingsOnly || res.Field(FieldNewFindingsOnly).LockedBy != ScopeBusinessUnit {
		t.Fatalf("business unit lock: %+v", res.Field(FieldNewFindingsOnly))
	}
}

func TestResolve_ExpiredAndDisabledRepositoryPolicy(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Minute)
	repo := layer(ScopeRepository, []string{FieldFailOnSeverity}, func(p *GatePolicy) { p.FailOnSeverity = "critical"; p.ExpiresAt = &past })
	res := Resolve([]GatePolicy{repo}, now)
	if res.Policy.FailOnSeverity != "high" || !res.RepositoryExpired || res.Repository == nil {
		t.Fatalf("expired override applied: %s expired=%v", res.Policy.FailOnSeverity, res.RepositoryExpired)
	}
	repo.ExpiresAt, repo.Enabled = nil, false
	if res := Resolve([]GatePolicy{repo}, now); res.Policy.FailOnSeverity != "high" || res.RepositoryExpired {
		t.Fatalf("disabled override applied: %+v", res.Policy)
	}
}

func TestResolve_BusinessUnitsStrictestPerField(t *testing.T) {
	now := time.Now()
	a := layer(ScopeBusinessUnit, []string{FieldFailOnSeverity}, func(p *GatePolicy) { p.FailOnSeverity = "medium" })
	b := layer(ScopeBusinessUnit, []string{FieldFailOnSeverity, FieldFailOnKEV}, func(p *GatePolicy) { p.FailOnSeverity = "low"; p.FailOnKEV = false })
	res := Resolve([]GatePolicy{a, b}, now)
	if res.Policy.FailOnSeverity != "low" || res.Policy.FailOnKEV {
		t.Fatalf("strictest per field: %s kev=%v", res.Policy.FailOnSeverity, res.Policy.FailOnKEV)
	}
}

func TestValidateLayer(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		p    GatePolicy
	}{
		{"unknown field", layer(ScopeRepository, []string{"nope"}, nil)},
		{"partial org", layer(ScopeTenant, []string{FieldMode}, nil)},
		{"repo lock", layer(ScopeRepository, nil, func(p *GatePolicy) { p.LockedFields = []string{FieldMode} })},
		{"org expiry", layer(ScopeTenant, PolicyFields, func(p *GatePolicy) { t := now.Add(time.Hour); p.ExpiresAt = &t })},
		{"past expiry", layer(ScopeRepository, nil, func(p *GatePolicy) { t := now.Add(-time.Hour); p.ExpiresAt = &t })},
		{"far expiry", layer(ScopeRepository, nil, func(p *GatePolicy) { t := now.AddDate(2, 0, 0); p.ExpiresAt = &t })},
	}
	for _, c := range cases {
		if err := c.p.ValidateLayer(now); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	ok := layer(ScopeRepository, []string{FieldModes, FieldMode, FieldMode}, func(p *GatePolicy) { t := now.AddDate(0, 1, 0); p.ExpiresAt = &t })
	if err := ok.ValidateLayer(now); err != nil || !slices.Equal(ok.Fields, []string{FieldMode, FieldModes}) {
		t.Fatalf("valid layer: %v %v", err, ok.Fields)
	}
}

// The repository file never loosens, whatever the resolved policy is.
func TestTighten_NeverLoosensResolvedPolicy(t *testing.T) {
	no, yes := false, true
	base := Resolve([]GatePolicy{layer(ScopeTenant, PolicyFields, func(p *GatePolicy) {
		p.FailOnSeverity, p.NewFindingsOnly = "medium", false
	})}, time.Now()).Policy
	got := base.Tighten(&RepoPolicy{FailOnSeverity: "critical", NewFindingsOnly: &yes, FailOnKEV: &no})
	if len(Loosens(base, got)) > 0 {
		t.Fatalf("file loosened: %v", Loosens(base, got))
	}
}
