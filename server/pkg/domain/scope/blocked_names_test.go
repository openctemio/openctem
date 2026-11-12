package scope

import (
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestNormalizeExceptionName(t *testing.T) {
	cases := []struct {
		in   string
		want string
		err  error
	}{
		{"Portal.Example.gov.xx.", "portal.example.gov.xx", nil},
		{"agency.gov", "agency.gov", nil},
		{"ministry.gc.ca", "ministry.gc.ca", nil},
		{"base.army.mil", "base.army.mil", nil},
		{"gov.xx", "", ErrExceptionTooWide},
		{"gov", "", ErrExceptionName},
		{"gc.ca", "", ErrExceptionTooWide},
		{"*.example.gov.xx", "", ErrExceptionName},
		{"example.com", "", ErrExceptionNotGovernment},
		{"203.0.113.5", "", ErrExceptionNotGovernment},
		{"", "", ErrExceptionName},
		{"a b.gov", "", ErrExceptionName},
	}
	for _, c := range cases {
		got, err := NormalizeExceptionName(c.in)
		if !errors.Is(err, c.err) || got != c.want {
			t.Errorf("NormalizeExceptionName(%q) = %q, %v; want %q, %v", c.in, got, err, c.want, c.err)
		}
	}
}

// testPolicy is a policy with one exception for tenant a.
func testPolicy(t *testing.T, now time.Time, ex ...NameException) *NamePolicy {
	t.Helper()
	p := NewNamePolicy()
	p.SetClock(func() time.Time { return now })
	p.Set(NameSnapshot{Exceptions: ex})
	return p
}

func TestGuardrails_GovernmentExceptions(t *testing.T) {
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	a, b := shared.NewID(), shared.NewID()
	exact := NameException{TenantID: a, Name: "sub.example.gov.xx", ExpiresAt: now.Add(time.Hour)}
	wide := NameException{TenantID: a, Name: "agency.gov", Subdomains: true, ExpiresAt: now.Add(time.Hour)}
	expired := NameException{TenantID: a, Name: "old.example.gov.xx", ExpiresAt: now.Add(-time.Second)}
	g := DefaultGuardrails().WithNamePolicy(testPolicy(t, now, exact, wide, expired))

	cases := []struct {
		name    string
		g       Guardrails
		typ     TargetType
		pattern string
		want    error
	}{
		{"exact name, its organization", g.For(a), TargetTypeDomain, "sub.example.gov.xx", nil},
		{"exact URL, its organization", g.For(a), TargetTypeURL, "https://sub.example.gov.xx/login", nil},
		{"other organization", g.For(b), TargetTypeDomain, "sub.example.gov.xx", ErrGovernmentName},
		{"no organization", g, TargetTypeDomain, "sub.example.gov.xx", ErrGovernmentName},
		{"parent of the exact name", g.For(a), TargetTypeDomain, "example.gov.xx", ErrGovernmentName},
		{"sibling of the exact name", g.For(a), TargetTypeDomain, "other.example.gov.xx", ErrGovernmentName},
		{"child of the exact name", g.For(a), TargetTypeDomain, "deep.sub.example.gov.xx", ErrGovernmentName},
		{"wildcard over an exact exception", g.For(a), TargetTypeDomain, "*.sub.example.gov.xx", ErrGovernmentName},
		{"lookalike suffix", g.For(a), TargetTypeDomain, "xsub.example.gov.xx", ErrGovernmentName},
		{"subdomain exception, name", g.For(a), TargetTypeDomain, "agency.gov", nil},
		{"subdomain exception, wildcard", g.For(a), TargetTypeDomain, "*.agency.gov", nil},
		{"subdomain exception, child", g.For(a), TargetTypeDomain, "portal.agency.gov", nil},
		{"subdomain exception, other agency", g.For(a), TargetTypeDomain, "otheragency.gov", ErrGovernmentName},
		{"subdomain exception, the suffix", g.For(a), TargetTypeDomain, "*.gov", ErrPublicSuffix},
		{"expired exception", g.For(a), TargetTypeDomain, "old.example.gov.xx", ErrGovernmentName},
		{"repository on an excepted host", g.For(a), TargetTypeRepository, "git.agency.gov/team/*", nil},
	}
	for _, c := range cases {
		if err := c.g.CheckPattern(c.typ, c.pattern); !errors.Is(err, c.want) {
			t.Errorf("%s: CheckPattern(%s, %q) = %v, want %v", c.name, c.typ, c.pattern, err, c.want)
		}
	}

	// Dispatch: the same answers.
	disp := []struct {
		g      Guardrails
		target string
		want   bool
	}{
		{g.For(a), "sub.example.gov.xx", false},
		{g.For(a), "https://sub.example.gov.xx:8443/x", false},
		{g.For(a), "sub.example.gov.xx:443", false},
		{g.For(b), "sub.example.gov.xx", true},
		{g, "sub.example.gov.xx", true},
		{g.For(a), "example.gov.xx", true},
		{g.For(a), "old.example.gov.xx", true},
		{g.For(a), "*.sub.example.gov.xx", true},
		{g.For(a), "www.agency.gov", false},
	}
	for _, d := range disp {
		if got := d.g.Denies(d.target); got != d.want {
			t.Errorf("Denies(%q) tenant=%v = %v, want %v", d.target, d.g.tenant, got, d.want)
		}
	}
}

func TestGuardrails_ExceptionExpiresWithTheClock(t *testing.T) {
	now := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	a := shared.NewID()
	p := testPolicy(t, now, NameException{TenantID: a, Name: "sub.example.gov.xx", ExpiresAt: now.Add(time.Minute)})
	g := DefaultGuardrails().WithNamePolicy(p).For(a)
	if g.Denies("sub.example.gov.xx") {
		t.Fatal("an active exception must lift the rule")
	}
	p.SetClock(func() time.Time { return now.Add(time.Minute) })
	if !g.Denies("sub.example.gov.xx") || !errors.Is(g.CheckPattern(TargetTypeDomain, "sub.example.gov.xx"), ErrGovernmentName) {
		t.Fatal("an exception must stop at its expiry, at add and at dispatch, with no refresh")
	}
}

func TestGuardrails_GovernmentRuleOffAndOperatorNames(t *testing.T) {
	p := NewNamePolicy()
	g, _ := NewGuardrails(0, 0, []string{"env.example"})
	g = g.WithNamePolicy(p)
	p.Set(NameSnapshot{GovernmentRuleOff: true, Names: []string{"Console.Example"}})
	if err := g.CheckPattern(TargetTypeDomain, "*.agency.gov"); err != nil {
		t.Fatalf("rule off: %v", err)
	}
	for _, n := range []string{"a.console.example", "env.example"} {
		if err := g.CheckPattern(TargetTypeDomain, n); !errors.Is(err, ErrDenyList) {
			t.Errorf("operator name %q: %v, want DENY_LIST", n, err)
		}
	}
	// Hard-coded guardrails do not move with the policy.
	for _, c := range []struct {
		typ TargetType
		p   string
		err error
	}{
		{TargetTypeIPAddress, "169.254.169.254", ErrDenyList},
		{TargetTypeIPAddress, "127.0.0.1", ErrDenyList},
		{TargetTypeCIDR, "0.0.0.0/0", ErrDenyList},
		{TargetTypeDomain, "*.com", ErrPublicSuffix},
		{TargetTypeDomain, "*.amazonaws.com", ErrPublicSuffix},
		{TargetTypeCIDR, "8.0.0.0/15", ErrCIDRTooLarge},
	} {
		if err := g.CheckPattern(c.typ, c.p); !errors.Is(err, c.err) {
			t.Errorf("%q: %v, want %v", c.p, err, c.err)
		}
	}
	// An exception never lifts the operator's own names.
	a := shared.NewID()
	p.Set(NameSnapshot{Names: []string{"example.gov.xx"}, Exceptions: []NameException{
		{TenantID: a, Name: "sub.example.gov.xx", ExpiresAt: time.Now().Add(time.Hour)},
	}})
	if err := g.For(a).CheckPattern(TargetTypeDomain, "sub.example.gov.xx"); !errors.Is(err, ErrDenyList) {
		t.Fatalf("operator name with an exception: %v, want DENY_LIST", err)
	}
}

func TestPlatformNamePolicy_ReachesDefaultGuardrails(t *testing.T) {
	p := NewNamePolicy()
	SetPlatformNamePolicy(p)
	t.Cleanup(func() { SetPlatformNamePolicy(nil) })
	g := DefaultGuardrails() // built once, reads every later change
	if !g.Denies("portal.agency.gov") {
		t.Fatal("rule on by default")
	}
	p.Set(NameSnapshot{GovernmentRuleOff: true})
	if g.Denies("portal.agency.gov") {
		t.Fatal("a built guardrails must see the policy change")
	}
}

func TestNamePolicy_RefreshesWhenStale(t *testing.T) {
	now := time.Now()
	p := NewNamePolicy()
	p.SetClock(func() time.Time { return now })
	done := make(chan struct{}, 1)
	p.OnStale(time.Second, func() {
		p.Set(NameSnapshot{GovernmentRuleOff: true})
		done <- struct{}{}
	})
	_ = p.Snapshot() // fresh: no refresh
	now = now.Add(2 * time.Second)
	_ = p.Snapshot()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a stale snapshot must trigger a refresh")
	}
	if !p.Snapshot().GovernmentRuleOff {
		t.Fatal("refresh result not applied")
	}
}
