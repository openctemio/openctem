package actscope

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// fakeEnforcer: restricted to inScope unless unrestricted.
type fakeEnforcer struct {
	unrestricted bool
	inScope      map[shared.ID]bool
	err          error
	gotFallback  *shared.ID
}

func (f *fakeEnforcer) CanActOnAssets(_ context.Context, _ shared.ID, fallback *shared.ID, _ []shared.ID) (func(shared.ID) bool, bool, error) {
	f.gotFallback = fallback
	if f.err != nil {
		return nil, false, f.err
	}
	if f.unrestricted {
		return func(shared.ID) bool { return true }, true, nil
	}
	return func(id shared.ID) bool { return f.inScope[id] }, false, nil
}

// tenantAssets holds assets by name per tenant.
type tenantAssets map[shared.ID]map[string]*asset.Asset

func (t tenantAssets) GetByNames(_ context.Context, tenantID shared.ID, names []string) (map[string]*asset.Asset, error) {
	out := map[string]*asset.Asset{}
	for _, n := range names {
		if a, ok := t[tenantID][n]; ok {
			out[n] = a
		}
	}
	return out, nil
}

type failingAssets struct{}

func (failingAssets) GetByNames(context.Context, shared.ID, []string) (map[string]*asset.Asset, error) {
	return nil, errors.New("db down")
}

// tenantTargets holds active scope targets per tenant.
type tenantTargets map[string][]*scopedom.Target

func (t tenantTargets) ListActiveTargets(_ context.Context, tenantID string) ([]*scopedom.Target, error) {
	return t[tenantID], nil
}

// tenantRoots holds root-domain seeds and verified domains per tenant.
type tenantRoots struct{ seeds, verified map[shared.ID][]string }

func (r tenantRoots) RootDomainSeedNames(_ context.Context, t shared.ID) ([]string, error) {
	return r.seeds[t], nil
}

func (r tenantRoots) VerifiedDomainNames(_ context.Context, t shared.ID) ([]string, error) {
	return r.verified[t], nil
}

type failingRoots struct{}

func (failingRoots) RootDomainSeedNames(context.Context, shared.ID) ([]string, error) {
	return nil, errors.New("db down")
}

func (failingRoots) VerifiedDomainNames(context.Context, shared.ID) ([]string, error) {
	return nil, nil
}

type failingTargets struct{}

func (failingTargets) ListActiveTargets(context.Context, string) ([]*scopedom.Target, error) {
	return nil, errors.New("db down")
}

func mustAsset(t *testing.T, name string) *asset.Asset {
	t.Helper()
	a, err := asset.NewAsset(name, asset.AssetTypeDomain, asset.CriticalityHigh)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func mustTarget(t *testing.T, tenant shared.ID, typ scopedom.TargetType, pattern string) *scopedom.Target {
	t.Helper()
	st, err := scopedom.NewTarget(tenant, typ, pattern, "", "test")
	if err != nil {
		t.Fatal(err)
	}
	return st
}

type fixture struct {
	tenantA, tenantB shared.ID
	mine, theirs     *asset.Asset
	assets           tenantAssets
	targets          tenantTargets
	roots            tenantRoots
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{tenantA: shared.NewID(), tenantB: shared.NewID()}
	f.mine = mustAsset(t, "mine.example.com")
	f.theirs = mustAsset(t, "theirs.example.com")
	bOnly := mustAsset(t, "b-only.example.com")
	f.assets = tenantAssets{
		f.tenantA: {"mine.example.com": f.mine, "theirs.example.com": f.theirs},
		f.tenantB: {"b-only.example.com": bOnly},
	}
	f.targets = tenantTargets{
		f.tenantA.String(): {mustTarget(t, f.tenantA, scopedom.TargetTypeDomain, "*.allowed.example.com")},
		f.tenantB.String(): {mustTarget(t, f.tenantB, scopedom.TargetTypeDomain, "*.b-allowed.example.com")},
	}
	f.roots = tenantRoots{
		seeds:    map[shared.ID][]string{f.tenantA: {"seeded.example.net"}, f.tenantB: {"b-seeded.example.net"}},
		verified: map[shared.ID][]string{f.tenantA: {"verified.example.net"}, f.tenantB: {"b-verified.example.net"}},
	}
	return f
}

// A restricted member scans only inventory assets in their data scope:
// another asset of the tenant and any free text (even one inside a scope
// target, even another tenant's asset name) are refused.
func TestCheck_RestrictedMember(t *testing.T) {
	f := newFixture(t)
	enf := &fakeEnforcer{inScope: map[shared.ID]bool{f.mine.ID(): true}}
	c := New(enf, f.assets, f.targets, f.roots)
	owner := shared.NewID()

	d, err := c.Check(context.Background(), Input{
		TenantID: f.tenantA, FallbackUser: &owner,
		Targets: []string{
			"mine.example.com", "https://MINE.example.com/login", "theirs.example.com",
			"app.allowed.example.com", "b-only.example.com", "203.0.113.5",
		},
		AssetIDs: []shared.ID{f.mine.ID(), f.theirs.ID()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if enf.gotFallback == nil || !enf.gotFallback.Equals(owner) {
		t.Fatal("the fallback user must reach the enforcer")
	}
	want := map[string]string{
		"theirs.example.com":      ReasonOutOfDataScope,
		"app.allowed.example.com": ReasonNotAnAsset,
		"b-only.example.com":      ReasonNotAnAsset,
		"203.0.113.5":             ReasonNotAnAsset,
	}
	if len(d.RefusedTargets) != len(want) {
		t.Fatalf("refused = %v, want %v", d.RefusedTargets, want)
	}
	for k, v := range want {
		if d.RefusedTargets[k] != v {
			t.Fatalf("refused[%s] = %q, want %q (all: %v)", k, d.RefusedTargets[k], v, d.RefusedTargets)
		}
	}
	if !d.RefusedAssets[f.theirs.ID()] || d.RefusedAssets[f.mine.ID()] || len(d.RefusedAssets) != 1 {
		t.Fatalf("refused assets = %v", d.RefusedAssets)
	}
}

// An unrestricted actor (admin, system) scans any inventory asset; free text
// must match one of the tenant's own active scope targets.
func TestCheck_UnrestrictedActorAllowlist(t *testing.T) {
	f := newFixture(t)
	c := New(&fakeEnforcer{unrestricted: true}, f.assets, f.targets, f.roots)
	d, err := c.Check(context.Background(), Input{
		TenantID: f.tenantA,
		Targets: []string{
			"theirs.example.com", "app.allowed.example.com", "https://x.allowed.example.com:8443/a",
			"evil.example.org", "app.b-allowed.example.com", "b-only.example.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"evil.example.org": true, "app.b-allowed.example.com": true, "b-only.example.com": true}
	if len(d.RefusedTargets) != len(want) {
		t.Fatalf("refused = %v, want %v", d.RefusedTargets, want)
	}
	for k := range want {
		if d.RefusedTargets[k] != ReasonNoScopeTarget {
			t.Fatalf("refused[%s] = %q, want the allowlist reason", k, d.RefusedTargets[k])
		}
	}
}

// Every failure refuses: an unwired checker, an enforcer, asset or allowlist
// lookup error.
func TestCheck_FailsClosed(t *testing.T) {
	f := newFixture(t)
	in := Input{TenantID: f.tenantA, Targets: []string{"x.example.org"}, AssetIDs: []shared.ID{f.mine.ID()}}
	cases := map[string]*Checker{
		"nil checker":       nil,
		"no enforcer":       New(nil, f.assets, f.targets, f.roots),
		"no assets":         New(&fakeEnforcer{unrestricted: true}, nil, f.targets, f.roots),
		"no targets":        New(&fakeEnforcer{unrestricted: true}, f.assets, nil, f.roots),
		"enforcer error":    New(&fakeEnforcer{err: errors.New("down")}, f.assets, f.targets, f.roots),
		"asset lookup":      New(&fakeEnforcer{unrestricted: true}, failingAssets{}, f.targets, f.roots),
		"allowlist lookup":  New(&fakeEnforcer{unrestricted: true}, f.assets, failingTargets{}, f.roots),
		"zero tenant input": New(&fakeEnforcer{unrestricted: true}, f.assets, f.targets, f.roots),
		"no roots":          New(&fakeEnforcer{unrestricted: true}, f.assets, f.targets, nil),
		"roots lookup":      New(&fakeEnforcer{unrestricted: true}, f.assets, f.targets, failingRoots{}),
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			input := in
			if name == "zero tenant input" {
				input.TenantID = shared.ID{}
			}
			if d, err := c.Check(context.Background(), input); err == nil {
				t.Fatalf("want an error, got %+v", d)
			}
		})
	}
}

// Free text gets the same authority as an inventory asset (RFC-054 §4.2):
// a name at or under a seed or verified domain of the tenant is covered, as
// is a name inside a scope target, and another tenant's seeds, verified
// domains and targets cover nothing.
func TestCheck_FreeTextUsesTheOneAuthority(t *testing.T) {
	f := newFixture(t)
	c := New(&fakeEnforcer{unrestricted: true}, f.assets, f.targets, f.roots)
	d, err := c.Check(context.Background(), Input{
		TenantID: f.tenantA,
		Targets: []string{
			"seeded.example.net", "www.seeded.example.net", "https://a.verified.example.net/x",
			"app.allowed.example.com",
			"b-seeded.example.net", "x.b-verified.example.net", "app.b-allowed.example.com",
			"notseeded.example.net",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"b-seeded.example.net": true, "x.b-verified.example.net": true, "app.b-allowed.example.com": true,
		"notseeded.example.net": true,
	}
	if len(d.RefusedTargets) != len(want) {
		t.Fatalf("refused = %v, want exactly %v", d.RefusedTargets, want)
	}
	for k := range want {
		if d.RefusedTargets[k] != ReasonNoScopeTarget {
			t.Fatalf("refused[%s] = %q, want the authority reason", k, d.RefusedTargets[k])
		}
	}
}
