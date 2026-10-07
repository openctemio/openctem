package scopeauth

import (
	"context"
	"errors"
	"testing"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeSources struct {
	tenant          shared.ID
	targets         []*scopedom.Target
	seeds, verified []string
	// sso: domains verified for SSO sign-in (proof only, never authority).
	sso []string
	err error
}

func (f *fakeSources) ListActiveTargets(_ context.Context, t string) ([]*scopedom.Target, error) {
	if f.err != nil {
		return nil, f.err
	}
	if t != f.tenant.String() {
		return nil, nil
	}
	return f.targets, nil
}

func (f *fakeSources) RootDomainSeedNames(_ context.Context, t shared.ID) ([]string, error) {
	if !t.Equals(f.tenant) {
		return nil, nil
	}
	return f.seeds, nil
}

func (f *fakeSources) VerifiedDomainNames(_ context.Context, t shared.ID) ([]string, error) {
	if !t.Equals(f.tenant) {
		return nil, nil
	}
	return append(append([]string{}, f.verified...), f.sso...), nil
}

func (f *fakeSources) EASMVerifiedDomainNames(_ context.Context, t shared.ID) ([]string, error) {
	if !t.Equals(f.tenant) {
		return nil, nil
	}
	return f.verified, nil
}

func newSources(t *testing.T) *fakeSources {
	t.Helper()
	f := &fakeSources{tenant: shared.NewID(), seeds: []string{"Seeded.com."}, verified: []string{"verified.com"}}
	for _, p := range []struct {
		typ     scopedom.TargetType
		pattern string
	}{{scopedom.TargetTypeDomain, "*.scoped.com"}, {scopedom.TargetTypeCIDR, "198.51.100.0/24"}, {scopedom.TargetTypeRepository, "github.com/org/*"}} {
		st, err := scopedom.NewTarget(f.tenant, p.typ, p.pattern, "", "")
		if err != nil {
			t.Fatal(err)
		}
		f.targets = append(f.targets, st)
	}
	return f
}

func TestCovers(t *testing.T) {
	f := newSources(t)
	a, err := Load(context.Background(), f.tenant, f, f)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		kind  string
		proof string
	}{
		{"app.scoped.com", KindScopeTarget, ProofAsserted},
		{"https://app.scoped.com:8443/x", KindScopeTarget, ProofAsserted},
		{"198.51.100.9", KindScopeTarget, ProofAsserted},
		{"198.51.100.9:443", KindScopeTarget, ProofAsserted},
		{"app.scoped.com:443:tcp", KindScopeTarget, ProofAsserted},
		{"app.scoped.com:443/tcp", KindScopeTarget, ProofAsserted},
		{"198.51.100.9:443:tcp", KindScopeTarget, ProofAsserted},
		{"www.verified.com:443:tcp", KindVerifiedDomain, ProofVerified},
		{"github.com/org/repo", KindScopeTarget, ProofAsserted},
		{"seeded.com", KindSeed, ProofAsserted},
		{"a.b.seeded.com", KindSeed, ProofAsserted},
		{"verified.com", KindVerifiedDomain, ProofVerified},
		{"www.verified.com", KindVerifiedDomain, ProofVerified},
	}
	for _, c := range cases {
		via, ok := a.Covers(c.name)
		if !ok || via.Kind != c.kind || via.Proof != c.proof {
			t.Errorf("Covers(%q) = %+v, %v; want kind %s proof %s", c.name, via, ok, c.kind, c.proof)
		}
	}
	for _, n := range []string{"notseeded.com", "notseeded.com:443:tcp", "203.0.113.5:443:tcp", "seeded.com.evil.net", "203.0.113.5", "198.51.100.0/23", "github.com/other/repo", ""} {
		if via, ok := a.Covers(n); ok {
			t.Errorf("Covers(%q) = %+v, want not covered", n, via)
		}
	}
	if !a.Verified("api.verified.com") || a.Verified("api.seeded.com") || a.Verified("198.51.100.9") {
		t.Error("Verified must answer only for names at or under a verified domain")
	}
}

// Another tenant's targets, seeds and verified domains cover nothing.
func TestCovers_OtherTenant(t *testing.T) {
	f := newSources(t)
	a, err := Load(context.Background(), shared.NewID(), f, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"app.scoped.com", "seeded.com", "www.verified.com", "198.51.100.9"} {
		if via, ok := a.Covers(n); ok {
			t.Errorf("another tenant's authority covered %q: %+v", n, via)
		}
	}
}

func TestLoad_FailsClosed(t *testing.T) {
	f := newSources(t)
	if _, err := Load(context.Background(), f.tenant, nil, f); err == nil {
		t.Error("nil targets must fail")
	}
	if _, err := Load(context.Background(), f.tenant, f, nil); err == nil {
		t.Error("nil roots must fail")
	}
	if _, err := Load(context.Background(), shared.ID{}, f, f); err == nil {
		t.Error("zero tenant must fail")
	}
	f.err = errors.New("db down")
	if _, err := Load(context.Background(), f.tenant, f, f); err == nil {
		t.Error("a lookup error must fail")
	}
	var nilAuth *Authority
	if _, ok := nilAuth.Covers("app.scoped.com"); ok {
		t.Error("a nil authority covers nothing")
	}
}

// A domain a platform administrator verified for SSO sign-in never
// authorizes active probes (owner decision SC2); it still proves control, so
// a scope entry under it reports proof "verified".
func TestCovers_SSOVerifiedDomainIsProofNotAuthority(t *testing.T) {
	f := newSources(t)
	f.sso = []string{"signin.com", "scoped.com"}
	a, err := Load(context.Background(), f.tenant, f, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"signin.com", "www.signin.com", "https://app.signin.com/login"} {
		if via, ok := a.Covers(n); ok {
			t.Errorf("an SSO-verified domain authorized %q: %+v", n, via)
		}
	}
	if !a.Verified("www.signin.com") {
		t.Error("an SSO-verified domain is still proof of control")
	}
	via, ok := a.Covers("app.scoped.com")
	if !ok || via.Kind != KindScopeTarget || via.Proof != ProofVerified {
		t.Errorf("scope entry under an SSO-verified domain: %+v %v", via, ok)
	}
	// An easm-purpose verified domain still authorizes.
	if via, ok := a.Covers("www.verified.com"); !ok || via.Kind != KindVerifiedDomain {
		t.Errorf("easm verified domain: %+v %v", via, ok)
	}
}
