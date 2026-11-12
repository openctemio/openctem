package scopeauth

import (
	"context"
	"errors"
	"testing"
	"time"

	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeSources struct {
	tenant   shared.ID
	targets  []*scopedom.Target
	verified []string
	err      error
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

func (f *fakeSources) VerifiedDomainNames(_ context.Context, t shared.ID) ([]string, error) {
	if !t.Equals(f.tenant) {
		return nil, nil
	}
	return f.verified, nil
}

func newSources(t *testing.T) *fakeSources {
	t.Helper()
	f := &fakeSources{tenant: shared.NewID(), verified: []string{"Verified.com.", "scoped.com"}}
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
		proof string
	}{
		{"app.scoped.com", ProofVerified}, // under the verified scoped.com
		{"https://app.scoped.com:8443/x", ProofVerified},
		{"app.scoped.com:443:tcp", ProofVerified},
		{"app.scoped.com:443/tcp", ProofVerified},
		{"198.51.100.9", ProofAsserted},
		{"198.51.100.9:443", ProofAsserted},
		{"198.51.100.9:443:tcp", ProofAsserted},
		{"github.com/org/repo", ProofAsserted},
	}
	for _, c := range cases {
		via, ok := a.Covers(c.name)
		if !ok || via.Kind != KindScopeTarget || via.Proof != c.proof {
			t.Errorf("Covers(%q) = %+v, %v; want a scope entry with proof %s", c.name, via, ok, c.proof)
		}
	}
	// Only entries authorize (research/53 SC1, SC2): a verified domain alone
	// (of any purpose) authorizes nothing.
	for _, n := range []string{"verified.com", "www.verified.com", "www.verified.com:443:tcp", "notscoped.com",
		"scoped.com.evil.net", "203.0.113.5", "203.0.113.5:443:tcp", "198.51.100.0/23", "github.com/other/repo", ""} {
		if via, ok := a.Covers(n); ok {
			t.Errorf("Covers(%q) = %+v, want not covered", n, via)
		}
	}
	if !a.Verified("api.verified.com") || a.Verified("api.other.com") || a.Verified("198.51.100.9") {
		t.Error("Verified must answer only for names at or under a verified domain")
	}
}

// Another tenant's entries and verified domains count for nothing.
func TestCovers_OtherTenant(t *testing.T) {
	f := newSources(t)
	a, err := Load(context.Background(), shared.NewID(), f, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"app.scoped.com", "www.verified.com", "198.51.100.9"} {
		if via, ok := a.Covers(n); ok {
			t.Errorf("another tenant's authority covered %q: %+v", n, via)
		}
	}
	if a.Verified("www.verified.com") {
		t.Error("another tenant's verified domain proved control")
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

// RFC-054 §4.2 step 6: an entry covers up to its max_tier (t1 by default); a
// verified domain authorizes no tier. Another tenant's higher entry lifts
// nothing.
func TestCoversAt(t *testing.T) {
	f := newSources(t)
	now := time.Now()
	low, _ := scopedom.NewTarget(f.tenant, scopedom.TargetTypeDomain, "low.com", "", "")
	low.SetMaxTier(scopedom.TierPassive, now)
	high, _ := scopedom.NewTarget(f.tenant, scopedom.TargetTypeDomain, "*.intrusive.com", "", "")
	high.SetMaxTier(scopedom.TierIntrusive, now)
	f.targets = append(f.targets, low, high)
	a, err := Load(context.Background(), f.tenant, f, f)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		tier scopedom.Tier
		want bool
	}{
		{"low.com", scopedom.TierPassive, true},
		{"low.com", scopedom.TierActive, false},
		{"app.scoped.com", scopedom.TierActive, true}, // default t1
		{"app.scoped.com", scopedom.TierIntrusive, false},
		{"www.verified.com", scopedom.TierPassive, false}, // proof only
		{"a.intrusive.com", scopedom.TierIntrusive, true},
		{"nothing.com", scopedom.TierPassive, false},
	}
	for _, c := range cases {
		if _, ok := a.CoversAt(c.name, c.tier); ok != c.want {
			t.Errorf("CoversAt(%q, %s) = %v, want %v", c.name, c.tier, ok, c.want)
		}
	}
	if c := a.Ceiling("low.com"); c == nil || c.ID() != low.ID() {
		t.Errorf("Ceiling(low.com) = %v", c)
	}
	if c := a.Ceiling("www.verified.com"); c != nil {
		t.Errorf("a verified domain has no entry to raise: %v", c)
	}

	other, err := Load(context.Background(), shared.NewID(), f, f)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := other.CoversAt("a.intrusive.com", scopedom.TierPassive); ok {
		t.Error("another tenant's entry covered a name")
	}
}

// Rows of a type with no matcher (or a wildcard URL host) that exist in the
// database from before validation refused them cover nothing: no probe of an
// arbitrary host or address is authorized by them. The deny list is not
// involved here; the gate evaluates it first.
func TestStoredWildcardRowsAuthorizeNothing(t *testing.T) {
	tenant := shared.NewID()
	f := &fakeSources{tenant: tenant}
	now := time.Now()
	for i, r := range []struct {
		typ     scopedom.TargetType
		pattern string
	}{
		{scopedom.TargetTypeCertificate, "*"}, {scopedom.TargetTypeContainer, "*"},
		{scopedom.TargetTypeDatabase, "*"}, {scopedom.TargetTypeMobileApp, "*"},
		{scopedom.TargetTypeCloudResource, "*"}, {scopedom.TargetTypeNetwork, "*"},
		{scopedom.TargetTypeURL, "*"}, {scopedom.TargetTypeURL, "https://*"},
		{scopedom.TargetTypeWebsite, "*"}, {scopedom.TargetTypeAPI, "*"},
		{scopedom.TargetTypeHost, "*"}, {scopedom.TargetTypeProject, "*"},
	} {
		_ = i
		f.targets = append(f.targets, scopedom.ReconstituteTarget(shared.NewID(), tenant, r.typ, r.pattern, "", 0,
			scopedom.StatusActive, nil, "", now, now))
	}
	a, err := Load(context.Background(), tenant, f, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"victim.example", "203.0.113.9", "203.0.113.9:443", "https://victim.example/x", "198.51.100.0/24", "github.com/victim/repo"} {
		if v, ok := a.Covers(name); ok {
			t.Errorf("Covers(%q) = %+v", name, v)
		}
		if _, ok := a.CoversAt(name, scopedom.TierActive); ok {
			t.Errorf("CoversAt(%q) is covered", name)
		}
	}
}

// Label-boundary vectors at the API gate: a name is covered only when it is
// the entry's own name or a whole label below it, in every spelling.
func TestCovers_LabelBoundary(t *testing.T) {
	f := newSources(t)
	a, err := Load(context.Background(), f.tenant, f, f)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"app.scoped.com", "APP.Scoped.COM.", "scoped.com", "scoped.com.", "app.scoped.com:8443",
		"https://app.scoped.com./x", "http://scoped.com:80"} {
		if _, ok := a.Covers(n); !ok {
			t.Errorf("Covers(%q) = false, want covered", n)
		}
	}
	for _, n := range []string{"notscoped.com", "notscoped.com:443", "https://notscoped.com/", "scoped.com.evil.test",
		"https://scoped.com.evil.test:8443/", "scoped.com@evil.test", "https://scoped.com@evil.test/",
		"evil-scoped.com", "scoped.co", "com", "https://evil.test/?h=app.scoped.com"} {
		if via, ok := a.Covers(n); ok {
			t.Errorf("Covers(%q) = %+v, want not covered", n, via)
		}
	}
}

// Two tenants with entries on different roots: each gate answers only for
// its own entries, whatever the spelling.
func TestCovers_TenantsDoNotShareEntries(t *testing.T) {
	a1, a2 := newSources(t), newSources(t)
	other, err := scopedom.NewTarget(a2.tenant, scopedom.TargetTypeDomain, "*.other.example", "", "")
	if err != nil {
		t.Fatal(err)
	}
	a2.targets = []*scopedom.Target{other}
	auth1, err := Load(context.Background(), a1.tenant, a1, a1)
	if err != nil {
		t.Fatal(err)
	}
	auth2, err := Load(context.Background(), a2.tenant, a2, a2)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"app.other.example", "app.other.example:443", "https://APP.other.example./"} {
		if _, ok := auth1.Covers(n); ok {
			t.Errorf("tenant 1 covered tenant 2's name %q", n)
		}
		if _, ok := auth2.Covers(n); !ok {
			t.Errorf("tenant 2 does not cover its own name %q", n)
		}
	}
	for _, n := range []string{"app.scoped.com", "app.scoped.com:443"} {
		if _, ok := auth2.Covers(n); ok {
			t.Errorf("tenant 2 covered tenant 1's name %q", n)
		}
	}
}
