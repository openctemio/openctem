package easm

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// gateFixture is one tenant's data; any other tenant sees nothing.
type gateFixture struct {
	tenant  shared.ID
	assets  map[string]*asset.Asset // by name
	records map[string]attribution.Record
	tombs   map[string]bool
	targets []*scopedom.Target
	seeds   []string
	vds     []string
	err     error
}

func (f *gateFixture) mine(t shared.ID) bool { return t.Equals(f.tenant) }

func (f *gateFixture) Records(_ context.Context, t shared.ID, ids []string) (map[string]attribution.Record, error) {
	out := map[string]attribution.Record{}
	if f.err != nil {
		return nil, f.err
	}
	if !f.mine(t) {
		return out, nil
	}
	for _, id := range ids {
		if r, ok := f.records[id]; ok {
			out[id] = r
		}
	}
	return out, nil
}

func (f *gateFixture) Tombstoned(_ context.Context, t shared.ID, names []string) (map[string][]attribution.Rule, error) {
	out := map[string][]attribution.Rule{}
	if !f.mine(t) {
		return out, nil
	}
	for _, n := range names {
		if f.tombs[n] {
			out[n] = nil
		}
	}
	return out, nil
}

func (f *gateFixture) GetByIDs(_ context.Context, t shared.ID, ids []shared.ID) (map[string]*asset.Asset, error) {
	out := map[string]*asset.Asset{}
	if !f.mine(t) {
		return out, nil
	}
	for _, a := range f.assets {
		for _, id := range ids {
			if a.ID().Equals(id) {
				out[id.String()] = a
			}
		}
	}
	return out, nil
}

func (f *gateFixture) GetByNames(_ context.Context, t shared.ID, names []string) (map[string]*asset.Asset, error) {
	out := map[string]*asset.Asset{}
	if !f.mine(t) {
		return out, nil
	}
	for _, n := range names {
		if a, ok := f.assets[n]; ok {
			out[n] = a
		}
	}
	return out, nil
}

func (f *gateFixture) ListActiveTargets(_ context.Context, t string) ([]*scopedom.Target, error) {
	if t != f.tenant.String() {
		return nil, nil
	}
	return f.targets, nil
}

func (f *gateFixture) RootDomainSeedNames(_ context.Context, t shared.ID) ([]string, error) {
	if !f.mine(t) {
		return nil, nil
	}
	return f.seeds, nil
}

func (f *gateFixture) VerifiedDomainNames(_ context.Context, t shared.ID) ([]string, error) {
	if !f.mine(t) {
		return nil, nil
	}
	return f.vds, nil
}

func (f *gateFixture) EASMVerifiedDomainNames(ctx context.Context, t shared.ID) ([]string, error) {
	return f.VerifiedDomainNames(ctx, t)
}

func (f *gateFixture) add(t *testing.T, name string, typ asset.AssetType) *asset.Asset {
	t.Helper()
	a, err := asset.NewAsset(name, typ, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	f.assets[a.Name()] = a
	return a
}

func (f *gateFixture) record(a *asset.Asset, s attribution.State, human bool) {
	f.records[a.ID().String()] = attribution.Record{State: s, HumanDecided: human}
}

func newGateFixture(t *testing.T) *gateFixture {
	t.Helper()
	f := &gateFixture{tenant: shared.NewID(), assets: map[string]*asset.Asset{}, records: map[string]attribution.Record{}, tombs: map[string]bool{}}
	st, err := scopedom.NewTarget(f.tenant, scopedom.TargetTypeDomain, "*.scoped.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	cidr, err := scopedom.NewTarget(f.tenant, scopedom.TargetTypeCIDR, "198.51.100.0/24", "", "")
	if err != nil {
		t.Fatal(err)
	}
	f.targets = []*scopedom.Target{st, cidr}
	f.seeds = []string{"seeded.com"}
	f.vds = []string{"verified.com"}
	return f
}

func TestActiveGate_Assets(t *testing.T) {
	f := newGateFixture(t)
	g := NewActiveGate(f, f, f, f)
	cases := []struct {
		name  string
		setup func() *asset.Asset
		want  attribution.State // "" = allowed
	}{
		{"unrecorded inside a scope target", func() *asset.Asset { return f.add(t, "app.scoped.com", asset.AssetTypeSubdomain) }, ""},
		{"unrecorded IP inside a scope CIDR", func() *asset.Asset { return f.add(t, "198.51.100.7", asset.AssetTypeIPAddress) }, ""},
		// Only scope entries authorize (research/53 SC1, SC2): a former seed
		// is an entry; a verified domain alone is proof, never authority.
		{"unrecorded under a verified domain only", func() *asset.Asset {
			return f.add(t, "a.b.verified.com", asset.AssetTypeSubdomain)
		}, attribution.StateUnattributed},
		{"unrecorded outside everything", func() *asset.Asset { return f.add(t, "manual.example.net", asset.AssetTypeDomain) }, attribution.StateUnattributed},
		{"unrecorded public IP outside everything", func() *asset.Asset { return f.add(t, "203.0.113.5", asset.AssetTypeIPAddress) }, attribution.StateUnattributed},
		{"unrecorded private address: zones decide", func() *asset.Asset { return f.add(t, "10.0.0.5", asset.AssetTypeIPAddress) }, ""},
		{"unrecorded repository: not an internet target", func() *asset.Asset {
			return f.add(t, "github.com/org/repo", asset.AssetTypeRepository)
		}, ""},
		{"confirmed by a person outside scope: ownership is not authority", func() *asset.Asset {
			a := f.add(t, "confirmed.example.net", asset.AssetTypeDomain)
			f.record(a, attribution.StateConfirmed, true)
			return a
		}, attribution.StateOutOfScope},
		{"confirmed by a rule outside scope", func() *asset.Asset {
			a := f.add(t, "auto.example.net", asset.AssetTypeDomain)
			f.record(a, attribution.StateConfirmed, false)
			return a
		}, attribution.StateOutOfScope},
		{"confirmed IP outside every scope range", func() *asset.Asset {
			a := f.add(t, "203.0.113.77", asset.AssetTypeIPAddress)
			f.record(a, attribution.StateConfirmed, true)
			return a
		}, attribution.StateOutOfScope},
		{"confirmed by a person inside a scope target", func() *asset.Asset {
			a := f.add(t, "mine.scoped.com", asset.AssetTypeSubdomain)
			f.record(a, attribution.StateConfirmed, true)
			return a
		}, ""},
		{"confirmed private address: zones decide", func() *asset.Asset {
			a := f.add(t, "10.0.0.9", asset.AssetTypeIPAddress)
			f.record(a, attribution.StateConfirmed, true)
			return a
		}, ""},
		{"needs review inside a scope target", func() *asset.Asset {
			a := f.add(t, "review.scoped.com", asset.AssetTypeSubdomain)
			f.record(a, attribution.StateNeedsReview, false)
			return a
		}, attribution.StateNeedsReview},
		{"candidate", func() *asset.Asset {
			a := f.add(t, "cand.seeded.com", asset.AssetTypeSubdomain)
			f.record(a, attribution.StateCandidate, false)
			return a
		}, attribution.StateCandidate},
		{"dependency", func() *asset.Asset {
			a := f.add(t, "cdn.scoped.com", asset.AssetTypeSubdomain)
			f.record(a, attribution.StateDependency, true)
			return a
		}, attribution.StateDependency},
		{"rejected", func() *asset.Asset {
			a := f.add(t, "notours.scoped.com", asset.AssetTypeSubdomain)
			f.record(a, attribution.StateRejected, true)
			return a
		}, attribution.StateRejected},
		{"under a rejected parent asset", func() *asset.Asset {
			p := f.add(t, "legacy.scoped.com", asset.AssetTypeSubdomain)
			f.record(p, attribution.StateRejected, true)
			return f.add(t, "api.legacy.scoped.com", asset.AssetTypeSubdomain)
		}, attribution.StateRejected},
		{"re-created after rejection (tombstone on its own name)", func() *asset.Asset {
			f.tombs["gone.seeded.com"] = true
			return f.add(t, "gone.seeded.com", asset.AssetTypeSubdomain)
		}, attribution.StateRejected},
		{"under a tombstoned parent", func() *asset.Asset {
			f.tombs["old.scoped.com"] = true
			return f.add(t, "x.old.scoped.com", asset.AssetTypeSubdomain)
		}, attribution.StateRejected},
		{"automatically confirmed under a tombstone", func() *asset.Asset {
			f.tombs["auto.verified.com"] = true
			a := f.add(t, "www.auto.verified.com", asset.AssetTypeSubdomain)
			f.record(a, attribution.StateConfirmed, false)
			return a
		}, attribution.StateRejected},
		{"a person confirmed it under a rejected parent", func() *asset.Asset {
			f.tombs["parent.scoped.com"] = true
			a := f.add(t, "child.parent.scoped.com", asset.AssetTypeSubdomain)
			f.record(a, attribution.StateConfirmed, true)
			return a
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := tc.setup()
			got, err := g.ActiveCheckBlocked(context.Background(), f.tenant, []string{a.ID().String()})
			if err != nil {
				t.Fatal(err)
			}
			if state := got[a.ID().String()]; state != tc.want {
				t.Fatalf("state = %q, want %q", state, tc.want)
			}
		})
	}
}

func TestActiveGate_BlockedTargets(t *testing.T) {
	f := newGateFixture(t)
	g := NewActiveGate(f, f, f, f)
	rej := f.add(t, "www.scoped.com", asset.AssetTypeSubdomain)
	f.record(rej, attribution.StateRejected, true)
	rev := f.add(t, "dev.scoped.com", asset.AssetTypeSubdomain)
	f.record(rev, attribution.StateNeedsReview, false)
	f.add(t, "manual.example.net", asset.AssetTypeDomain)
	f.add(t, "ok.scoped.com", asset.AssetTypeSubdomain)
	f.tombs["dead.example.org"] = true

	targets := []string{
		"www.scoped.com",               // rejected asset
		"https://WWW.scoped.com/login", // the same asset by URL
		"dev.scoped.com:443",           // needs_review asset by host:port
		"manual.example.net",           // unattributed asset
		"ok.scoped.com",                // allowed
		"api.www.scoped.com",           // free text under a rejected asset
		"a.dead.example.org",           // free text under a tombstone
		"free.example.com",             // free text outside every scope entry
		"https://new.seeded.com/x",     // free text under a former seed with no entry: refused
		"203.0.113.9",                  // public address outside every range
		"198.51.100.9:443",             // address inside a scope CIDR: allowed
		"10.1.2.3",                     // private: zones decide
		"github.com/org/repo-x",        // a host with a path and no covering entry
	}
	got, err := g.BlockedTargets(context.Background(), f.tenant, targets)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]attribution.State{
		"www.scoped.com":               attribution.StateRejected,
		"https://WWW.scoped.com/login": attribution.StateRejected,
		"dev.scoped.com:443":           attribution.StateNeedsReview,
		"manual.example.net":           attribution.StateUnattributed,
		"api.www.scoped.com":           attribution.StateRejected,
		"a.dead.example.org":           attribution.StateRejected,
		"free.example.com":             attribution.StateUnattributed,
		"203.0.113.9":                  attribution.StateUnattributed,
		"github.com/org/repo-x":        attribution.StateUnattributed,
		"https://new.seeded.com/x":     attribution.StateUnattributed,
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: got %q, want %q (all: %v)", k, got[k], v, got)
		}
	}

	// Another tenant: tenant A's rejections, records, assets, scope targets,
	// seeds and verified domains mean nothing: every internet target is
	// unattributed (never rejected by A's data, never allowed by A's scope).
	other, err := g.BlockedTargets(context.Background(), shared.NewID(), targets)
	if err != nil {
		t.Fatal(err)
	}
	for _, tg := range targets {
		st, no := other[tg]
		switch tg {
		case "10.1.2.3":
			if no {
				t.Fatalf("another tenant: %s refused (%s), want left to zones/act scope", tg, st)
			}
		default:
			if st != attribution.StateUnattributed {
				t.Fatalf("another tenant: %s = %q, want unattributed (A's data leaked)", tg, st)
			}
		}
	}
	if b, err := g.ActiveCheckBlocked(context.Background(), shared.NewID(), []string{rej.ID().String()}); err != nil || b[rej.ID().String()] != attribution.StateUnattributed {
		// Tenant A's asset id asked by another tenant is not found: refused.
		t.Fatalf("foreign asset id: %v, %v", b, err)
	}
}

func TestActiveGate_FailsClosed(t *testing.T) {
	f := newGateFixture(t)
	a := f.add(t, "app.scoped.com", asset.AssetTypeSubdomain)
	if _, err := NewActiveGate(nil, f, f, f).ActiveCheckBlocked(context.Background(), f.tenant, []string{a.ID().String()}); err == nil {
		t.Fatal("unwired gate must fail")
	}
	if _, err := NewActiveGate(f, f, nil, f).BlockedTargets(context.Background(), f.tenant, []string{"x"}); err == nil {
		t.Fatal("unwired gate must fail")
	}
	f.err = errors.New("db down")
	g := NewActiveGate(f, f, f, f)
	if _, err := g.ActiveCheckBlocked(context.Background(), f.tenant, []string{a.ID().String()}); err == nil {
		t.Fatal("a lookup error must fail the check")
	}
	if _, err := g.BlockedTargets(context.Background(), f.tenant, []string{"app.scoped.com"}); err == nil {
		t.Fatal("a lookup error must fail the check")
	}
	if _, err := g.ActiveCheckBlocked(context.Background(), f.tenant, []string{"not-a-uuid"}); err == nil {
		t.Fatal("a malformed id must fail the check")
	}
}

// The platform's guardrails win over anything the tenant declares (RFC-054
// §8): a deny-listed name is refused even inside the tenant's own scope
// target and even when a person confirmed it; with SCOPE_ACTIVE_PROOF=all
// only names under a verified domain are probed.
func TestActiveGate_PlatformPolicy(t *testing.T) {
	f := newGateFixture(t)
	gov, err := scopedom.NewTarget(f.tenant, scopedom.TargetTypeDomain, "*.agency.gov.vn", "", "")
	if err != nil {
		t.Fatal(err)
	}
	f.targets = append(f.targets, gov)
	gr, _ := scopedom.NewGuardrails(0, 0, []string{"198.51.100.200/32"})

	g := NewActiveGate(f, f, f, f).WithPlatformPolicy(gr, false)
	confirmedGov := f.add(t, "portal.agency.gov.vn", asset.AssetTypeSubdomain)
	f.record(confirmedGov, attribution.StateConfirmed, true)
	platformIP := f.add(t, "198.51.100.200", asset.AssetTypeIPAddress)
	ok := f.add(t, "ok.scoped.com", asset.AssetTypeSubdomain)
	got, err := g.ActiveCheckBlocked(context.Background(), f.tenant, []string{confirmedGov.ID().String(), platformIP.ID().String(), ok.ID().String()})
	if err != nil {
		t.Fatal(err)
	}
	if got[confirmedGov.ID().String()] != attribution.StatePlatformDenied || got[platformIP.ID().String()] != attribution.StatePlatformDenied {
		t.Fatalf("deny list: %v", got)
	}
	if _, no := got[ok.ID().String()]; no {
		t.Fatalf("an allowed asset was refused: %v", got)
	}
	typed, err := g.BlockedTargets(context.Background(), f.tenant, []string{"x.agency.gov.vn", "https://x.agency.gov.vn/", "169.254.169.254", "app.scoped.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"x.agency.gov.vn", "https://x.agency.gov.vn/", "169.254.169.254"} {
		if typed[d] != attribution.StatePlatformDenied {
			t.Errorf("%s = %q, want platform_denied", d, typed[d])
		}
	}
	if _, no := typed["app.scoped.com"]; no {
		t.Errorf("app.scoped.com refused: %v", typed)
	}

	// A verified domain is proof, not authority: www.verified.com needs an
	// entry too (research/53 SC2).
	vt, err := scopedom.NewTarget(f.tenant, scopedom.TargetTypeDomain, "*.verified.com", "", "")
	if err != nil {
		t.Fatal(err)
	}
	f.targets = append(f.targets, vt)
	all := NewActiveGate(f, f, f, f).WithPlatformPolicy(gr, true)
	typed, err = all.BlockedTargets(context.Background(), f.tenant, []string{"app.scoped.com", "www.verified.com", "198.51.100.7"})
	if err != nil {
		t.Fatal(err)
	}
	if typed["app.scoped.com"] != attribution.StateProofRequired || typed["198.51.100.7"] != attribution.StateProofRequired {
		t.Fatalf("proof all: %v", typed)
	}
	if _, no := typed["www.verified.com"]; no {
		t.Fatalf("a verified name was refused: %v", typed)
	}
	un, err := all.UnverifiedTargets(context.Background(), f.tenant, []string{"app.scoped.com", "www.verified.com", "10.0.0.1", "198.51.100.7"})
	if err != nil || len(un) != 2 {
		t.Fatalf("unverified = %v (%v), want app.scoped.com and the address", un, err)
	}
	// Another tenant's verified domain proves nothing.
	un, _ = all.UnverifiedTargets(context.Background(), shared.NewID(), []string{"www.verified.com"})
	if len(un) != 1 {
		t.Fatalf("tenant A's verified domain proved another tenant's target: %v", un)
	}
}

// The asset attribution view says whether scope covers the asset and what
// covers it (RFC-054 §6.6).
func TestActiveGate_ScopeOfAsset(t *testing.T) {
	f := newGateFixture(t)
	g := NewActiveGate(f, f, f, f)
	in := f.add(t, "app.scoped.com", asset.AssetTypeSubdomain)
	out := f.add(t, "elsewhere.example.net", asset.AssetTypeDomain)
	priv := f.add(t, "10.1.2.3", asset.AssetTypeIPAddress)
	repo := f.add(t, "github.com/org/r", asset.AssetTypeRepository)
	cases := map[string]string{
		in.ID().String(): ScopeStatusInScope, out.ID().String(): ScopeStatusOutOfScope,
		priv.ID().String(): ScopeStatusInternal, repo.ID().String(): ScopeStatusNotApplicable,
		shared.NewID().String(): ScopeStatusOutOfScope,
	}
	for id, want := range cases {
		got, via, err := g.ScopeOfAsset(context.Background(), f.tenant, id)
		if err != nil || got != want {
			t.Errorf("%s: %s (%v), want %s", id, got, err, want)
		}
		if want == ScopeStatusInScope && (via == nil || via.Pattern != "*.scoped.com") {
			t.Errorf("covered_by = %+v", via)
		}
	}
	// Another tenant: tenant A's asset id is unknown there.
	if got, _, _ := g.ScopeOfAsset(context.Background(), shared.NewID(), in.ID().String()); got != ScopeStatusOutOfScope {
		t.Errorf("another tenant saw %s", got)
	}
}

// RFC-054 §4.2 step 6: the gate lists the targets covered only below the
// probe's tier, with the entry to raise; what nothing covers, and private
// names, are left to the ownership gate. Another tenant sees none of it.
func TestActiveGate_TierExceeded(t *testing.T) {
	f := newGateFixture(t)
	low, err := scopedom.NewTarget(f.tenant, scopedom.TargetTypeDomain, "*.low.example", "", "")
	if err != nil {
		t.Fatal(err)
	}
	low.SetMaxTier(scopedom.TierPassive, time.Now())
	f.targets = append(f.targets, low)
	g := NewActiveGate(f, f, f, f)
	ctx := context.Background()
	targets := []string{"app.low.example", "app.scoped.com", "www.seeded.com", "www.verified.com", "nothing.example", "10.0.0.5"}

	got, err := g.TierExceeded(ctx, f.tenant, targets, scopedom.TierActive)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got["app.low.example"] == nil || got["app.low.example"].ID != low.ID().String() {
		t.Fatalf("t1: %v", got)
	}
	got, err = g.TierExceeded(ctx, f.tenant, targets, scopedom.TierIntrusive)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"app.low.example", "app.scoped.com"} {
		if r := got[want]; r == nil {
			t.Errorf("t2: %s not listed with its entry (%v)", want, got)
		}
	}
	// Only entries authorize (research/53 SC1, SC2): a name under a former
	// seed or a verified domain is uncovered, the ownership gate's answer.
	for _, n := range []string{"www.seeded.com", "www.verified.com", "nothing.example"} {
		if _, ok := got[n]; ok {
			t.Errorf("%s: an uncovered name is the ownership gate's answer, not tier_exceeds", n)
		}
	}
	if _, ok := got["10.0.0.5"]; ok {
		t.Error("a private address is gated by zones")
	}
	if got, _ := g.TierExceeded(ctx, f.tenant, targets, scopedom.TierPassive); len(got) != 0 {
		t.Errorf("t0 exceeds nothing: %v", got)
	}
	// Another tenant: nothing of this tenant covers anything for it.
	if got, err := g.TierExceeded(ctx, shared.NewID(), targets, scopedom.TierIntrusive); err != nil || len(got) != 0 {
		t.Errorf("another tenant: %v, %v", got, err)
	}
	if _, err := (&ActiveGate{}).TierExceeded(ctx, f.tenant, targets, scopedom.TierActive); err == nil {
		t.Error("an unwired gate must refuse")
	}
}

// The dry run names an asset only for its own tenant: another tenant asking
// for the id, or an unknown id, gets nothing back (RFC-054 §6.4).
func TestActiveGate_AssetTargets(t *testing.T) {
	f := newGateFixture(t)
	g := NewActiveGate(f, f, f, f)
	a := f.add(t, "app.scoped.com", asset.AssetTypeSubdomain)
	a.SetTenantID(f.tenant)
	ip := f.add(t, "198.51.100.7", asset.AssetTypeIPAddress)
	ip.SetTenantID(f.tenant)
	unknown := shared.NewID()

	got, err := g.AssetTargets(context.Background(), f.tenant, []shared.ID{a.ID(), ip.ID(), unknown})
	if err != nil {
		t.Fatal(err)
	}
	if v := got[a.ID()]; len(v) == 0 || v[0] != "app.scoped.com" {
		t.Fatalf("own asset = %v", v)
	}
	if v := got[ip.ID()]; len(v) == 0 || v[0] != "198.51.100.7" {
		t.Fatalf("own address = %v", v)
	}
	if _, ok := got[unknown]; ok {
		t.Fatal("an unknown id was answered")
	}
	other, err := g.AssetTargets(context.Background(), shared.NewID(), []shared.ID{a.ID()})
	if err != nil || len(other) != 0 {
		t.Fatalf("another tenant got %v, %v", other, err)
	}
	if _, err := (&ActiveGate{}).AssetTargets(context.Background(), f.tenant, []shared.ID{a.ID()}); err == nil {
		t.Fatal("an unwired gate must refuse")
	}
}

// A passive step takes only names in the organization's scope (RFC-071):
// UncoveredTargets lists the internet names and addresses no scope entry of
// the tenant covers. Private targets are left to the scan zones; another
// tenant's entries cover nothing.
func TestActiveGate_UncoveredTargets(t *testing.T) {
	f := newGateFixture(t)
	g := NewActiveGate(f, f, f, f)
	ctx := context.Background()
	targets := []string{"app.scoped.com", "198.51.100.7", "victim.example.org", "10.0.0.5", "203.0.113.9"}

	got, err := g.UncoveredTargets(ctx, f.tenant, targets)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"victim.example.org", "203.0.113.9"}; !slices.Equal(got, want) {
		t.Fatalf("uncovered = %v, want %v", got, want)
	}
	other, err := g.UncoveredTargets(ctx, shared.NewID(), targets)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"app.scoped.com", "198.51.100.7", "victim.example.org", "203.0.113.9"}; !slices.Equal(other, want) {
		t.Fatalf("another tenant: uncovered = %v, want %v (this tenant's entries cover nothing for it)", other, want)
	}
	if _, err := (&ActiveGate{}).UncoveredTargets(ctx, f.tenant, targets); err == nil {
		t.Error("an unwired gate must refuse")
	}
}

// A target only a port-limited entry covers goes to a job only within the
// limit: no full port scan, no tool that could reach other ports; an entry
// without a limit lifts it (RFC-065 §16.8).
func TestActiveGate_ConstraintRefused(t *testing.T) {
	f := newGateFixture(t)
	svc, err := scopedom.NewTarget(f.tenant, scopedom.TargetTypeDomain, "api.limited.example", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SetConstraint(scopedom.Constraint{Ports: "8443", Protocol: "tcp"}); err != nil {
		t.Fatal(err)
	}
	path, err := scopedom.NewTarget(f.tenant, scopedom.TargetTypeURL, "https://shop.limited.example/api*", "", "")
	if err != nil {
		t.Fatal(err)
	}
	f.targets = append(f.targets, svc, path)
	g := NewActiveGate(f, f, f, f)
	ctx := context.Background()
	targets := []string{"api.limited.example:8443", "https://shop.limited.example/api/v1", "app.scoped.com", "10.0.0.5"}

	full, err := g.ConstraintRefused(ctx, f.tenant, targets, scopedom.TierActive, scopedom.JobShape{Tool: "naabu", Ports: "1-65535"})
	if err != nil {
		t.Fatal(err)
	}
	if full["api.limited.example:8443"] != scopedom.ConstrainedPortsOutside || full["https://shop.limited.example/api/v1"] != scopedom.ConstrainedToolRefused ||
		len(full) != 2 {
		t.Fatalf("full port scan: %v", full)
	}
	ok, err := g.ConstraintRefused(ctx, f.tenant, targets[:1], scopedom.TierActive, scopedom.JobShape{Tool: "naabu", Ports: "8443"})
	if err != nil || len(ok) != 0 {
		t.Fatalf("allowed port: %v %v", ok, err)
	}
	crawl, err := g.ConstraintRefused(ctx, f.tenant, targets, scopedom.TierActive, scopedom.JobShape{Tool: "katana"})
	if err != nil || crawl["https://shop.limited.example/api/v1"] != scopedom.ConstrainedToolRefused {
		t.Fatalf("crawler on a path-limited entry: %v %v", crawl, err)
	}
	// Passive work is never limited; another tenant has no entries here.
	if p, _ := g.ConstraintRefused(ctx, f.tenant, targets, scopedom.TierPassive, scopedom.JobShape{Tool: "katana"}); len(p) != 0 {
		t.Fatalf("passive: %v", p)
	}
	whole, err := scopedom.NewTarget(f.tenant, scopedom.TargetTypeDomain, "api.limited.example", "", "")
	if err != nil {
		t.Fatal(err)
	}
	f.targets = append(f.targets, whole)
	if got, _ := g.ConstraintRefused(ctx, f.tenant, targets[:1], scopedom.TierActive, scopedom.JobShape{Tool: "naabu", Ports: "1-65535"}); len(got) != 0 {
		t.Fatalf("an unlimited entry covers the host: %v", got)
	}
}
