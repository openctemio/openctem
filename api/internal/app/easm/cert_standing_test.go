package easm

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const fingerprint = "9f2b5c1e7a0d4e8f93b6a1c2d3e4f5a60718293a4b5c6d7e8f9012a3b4c5d6e7"

// cert adds a certificate asset named by its fingerprint, with names, served
// by the given endpoints.
func (f *gateFixture) cert(t *testing.T, fp string, names []string, endpoints ...string) *asset.Asset {
	t.Helper()
	c := f.add(t, fp, asset.AssetTypeCertificate)
	props := map[string]any{}
	if len(names) > 0 {
		sans := make([]any, len(names))
		for i, n := range names {
			sans[i] = n
		}
		props["sans"] = sans
	}
	c.SetProperties(props)
	if f.serving == nil {
		f.serving = map[string][]string{}
	}
	// A service is stored as host:port:tcp.
	var stored []string
	for _, e := range endpoints {
		if _, ok := f.assets[e+":tcp"]; ok {
			e += ":tcp"
		}
		stored = append(stored, e)
	}
	f.serving[fp] = stored
	return c
}

func certGate(f *gateFixture) *ActiveGate {
	g := NewActiveGate(f, f, f, f)
	g.SetCertificates(f)
	return g
}

func standing(t *testing.T, g *ActiveGate, f *gateFixture, c *asset.Asset) CertStanding {
	t.Helper()
	got, err := g.CertificateStandings(context.Background(), f.tenant, []shared.ID{c.ID()})
	if err != nil {
		t.Fatal(err)
	}
	st, ok := got[c.ID().String()]
	if !ok {
		t.Fatal("no standing for the certificate")
	}
	return st
}

func blockedState(t *testing.T, g *ActiveGate, f *gateFixture, c *asset.Asset) attribution.State {
	t.Helper()
	got, err := g.ActiveCheckBlocked(context.Background(), f.tenant, []string{c.ID().String()})
	if err != nil {
		t.Fatal(err)
	}
	return got[c.ID().String()]
}

// A certificate served by an endpoint a scope entry covers is in scope
// through that endpoint, never by its fingerprint.
func TestCertificate_ServedByEndpointInScope(t *testing.T) {
	f := newGateFixture(t)
	g := certGate(f)
	f.add(t, "app.scoped.com:443", asset.AssetTypeService)
	c := f.cert(t, fingerprint, []string{"app.scoped.com"}, "app.scoped.com:443")

	if s := blockedState(t, g, f, c); s != "" {
		t.Fatalf("gate refused the certificate: %q", s)
	}
	st := standing(t, g, f, c)
	if st.Standing != CertStandingInScope || st.ServedBy == nil {
		t.Fatalf("standing = %+v", st)
	}
	if v := st.ServedBy; v.Kind != "served_by" || v.Name != "app.scoped.com:443:tcp" || v.Pattern != "*.scoped.com" || v.Endpoint == "" {
		t.Errorf("served_by = %+v", v)
	}
	status, via, err := g.ScopeOfAsset(context.Background(), f.tenant, c.ID().String())
	if err != nil || status != ScopeStatusInScope || via == nil || via.Kind != "served_by" {
		t.Errorf("ScopeOfAsset = %s %+v %v", status, via, err)
	}
	if r, err := g.GuardrailOf(context.Background(), f.tenant, []shared.ID{c.ID()}); err != nil || len(r) != 0 {
		t.Errorf("GuardrailOf = %v %v, want none", r, err)
	}
	if st.Ownership != CertOwnershipYours || st.OwnedBy == nil || st.OwnedBy.Kind != "san" || st.OwnedBy.Name != "app.scoped.com" {
		t.Errorf("ownership = %s %+v", st.Ownership, st.OwnedBy)
	}
}

// With any one endpoint in scope the certificate passes (a wildcard
// certificate served on many hosts).
func TestCertificate_AnyEndpointInScope(t *testing.T) {
	f := newGateFixture(t)
	g := certGate(f)
	f.add(t, "203.0.113.9:443", asset.AssetTypeService)
	f.add(t, "198.51.100.7:443", asset.AssetTypeService)
	c := f.cert(t, fingerprint, []string{"*.scoped.com"}, "203.0.113.9:443", "198.51.100.7:443")
	if s := blockedState(t, g, f, c); s != "" {
		t.Fatalf("refused: %q", s)
	}
	st := standing(t, g, f, c)
	if st.Standing != CertStandingInScope || st.ServedBy.Name != "198.51.100.7:443:tcp" || st.EndpointCount != 2 {
		t.Fatalf("standing = %+v", st)
	}
	// A wildcard name reads as its root.
	if st.Ownership != CertOwnershipYours || st.OwnedBy.Name != "scoped.com" {
		t.Errorf("ownership = %s %+v", st.Ownership, st.OwnedBy)
	}
}

// The fingerprint is never judged as a name: with no known endpoint nothing
// is dispatched, and the answer is "not served", not a guardrail.
func TestCertificate_NoEndpointIsNotApplicable(t *testing.T) {
	f := newGateFixture(t)
	g := certGate(f)
	c := f.cert(t, fingerprint, nil)
	if s := blockedState(t, g, f, c); s != attribution.StateUnattributed {
		t.Errorf("state = %q, want unattributed", s)
	}
	if st := standing(t, g, f, c); st.Standing != CertStandingNotApplicable || st.Ownership != CertOwnershipNone || st.EndpointCount != 0 {
		t.Errorf("standing = %+v", st)
	}
	if status, _, _ := g.ScopeOfAsset(context.Background(), f.tenant, c.ID().String()); status != ScopeStatusNotApplicable {
		t.Errorf("scope = %s", status)
	}
	if r, _ := g.GuardrailOf(context.Background(), f.tenant, []shared.ID{c.ID()}); len(r) != 0 {
		t.Errorf("a fingerprint got a guardrail: %v", r)
	}
}

// A SAN under a domain root says the certificate is ours, nothing more.
func TestCertificate_SANOwnershipAuthorizesNothing(t *testing.T) {
	f := newGateFixture(t)
	g := certGate(f)
	c := f.cert(t, fingerprint, []string{"login.scoped.com"})
	st := standing(t, g, f, c)
	if st.Ownership != CertOwnershipYours || st.Standing != CertStandingNotApplicable {
		t.Fatalf("standing = %+v", st)
	}
	if s := blockedState(t, g, f, c); s == "" {
		t.Fatal("ownership alone let probes reach the certificate")
	}
}

// T1: an attacker-made certificate carrying the tenant's names, served from
// a foreign address, brings nothing into scope. The address stays blocked
// and uncovered, the certificate is held, and the endpoint stays refused.
func TestCertificate_AttackerCertificateOnForeignIPStaysOut(t *testing.T) {
	f := newGateFixture(t)
	g := certGate(f)
	ctx := context.Background()
	ip := f.add(t, "203.0.113.9", asset.AssetTypeIPAddress)
	svc := f.add(t, "203.0.113.9:443", asset.AssetTypeService)
	c := f.cert(t, fingerprint, []string{"app.scoped.com", "*.scoped.com", "scoped.com"}, "203.0.113.9:443")

	st := standing(t, g, f, c)
	if st.Standing == CertStandingInScope || st.Standing == CertStandingLowImpact || st.ServedBy != nil {
		t.Fatalf("the certificate reached scope through a foreign endpoint: %+v", st)
	}
	if st.Standing != CertStandingHeld || st.HeldBy == nil || st.HeldBy.Name != "203.0.113.9:443:tcp" {
		t.Errorf("standing = %+v", st)
	}
	if st.Ownership != CertOwnershipYours {
		t.Errorf("ownership = %s (the names are ours; that is all it says)", st.Ownership)
	}
	if s := blockedState(t, g, f, c); s == "" {
		t.Error("gate let the certificate through")
	}
	blocked, err := g.BlockedTargets(ctx, f.tenant, []string{"203.0.113.9", "203.0.113.9:443"})
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"203.0.113.9", "203.0.113.9:443"} {
		if blocked[target] != attribution.StateUnattributed {
			t.Errorf("BlockedTargets[%s] = %q, want unattributed", target, blocked[target])
		}
	}
	if got, err := g.ActiveCheckBlocked(ctx, f.tenant, []string{ip.ID().String(), svc.ID().String()}); err != nil || len(got) != 2 {
		t.Errorf("endpoint and address must stay refused: %v %v", got, err)
	}
	unc, err := g.UncoveredTargets(ctx, f.tenant, []string{"203.0.113.9"})
	if err != nil || !slices.Equal(unc, []string{"203.0.113.9"}) {
		t.Errorf("UncoveredTargets = %v %v", unc, err)
	}
}

// A certificate on our endpoint whose names are all foreign is a third-party
// certificate; it still passes through the endpoint.
func TestCertificate_ForeignNamesOnOurEndpointIsThirdParty(t *testing.T) {
	f := newGateFixture(t)
	g := certGate(f)
	f.add(t, "app.scoped.com:443", asset.AssetTypeService)
	c := f.cert(t, fingerprint, []string{"sni.cdn.example.net", "shop.other.example.org"}, "app.scoped.com:443")
	st := standing(t, g, f, c)
	if st.Standing != CertStandingInScope || st.Ownership != CertOwnershipThirdParty || st.OwnedBy != nil {
		t.Fatalf("standing = %+v", st)
	}
	if s := blockedState(t, g, f, c); s != "" {
		t.Errorf("a third-party certificate on our endpoint was refused: %q", s)
	}
}

// The deny list holds: a certificate served only by a deny-listed endpoint
// shows platform_denied, whatever else is true of it.
func TestCertificate_DeniedEndpointStaysDenied(t *testing.T) {
	f := newGateFixture(t)
	gr, _ := scopedom.NewGuardrails(0, 0, []string{"198.51.100.200/32"})
	g := certGate(f).WithPlatformPolicy(gr)
	f.add(t, "198.51.100.200", asset.AssetTypeIPAddress)
	f.add(t, "198.51.100.200:443", asset.AssetTypeService)
	c := f.cert(t, fingerprint, []string{"app.scoped.com"}, "198.51.100.200:443")
	if s := blockedState(t, g, f, c); s != attribution.StatePlatformDenied {
		t.Errorf("state = %q, want platform_denied", s)
	}
	if st := standing(t, g, f, c); st.Standing != CertStandingHeld || st.HeldBy.State != string(attribution.StatePlatformDenied) {
		t.Errorf("standing = %+v", st)
	}
}

// A rejected endpoint refuses the certificate it served; the strongest
// refusal among endpoints is the one shown.
func TestCertificate_RejectedEndpointAndRanking(t *testing.T) {
	f := newGateFixture(t)
	g := certGate(f)
	rej := f.add(t, "old.scoped.com:443", asset.AssetTypeService)
	f.record(rej, attribution.StateRejected, true)
	f.add(t, "203.0.113.9:443", asset.AssetTypeService)
	c := f.cert(t, fingerprint, nil, "203.0.113.9:443", "old.scoped.com:443")
	if s := blockedState(t, g, f, c); s != attribution.StateRejected {
		t.Errorf("state = %q, want rejected", s)
	}
}

// A person's decision on the certificate itself still refuses, even when
// an in-scope endpoint serves it.
func TestCertificate_HumanDecisionWins(t *testing.T) {
	f := newGateFixture(t)
	g := certGate(f)
	f.add(t, "app.scoped.com:443", asset.AssetTypeService)
	c := f.cert(t, fingerprint, nil, "app.scoped.com:443")
	f.record(c, attribution.StateDependency, true)
	if s := blockedState(t, g, f, c); s != attribution.StateDependency {
		t.Errorf("state = %q, want dependency", s)
	}
}

// A rejected parent of a name refuses ownership through that name.
func TestCertificate_RejectedParentRefusesOwnership(t *testing.T) {
	f := newGateFixture(t)
	g := certGate(f)
	f.tombs["bad.scoped.com"] = true
	c := f.cert(t, fingerprint, []string{"api.bad.scoped.com"})
	if st := standing(t, g, f, c); st.Ownership != CertOwnershipNone {
		t.Errorf("ownership = %s through a rejected parent", st.Ownership)
	}
	c2 := f.cert(t, "ab"+fingerprint[2:], []string{"api.bad.scoped.com", "ok.scoped.com"})
	if st := standing(t, g, f, c2); st.Ownership != CertOwnershipYours || st.OwnedBy.Name != "ok.scoped.com" {
		t.Errorf("ownership = %s %+v", st.Ownership, st.OwnedBy)
	}
}

// Addresses, other tenants' roots and hostile values never mark ownership.
func TestCertificate_NamesAreNormalizedAndBounded(t *testing.T) {
	f := newGateFixture(t)
	g := certGate(f)
	names := []string{"198.51.100.7", "scoped.com.evil.example", "evilscoped.com", "app.scoped.com\x00", " ", "*.", "x"}
	c := f.cert(t, fingerprint, names)
	if st := standing(t, g, f, c); st.Ownership != CertOwnershipNone {
		t.Errorf("ownership = %s from %v", st.Ownership, names)
	}
	long := make([]string, 0, 150)
	for i := 0; i < 149; i++ {
		long = append(long, "n"+strings.Repeat("a", i%5)+".other.example.org")
	}
	long = append(long, "late.scoped.com")
	got := certificateNames(f.cert(t, "cd"+fingerprint[2:], long))
	if len(got) > maxCertNames {
		t.Errorf("%d names read, cap %d", len(got), maxCertNames)
	}
}

// Another tenant's SAN, endpoints and roots never affect this tenant.
func TestCertificate_CrossTenant(t *testing.T) {
	a := newGateFixture(t)
	b := newGateFixture(t)
	other, err := scopedom.NewTarget(b.tenant, scopedom.TargetTypeDomain, "*.tenantb.example", "", "")
	if err != nil {
		t.Fatal(err)
	}
	b.targets = []*scopedom.Target{other}
	ga, gb := certGate(a), certGate(b)

	// Tenant A's certificate names tenant B's root.
	ca := a.cert(t, fingerprint, []string{"www.tenantb.example"})
	if st := standing(t, ga, a, ca); st.Ownership != CertOwnershipNone {
		t.Errorf("tenant A owns a name under tenant B's root: %+v", st)
	}
	// Tenant B's certificate names tenant A's root: it is not B's.
	cb := b.cert(t, "ef"+fingerprint[2:], []string{"app.scoped.com", "www.tenantb.example"})
	if st := standing(t, gb, b, cb); st.Ownership != CertOwnershipYours || st.OwnedBy.Name != "www.tenantb.example" {
		t.Errorf("tenant B standing = %+v", st)
	}
	cb2 := b.cert(t, "01"+fingerprint[2:], []string{"app.scoped.com"})
	if st := standing(t, gb, b, cb2); st.Ownership != CertOwnershipNone {
		t.Errorf("tenant B owns a name under tenant A's root: %+v", st)
	}
	// Tenant A's id asked as tenant B: nothing.
	got, err := gb.CertificateStandings(context.Background(), b.tenant, []shared.ID{ca.ID()})
	if err != nil || len(got) != 0 {
		t.Errorf("another tenant's certificate answered: %v %v", got, err)
	}
	// Tenant A's verified domain never counts for B.
	a.vds = []string{"only-a.example"}
	cv := b.cert(t, "02"+fingerprint[2:], []string{"www.only-a.example"})
	if st := standing(t, gb, b, cv); st.Ownership != CertOwnershipNone {
		t.Errorf("tenant A's verified domain counted for tenant B: %+v", st)
	}
}

// Under a verified domain the certificate is the tenant's, with the verified
// domain named; it still authorizes nothing.
func TestCertificate_VerifiedDomainOwnership(t *testing.T) {
	f := newGateFixture(t)
	g := certGate(f)
	c := f.cert(t, fingerprint, []string{"www.verified.com"})
	st := standing(t, g, f, c)
	if st.Ownership != CertOwnershipYours || st.OwnedBy.Pattern != "verified.com" {
		t.Fatalf("standing = %+v", st)
	}
	if blockedState(t, g, f, c) == "" {
		t.Error("a verified domain authorized the certificate")
	}
}

// A lookup failure refuses (nothing is dispatched), and an edge from one
// certificate to another is no endpoint.
func TestCertificate_FailsClosedAndIgnoresCertificateEndpoints(t *testing.T) {
	f := newGateFixture(t)
	g := certGate(f)
	c := f.cert(t, fingerprint, nil)
	f.servingErr = errors.New("db down")
	if _, err := g.ActiveCheckBlocked(context.Background(), f.tenant, []string{c.ID().String()}); err == nil {
		t.Error("a failed endpoint lookup must fail the check")
	}
	if _, err := g.CertificateStandings(context.Background(), f.tenant, []shared.ID{c.ID()}); err == nil {
		t.Error("a failed endpoint lookup must fail the standing")
	}
	f.servingErr = nil
	f.add(t, "app.scoped.com", asset.AssetTypeSubdomain)
	c2 := f.cert(t, "cd"+fingerprint[2:], nil, fingerprint)
	if st := standing(t, g, f, c2); st.Standing != CertStandingNotApplicable {
		t.Errorf("a certificate served another: %+v", st)
	}
	if st := standing(t, g, f, c); st.Standing != CertStandingNotApplicable {
		t.Errorf("standing = %+v", st)
	}
	// An unwired reader knows no endpoint: refused.
	f.serving = nil
	if s := blockedState(t, g, f, c); s != attribution.StateUnattributed {
		t.Errorf("state = %q", s)
	}
}
