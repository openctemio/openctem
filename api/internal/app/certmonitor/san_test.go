package certmonitor

// Certificate SAN promotion (san.go): names in a certificate a report wrote
// become candidate subdomains under the tenant's roots, through the CT
// promotion path, and never confirmed or scoped by the certificate alone.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

func sanService(t *testing.T, tenant shared.ID, assets ...*assetdom.Asset) (*Service, *fakeInventory, *memAttribution) {
	t.Helper()
	svc, inv, attr := promotionService(t, "http://unused.invalid", nil, tenant, assets)
	inv.source = assetdom.DiscoverySourceCertificate
	return svc, inv, attr
}

func cert(names ...string) ingest.CertificateNames {
	na := time.Now().Add(200 * 24 * time.Hour)
	return ingest.CertificateNames{AssetID: shared.NewID(), Name: "ab:cd:ef", Names: names, Issuer: "Test CA", NotAfter: &na}
}

type fakeNameAddrs struct {
	byName map[string][]string
	err    error
}

func (f *fakeNameAddrs) AddressesOf(_ context.Context, _ shared.ID, names []string) (map[string][]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := map[string][]string{}
	for _, n := range names {
		if a, ok := f.byName[n]; ok {
			out[n] = a
		}
	}
	return out, nil
}

// A SAN below a root becomes a candidate with certificate_san evidence that
// names the certificate; a SAN under a verified domain is still only a
// candidate (a certificate never confirms); foreign names, wildcards,
// addresses, the root itself and junk create nothing.
func TestPromoteCertificateNames_CandidatesUnderRootsOnly(t *testing.T) {
	tenant := shared.NewID()
	listed := mustDomainAsset(t, tenant, "listed.com")
	svc, inv, attr := sanService(t, tenant, listed)
	now := time.Now().UTC()
	svc.SetDomainSources(fakeVerified{list: []*verifieddomain.VerifiedDomain{
		verifieddomain.Reconstruct(shared.NewID(), tenant, "proven.com", "tok", verifieddomain.StatusVerified, &now, &now, now, now),
	}}, nil)

	c := cert("WWW.Listed.com.", "api.proven.com", "*.wild.listed.com", "cdn.foreign.net",
		"listed.com", "203.0.113.7", "bad name.listed.com", "sni.cloudflaressl.com")
	n, err := svc.PromoteCertificateNames(context.Background(), tenant, "httpx", []ingest.CertificateNames{c})
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("created %d, want 2 (www.listed.com, api.proven.com); inventory %v", n, inv.reports)
	}
	for _, name := range []string{"www.listed.com", "api.proven.com"} {
		a, ok := inv.byName[name]
		if !ok {
			t.Fatalf("%s not promoted", name)
		}
		id := a.ID().String()
		if got := attr.records[id].State; got != attribution.StateCandidate {
			t.Errorf("%s: state %q, want candidate", name, got)
		}
		ev, ok := attr.evidence[id][attribution.RuleCertificateSAN]
		if !ok || len(attr.evidence[id]) != 1 {
			t.Fatalf("%s: evidence %+v, want one certificate_san row", name, attr.evidence[id])
		}
		if ev.Technique != assetdom.DiscoverySourceCertificate || ev.Source != SourceCertificateSAN ||
			ev.Observed["certificate_asset_id"] != c.AssetID.String() || ev.Observed["tool"] != "httpx" {
			t.Errorf("%s: evidence = %+v", name, ev)
		}
	}
	for _, name := range []string{"wild.listed.com", "cdn.foreign.net", "sni.cloudflaressl.com", "203.0.113.7"} {
		if _, ok := inv.byName[name]; ok {
			t.Errorf("%s promoted", name)
		}
	}
	for _, tn := range inv.tenants {
		if tn != tenant {
			t.Fatalf("ingested under tenant %s, want %s", tn, tenant)
		}
	}
}

// A permanent scope entry covering the name confirms it through the scope
// join, as for CT names (scope-model S4); without it the name waits.
func TestPromoteCertificateNames_ScopeJoinConfirms(t *testing.T) {
	tenant := shared.NewID()
	svc, inv, attr := sanService(t, tenant, mustDomainAsset(t, tenant, "listed.com"), mustDomainAsset(t, tenant, "other.com"))
	svc.SetScopeJoin(&fakeJoin{root: "listed.com"})
	if _, err := svc.PromoteCertificateNames(context.Background(), tenant, "tlsx",
		[]ingest.CertificateNames{cert("www.listed.com", "www.other.com")}); err != nil {
		t.Fatal(err)
	}
	if got := attr.records[inv.byName["www.listed.com"].ID().String()].State; got != attribution.StateConfirmed {
		t.Errorf("www.listed.com = %q, want confirmed through matches_scope_target", got)
	}
	if got := attr.records[inv.byName["www.other.com"].ID().String()].State; got != attribution.StateCandidate {
		t.Errorf("www.other.com = %q, want candidate", got)
	}
}

// An existing asset keeps its standing: not re-ingested, a legacy asset gets
// no record, a confirmed one stays confirmed, a rejection stays.
func TestPromoteCertificateNames_ExistingAssetKeepsStanding(t *testing.T) {
	tenant := shared.NewID()
	listed := mustDomainAsset(t, tenant, "listed.com")
	legacy, _ := assetdom.NewAssetWithTenant(tenant, "www.listed.com", assetdom.AssetTypeSubdomain, assetdom.CriticalityHigh)
	confirmed, _ := assetdom.NewAssetWithTenant(tenant, "api.listed.com", assetdom.AssetTypeSubdomain, assetdom.CriticalityHigh)
	rejected, _ := assetdom.NewAssetWithTenant(tenant, "old.listed.com", assetdom.AssetTypeSubdomain, assetdom.CriticalityHigh)
	svc, inv, attr := sanService(t, tenant, listed, legacy, confirmed, rejected)
	attr.records[confirmed.ID().String()] = attribution.Record{State: attribution.StateConfirmed, Confidence: 99}
	attr.records[rejected.ID().String()] = attribution.Record{State: attribution.StateRejected, HumanDecided: true}

	if _, err := svc.PromoteCertificateNames(context.Background(), tenant, "httpx",
		[]ingest.CertificateNames{cert("www.listed.com", "api.listed.com", "old.listed.com")}); err != nil {
		t.Fatal(err)
	}
	if inv.ingests != 0 {
		t.Errorf("an existing asset was re-ingested %d times", inv.ingests)
	}
	if _, ok := attr.records[legacy.ID().String()]; ok {
		t.Error("legacy asset got an attribution record")
	}
	if got := attr.records[confirmed.ID().String()].State; got != attribution.StateConfirmed {
		t.Errorf("confirmed asset demoted to %q", got)
	}
	if got := attr.records[rejected.ID().String()].State; got != attribution.StateRejected {
		t.Errorf("human rejection overridden: %q", got)
	}
}

// Excluded names, names under an excluded root, a name whose dedicated
// address is excluded and a tombstoned name (whatever rule it was rejected
// under) are not proposed; a name behind a shared front end still is.
func TestPromoteCertificateNames_ExclusionsAndTombstones(t *testing.T) {
	tenant := shared.NewID()
	listed := mustDomainAsset(t, tenant, "listed.com")
	vpn, _ := assetdom.NewAssetWithTenant(tenant, "vpn.listed.com", assetdom.AssetTypeSubdomain, assetdom.CriticalityHigh)
	svc, inv, attr := sanService(t, tenant, listed, mustDomainAsset(t, tenant, "gone.com"), vpn)
	svc.SetExclusions(exclusionsFor([]*scopedom.Exclusion{
		approvedExclusion(tenant, scopedom.ExclusionTypeDomain, "secret.listed.com"),
		approvedExclusion(tenant, scopedom.ExclusionTypeDomain, "gone.com"),
		approvedExclusion(tenant, scopedom.ExclusionTypeDomain, "*.gone.com"),
		approvedExclusion(tenant, scopedom.ExclusionTypeIPAddress, "203.0.113.10"),
	}, nil))
	svc.SetNameAddresses(&fakeNameAddrs{byName: map[string][]string{"vpn.listed.com": {"203.0.113.10"}}})
	svc.SetTombstones(&fakeTombstones{dead: map[string][]attribution.Rule{
		"dead.listed.com": {attribution.RuleAssertedRoot}, // rejected under another rule: still blocked
	}})

	if _, err := svc.PromoteCertificateNames(context.Background(), tenant, "httpx", []ingest.CertificateNames{
		cert("secret.listed.com", "www.gone.com", "vpn.listed.com", "dead.listed.com", "ok.listed.com"),
	}); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"secret.listed.com", "www.gone.com", "dead.listed.com"} {
		if _, ok := inv.byName[n]; ok {
			t.Errorf("%s promoted", n)
		}
	}
	if len(attr.evidence[vpn.ID().String()]) != 0 {
		t.Error("an asset on an excluded dedicated address got evidence")
	}
	if _, ok := inv.byName["ok.listed.com"]; !ok {
		t.Error("ok.listed.com not promoted")
	}

	// Failed lookups promote nothing (fail closed).
	svc2, inv2, _ := sanService(t, tenant, listed, vpn)
	svc2.SetExclusions(exclusionsFor(nil, errors.New("db down")))
	if _, err := svc2.PromoteCertificateNames(context.Background(), tenant, "httpx", []ingest.CertificateNames{cert("new.listed.com")}); err == nil {
		t.Error("a failed exclusion lookup was not an error")
	}
	svc3, inv3, _ := sanService(t, tenant, listed, vpn)
	svc3.SetExclusions(exclusionsFor([]*scopedom.Exclusion{approvedExclusion(tenant, scopedom.ExclusionTypeIPAddress, "203.0.113.10")}, nil))
	svc3.SetNameAddresses(&fakeNameAddrs{err: errors.New("db down")})
	if _, err := svc3.PromoteCertificateNames(context.Background(), tenant, "httpx", []ingest.CertificateNames{cert("new.listed.com", "vpn.listed.com")}); err == nil {
		t.Error("a failed address lookup was not an error")
	}
	if _, ok := inv2.byName["new.listed.com"]; ok {
		t.Error("promoted without the exclusion check")
	}
	if _, ok := inv3.byName["new.listed.com"]; ok {
		t.Error("promoted without the address check")
	}
}

// The per-call cap bounds new assets; a long-expired certificate and an
// organization without roots promote nothing.
func TestPromoteCertificateNames_CapExpiredNoRoots(t *testing.T) {
	tenant := shared.NewID()
	svc, inv, _ := sanService(t, tenant, mustDomainAsset(t, tenant, "listed.com"))
	svc.maxPromotions = 3
	names := []string{"a.listed.com", "b.listed.com", "c.listed.com", "d.listed.com", "e.listed.com"}
	n, err := svc.PromoteCertificateNames(context.Background(), tenant, "httpx", []ingest.CertificateNames{cert(names...)})
	if err != nil || n != 3 {
		t.Fatalf("created %d (err %v), want the cap 3", n, err)
	}

	old := cert("z.listed.com")
	past := time.Now().Add(-200 * 24 * time.Hour)
	old.NotAfter = &past
	if n, _ := svc.PromoteCertificateNames(context.Background(), tenant, "httpx", []ingest.CertificateNames{old}); n != 0 {
		t.Errorf("a long-expired certificate promoted %d names", n)
	}
	if inv.ingests != 1 {
		t.Errorf("ingests = %d, want 1", inv.ingests)
	}

	// No roots in this organization: nothing, whatever the certificate says.
	other := shared.NewID()
	svc2, inv2, _ := sanService(t, other)
	if n, _ := svc2.PromoteCertificateNames(context.Background(), other, "httpx", []ingest.CertificateNames{cert("www.listed.com")}); n != 0 || inv2.ingests != 0 {
		t.Errorf("an organization without roots promoted %d names", n)
	}
}

func TestSanName(t *testing.T) {
	cases := map[string]string{
		"WWW.Example.COM.": "www.example.com",
		" api.example.com": "api.example.com",
		"*.example.com":    "",
		"a.*.example.com":  "",
		"10.0.0.1":         "",
		"localhost":        "",
		"a b.example.com":  "",
		"x@example.com":    "",
		"-bad.example.com": "",
	}
	for in, want := range cases {
		got, ok := sanName(in)
		if got != want || ok != (want != "") {
			t.Errorf("sanName(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
}
