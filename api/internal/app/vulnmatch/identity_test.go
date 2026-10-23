package vulnmatch

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// newDistroSvc is newSvc with distro builds included (pkgMatch is a deb).
func newDistroSvc(store *fakeStore) (*Service, *fakeWriter) {
	w := &fakeWriter{}
	return NewService(store, fakePolicy{tenant.VulnMatchingSettings{Enabled: true, IncludeDistroBuilds: true}}, w, logger.NewNop()), w
}

// pkgMatch is a match on an OS package link, the shape TenantMatches reads.
func pkgMatch(asset shared.ID, cve string) softwarematch.Match {
	return softwarematch.Match{
		AssetID: asset, LinkConfidence: 90, Location: "usr/lib/dpkg/status",
		ProductID: shared.NewID(), Product: "openssl", VersionID: shared.NewID(), Version: "3.0.11-1~deb12u1",
		Qualifier: "debian-12/amd64", Package: true, PURL: "pkg:deb/debian/openssl@3.0.11-1~deb12u1",
		Result: softwarematch.VersionVuln{CVEID: cve, RangeText: "< 3.0.13"},
		CVE:    softwarematch.CVEInfo{ID: cve, Severity: "high", Description: "d"},
	}
}

func scaFP(t *testing.T, m softwarematch.Match) string {
	t.Helper()
	k, _, ok := MatchIdentity(m)
	if !ok {
		t.Fatal("no identity")
	}
	return k.Fingerprint()
}

type fakeVEX struct{ fps []string }

func (v *fakeVEX) ApplyToFingerprints(_ context.Context, _ shared.ID, fps []string) (int, error) {
	v.fps = append(v.fps, fps...)
	return 0, nil
}

// The matcher's key for a package is the key ingest builds for a scanner
// report of the same package and CVE (the report's package URL carries its
// version and qualifiers; the identity drops the version and keeps the
// distro).
func TestMatchIdentity_PackageEqualsScannerKey(t *testing.T) {
	asset := shared.NewID()
	cases := []struct {
		name       string
		m          softwarematch.Match
		scannerURL string
	}{
		{"deb with distro and arch", pkgMatch(asset, "CVE-2024-0727"),
			"pkg:deb/debian/openssl@3.0.11-1~deb12u1?arch=amd64&distro=debian-12"},
		{"npm", func() softwarematch.Match {
			m := pkgMatch(asset, "cve-2021-23337")
			m.PURL, m.Qualifier = "pkg:npm/lodash@4.17.15", ""
			return m
		}(), "pkg:npm/lodash@4.17.20"},
		{"apk with arch only", func() softwarematch.Match {
			m := pkgMatch(asset, "CVE-2023-42363")
			m.PURL, m.Qualifier = "pkg:apk/alpine/busybox@1.36.1-r2", "x86_64"
			return m
		}(), "pkg:apk/alpine/busybox@1.36.1-r5?arch=x86_64"},
	}
	for _, c := range cases {
		key, legacy, ok := MatchIdentity(c.m)
		want, _ := vulnerability.SCAIdentity(asset.String(), c.scannerURL, "", "", c.m.Result.CVEID, "")
		if !ok || key.Fingerprint() != want.Fingerprint() || key.Kind != vulnerability.IdentityKindSCA {
			t.Errorf("%s: key %+v, want the scanner's %+v", c.name, key, want)
		}
		net, _ := vulnerability.NetworkIdentity(asset.String(), c.m.Result.CVEID, "", 0, "")
		if legacy == nil || legacy.Fingerprint() != net.Fingerprint() {
			t.Errorf("%s: legacy %+v", c.name, legacy)
		}
	}
}

// A product named by CPE (technology, service, OS) keeps the network key.
func TestMatchIdentity_CPEProductKeepsNetworkKey(t *testing.T) {
	m := match(shared.NewID(), "CVE-2021-23017", 80)
	for _, mod := range []func(*softwarematch.Match){
		func(*softwarematch.Match) {},
		func(m *softwarematch.Match) { m.PURL = "pkg:generic/nginx@1.18.0" }, // purl without a package link
		func(m *softwarematch.Match) { m.Package = true },                    // package link without a purl
	} {
		mm := m
		mod(&mm)
		key, legacy, ok := MatchIdentity(mm)
		if !ok || key.Fingerprint() != fp(mm) || legacy != nil {
			t.Errorf("%+v: key %+v legacy %v", mm, key, legacy)
		}
	}
}

func TestReconcile_PackageMatchCarriesComponentAndVEX(t *testing.T) {
	store := newFakeStore()
	m := pkgMatch(shared.NewID(), "CVE-2024-0727")
	store.matches = []softwarematch.Match{m}
	svc, w := newDistroSvc(store)
	vex := &fakeVEX{}
	svc.SetVEXApplier(vex)
	var st Stats
	if err := svc.ReconcileTenant(context.Background(), shared.NewID(), &st); err != nil {
		t.Fatal(err)
	}
	if len(w.created) != 1 {
		t.Fatalf("created %d", len(w.created))
	}
	f := w.created[0]
	if f.Fingerprint() != scaFP(t, m) || f.ComponentID() == nil || *f.ComponentID() != m.VersionID {
		t.Fatalf("finding fp %s component %v", f.Fingerprint(), f.ComponentID())
	}
	if vm, _ := f.Metadata()["version_match"].(map[string]any); vm["purl"] != "pkg:deb/debian/openssl@3.0.11-1~deb12u1?distro=debian-12" {
		t.Fatalf("evidence %+v", vm)
	}
	if len(vex.fps) != 1 || vex.fps[0] != f.Fingerprint() {
		t.Fatalf("VEX applied to %v", vex.fps)
	}
}

// A scanner finding a person closed (false positive, accepted, closed by a
// VEX statement) holds the package identity: the matcher must not create
// the same issue again under another key.
func TestReconcile_ClosedScannerFindingIsNotRecreated(t *testing.T) {
	store := newFakeStore()
	m := pkgMatch(shared.NewID(), "CVE-2024-0727")
	store.matches = []softwarematch.Match{m}
	// The key ingest gave the scanner's report of this package and CVE.
	scanner, _ := vulnerability.SCAIdentity(m.AssetID.String(),
		"pkg:deb/debian/openssl@3.0.11-1~deb12u1?arch=amd64&distro=debian-12", "", "", "CVE-2024-0727", "")
	store.taken = map[string]bool{scanner.Fingerprint(): true} // closed, so not in the open-CVE set
	svc, w := newDistroSvc(store)
	var st Stats
	if err := svc.ReconcileTenant(context.Background(), shared.NewID(), &st); err != nil {
		t.Fatal(err)
	}
	if len(w.created) != 0 {
		t.Fatalf("recreated a closed scanner finding: %d", len(w.created))
	}
}

// A matcher finding stored under the network key before moves to the
// package key in place (same finding, status kept, component set) and is
// neither recreated nor closed.
func TestReconcile_RekeysLegacyPackageFinding(t *testing.T) {
	store := newFakeStore()
	m := pkgMatch(shared.NewID(), "CVE-2024-0727")
	store.matches = []softwarematch.Match{m}
	_, legacy, _ := MatchIdentity(m)
	id := shared.NewID()
	store.existing = []softwarematch.MatcherFinding{{ID: id, AssetID: m.AssetID, Fingerprint: legacy.Fingerprint(),
		Status: "confirmed", ProductID: &m.ProductID, VersionID: &m.VersionID, Location: m.Location}}
	store.links[softwarematch.LinkKey{AssetID: m.AssetID, ProductID: m.ProductID, VersionID: m.VersionID, Location: m.Location}] =
		softwarematch.LinkInfo{State: softwarematch.LinkCurrent, VersionEvaluated: true}
	svc, w := newDistroSvc(store)
	vex := &fakeVEX{}
	svc.SetVEXApplier(vex)
	var st Stats
	if err := svc.ReconcileTenant(context.Background(), shared.NewID(), &st); err != nil {
		t.Fatal(err)
	}
	if len(store.rekeys) != 1 {
		t.Fatalf("rekeys %+v", store.rekeys)
	}
	r := store.rekeys[0]
	if r.FindingID != id || r.From != legacy.Fingerprint() || r.To != scaFP(t, m) || r.ComponentID != m.VersionID || len(r.IdentityKey) == 0 {
		t.Fatalf("rekey %+v", r)
	}
	if len(w.created) != 0 || len(store.closed) != 0 || st.Rekeyed != 1 {
		t.Fatalf("created %d closed %v rekeyed %d", len(w.created), store.closed, st.Rekeyed)
	}
	if len(vex.fps) != 1 || vex.fps[0] != r.To {
		t.Fatalf("VEX applied to %v", vex.fps)
	}
}

// When another finding already holds the package key, the legacy matcher
// finding keeps its key and is still managed under it: no merge, no new
// finding, and the matcher still reopens it when it had closed it.
func TestReconcile_LegacyKeyKeptWhenPackageKeyHeld(t *testing.T) {
	store := newFakeStore()
	m := pkgMatch(shared.NewID(), "CVE-2024-0727")
	store.matches = []softwarematch.Match{m}
	_, legacy, _ := MatchIdentity(m)
	store.taken = map[string]bool{scaFP(t, m): true}
	id := shared.NewID()
	store.existing = []softwarematch.MatcherFinding{{ID: id, AssetID: m.AssetID, Fingerprint: legacy.Fingerprint(),
		Status: "resolved", ProductID: &m.ProductID, VersionID: &m.VersionID, Location: m.Location}}
	store.links[softwarematch.LinkKey{AssetID: m.AssetID, ProductID: m.ProductID, VersionID: m.VersionID, Location: m.Location}] =
		softwarematch.LinkInfo{State: softwarematch.LinkCurrent, VersionEvaluated: true}
	svc, w := newDistroSvc(store)
	var st Stats
	if err := svc.ReconcileTenant(context.Background(), shared.NewID(), &st); err != nil {
		t.Fatal(err)
	}
	if len(w.created) != 0 || len(store.closed) != 0 || st.Rekeyed != 0 || len(store.reopened) != 1 || store.reopened[0] != id {
		t.Fatalf("created %d closed %v rekeyed %d reopened %v", len(w.created), store.closed, st.Rekeyed, store.reopened)
	}
}

// A legacy finding whose match is now below the policy is still matched:
// it is not closed while it waits to move.
func TestReconcile_LegacyBelowPolicyStays(t *testing.T) {
	store := newFakeStore()
	m := pkgMatch(shared.NewID(), "CVE-2024-0727")
	m.LinkConfidence = 20
	store.matches = []softwarematch.Match{m}
	_, legacy, _ := MatchIdentity(m)
	store.existing = []softwarematch.MatcherFinding{{ID: shared.NewID(), AssetID: m.AssetID, Fingerprint: legacy.Fingerprint(),
		Status: "new", ProductID: &m.ProductID, VersionID: &m.VersionID, Location: m.Location}}
	store.links[softwarematch.LinkKey{AssetID: m.AssetID, ProductID: m.ProductID, VersionID: m.VersionID, Location: m.Location}] =
		softwarematch.LinkInfo{State: softwarematch.LinkCurrent, VersionEvaluated: true}
	svc, _ := newDistroSvc(store)
	var st Stats
	if err := svc.ReconcileTenant(context.Background(), shared.NewID(), &st); err != nil {
		t.Fatal(err)
	}
	if len(store.closed) != 0 {
		t.Fatalf("closed %v", store.closed)
	}
}
