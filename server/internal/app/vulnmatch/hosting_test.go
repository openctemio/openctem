package vulnmatch

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/softwarematch"
	"github.com/openctemio/openctem/server/pkg/domain/vulnerability"
)

type hostingStore struct {
	*fakeStore
	facts map[shared.ID]softwarematch.HostFacts
}

func (h *hostingStore) HostingFacts(_ context.Context, _ shared.ID, ids []shared.ID) (map[shared.ID]softwarematch.HostFacts, error) {
	out := map[shared.ID]softwarematch.HostFacts{}
	for _, id := range ids {
		if f, ok := h.facts[id]; ok {
			out[id] = f
		}
	}
	return out, nil
}

func sshMatch(asset shared.ID, cve string) softwarematch.Match {
	m := match(asset, cve, 80)
	m.Port, m.Location, m.Product, m.Vendor, m.Version = 22, "tcp/22", "openssh", "openbsd", "9.6p1"
	m.CVE.Severity = "critical"
	return m
}

// A match on the shared front end of a site-building provider (an address
// every tenant name reaches through the provider's host) is the provider's
// software: attributed to it and capped at P3. The same software on the
// organization's own address is raised as usual.
func TestReconcile_SharedHostingIsAttributedToTheProvider(t *testing.T) {
	providerIP, ownIP := shared.NewID(), shared.NewID()
	store := &hostingStore{fakeStore: newFakeStore(), facts: map[shared.ID]softwarematch.HostFacts{
		providerIP: {Name: "203.0.113.114:22", NameCNAMEs: []string{"dns.ladipage.com", "dns.ladipage.com"}},
		ownIP:      {Name: "198.51.100.7:22", NameCNAMEs: []string{"", "dns.ladipage.com"}},
	}}
	store.matches = []softwarematch.Match{sshMatch(providerIP, "CVE-2024-6387"), sshMatch(ownIP, "CVE-2024-6387")}
	svc, w := newSvc(store.fakeStore, true)
	svc.store = store
	var st Stats
	if err := svc.ReconcileTenant(context.Background(), shared.NewID(), &st); err != nil {
		t.Fatal(err)
	}
	if len(w.created) != 2 {
		t.Fatalf("created %d, want 2", len(w.created))
	}
	for _, f := range w.created {
		vm, _ := f.Metadata()["version_match"].(map[string]any)
		reasons, _ := vm["reasons"].([]string)
		switch f.AssetID() {
		case providerIP:
			if vm["hosted_by"] != "LadiPage" || vm["attributed_to"] != "provider" || !slices.Contains(reasons, "shared_hosting") {
				t.Fatalf("provider match evidence = %v", vm)
			}
			if p := f.PriorityClass(); p == nil || *p != vulnerability.PriorityP3 {
				t.Fatalf("provider match priority = %v", p)
			}
		case ownIP:
			if _, ok := vm["hosted_by"]; ok {
				t.Fatalf("own address attributed to a provider: %v", vm)
			}
			if p := f.PriorityClass(); p != nil && *p == vulnerability.PriorityP3 {
				t.Fatal("own address capped as context")
			}
		}
	}
}

// A CVE whose applicability names the product with no version range (the
// trojaned-package advisories of 2008 are the classic case) matches every
// version and must never become a finding; a distro build is not raised
// unless the organization opts in.
func TestReconcile_NoRangeAndDistroBuildsAreNotRaised(t *testing.T) {
	store := newFakeStore()
	noRange := sshMatch(shared.NewID(), "CVE-2008-3844")
	noRange.Result.AllVersions = true
	noRange.Result.RangeText = "*"
	distro := sshMatch(shared.NewID(), "CVE-2024-6387")
	distro.Qualifier = "Ubuntu-3ubuntu13.5"
	store.matches = []softwarematch.Match{noRange, distro}
	svc, w := newSvc(store, true)
	var st Stats
	if err := svc.ReconcileTenant(context.Background(), shared.NewID(), &st); err != nil {
		t.Fatal(err)
	}
	if len(w.created) != 0 {
		t.Fatalf("raised %d findings (%s)", len(w.created), w.created[0].CVEID())
	}
}

func TestCapSharedHostingPriority(t *testing.T) {
	f, _ := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceVA, softwarematch.ToolName, vulnerability.SeverityCritical, "m")
	f.SetPriorityClassification(vulnerability.PriorityP0, "x")
	f.SetMetadata("version_match", map[string]any{"hosted_by": "LadiPage"})
	vulnerability.CapSharedHostingPriority(f)
	if *f.PriorityClass() != vulnerability.PriorityP3 {
		t.Fatalf("priority %s", *f.PriorityClass())
	}
	g, _ := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceVA, softwarematch.ToolName, vulnerability.SeverityCritical, "m")
	g.SetPriorityClassification(vulnerability.PriorityP0, "x")
	g.SetMetadata("version_match", map[string]any{"label": "likely"})
	vulnerability.CapSharedHostingPriority(g)
	if *g.PriorityClass() != vulnerability.PriorityP0 {
		t.Fatal("an own match was capped")
	}
}
