package certmonitor

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

type fakeSeeds map[shared.ID][]string

func (f fakeSeeds) DiscoveryRootDomains(_ context.Context, tenantID shared.ID) ([]string, error) {
	return f[tenantID], nil
}

// A root_domain seed is watched (RFC-036 §6.3). Names under it are asserted
// (needs review) unless a verified domain covers them; another tenant's seed
// is never queried for this tenant.
func TestMonitorTenant_WatchesSeeds(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	srv := ctNames(t, "www")
	defer srv.Close()

	svc, inv, attr := promotionService(t, srv.URL, srv.Client(), tenant, nil)
	now := time.Now().UTC()
	svc.SetDomainSources(fakeVerified{list: []*verifieddomain.VerifiedDomain{
		verifieddomain.Reconstruct(shared.NewID(), tenant, "proven.com", "tok", verifieddomain.StatusVerified, &now, &now, now, now),
	}}, nil)
	svc.SetSeedSource(fakeSeeds{tenant: {"seeded.com", "proven.com"}, other: {"theirs.com"}})

	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	want := map[string]attribution.State{
		"www.seeded.com": attribution.StateNeedsReview, // asserted by the seed
		"www.proven.com": attribution.StateConfirmed,   // the verified origin wins over the seed
	}
	for name, state := range want {
		a, ok := inv.byName[name]
		if !ok {
			t.Fatalf("%s not promoted", name)
		}
		if got := attr.records[a.ID().String()].State; got != state {
			t.Errorf("%s: %q, want %q", name, got, state)
		}
	}
	if _, ok := inv.byName["www.theirs.com"]; ok {
		t.Fatal("another tenant's seed was queried for this tenant")
	}
}
