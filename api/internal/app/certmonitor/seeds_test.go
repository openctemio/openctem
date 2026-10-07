package certmonitor

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

// Discovery hangs off scope entries (research/53 SC1): a permanent domain
// entry with discovery on is watched; one with discovery off, or a one-off
// entry, is not. Names under a watched entry are asserted (needs review)
// unless a verified domain covers them.
func TestMonitorTenant_WatchesEntriesWithDiscovery(t *testing.T) {
	tenant := shared.NewID()
	srv := ctNames(t, "www")
	defer srv.Close()

	entry := func(pattern string, discovery bool, expires *time.Time) *scope.Target {
		t.Helper()
		e, err := scope.NewEntry(tenant, scope.TargetTypeDomain, pattern, "", "u", scope.EntryOptions{
			Reason: "r", MaxTier: scope.TierActive, ExpiresAt: expires})
		if err != nil {
			t.Fatal(err)
		}
		e.SetDiscovery(discovery)
		return e
	}
	soon := time.Now().Add(48 * time.Hour)
	svc, inv, attr := promotionService(t, srv.URL, srv.Client(), tenant, nil)
	now := time.Now().UTC()
	svc.SetDomainSources(fakeVerified{list: []*verifieddomain.VerifiedDomain{
		verifieddomain.Reconstruct(shared.NewID(), tenant, "proven.com", "tok", verifieddomain.StatusVerified, &now, &now, now, now),
	}}, fakeTargets{list: []*scope.Target{
		entry("*.seeded.com", true, nil),
		entry("*.proven.com", true, nil),
		entry("*.quiet.com", false, nil),
		entry("*.oneoff.com", true, &soon),
	}})

	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	want := map[string]attribution.State{
		"www.seeded.com": attribution.StateNeedsReview, // asserted by the entry
		"www.proven.com": attribution.StateConfirmed,   // the verified origin wins
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
	for _, name := range []string{"www.quiet.com", "www.oneoff.com"} {
		if _, ok := inv.byName[name]; ok {
			t.Errorf("%s was discovered from an entry that must not discover", name)
		}
	}
}
