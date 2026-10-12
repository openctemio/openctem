package certmonitor

import (
	"context"
	"errors"
	"testing"
	"time"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/verifieddomain"
)

type fakeTombstones struct {
	dead   map[string][]attribution.Rule
	err    error
	purged int
}

func (f *fakeTombstones) Tombstoned(_ context.Context, _ shared.ID, names []string) (map[string][]attribution.Rule, error) {
	out := map[string][]attribution.Rule{}
	for _, n := range names {
		if r, ok := f.dead[n]; ok {
			out[n] = r
		}
	}
	return out, f.err
}

func (f *fakeTombstones) PurgeExpiredTombstones(context.Context, shared.ID) (int64, error) {
	f.purged++
	return 0, nil
}

// A rejected name (asset since deleted) is not proposed again under the rule
// it was rejected with; a new rule (the domain is now verified) brings it
// back, and expired tombstones are purged each sweep (O7).
func TestPromote_TombstonesBlockRepromotion(t *testing.T) {
	tenant := shared.NewID()
	srv := ctNames(t, "www", "api")
	defer srv.Close()

	listed := mustDomainAsset(t, tenant, "listed.com")
	svc, inv, _ := promotionService(t, srv.URL, srv.Client(), tenant, []*assetdom.Asset{listed})
	now := time.Now().UTC()
	svc.SetDomainSources(fakeVerified{list: []*verifieddomain.VerifiedDomain{
		verifieddomain.Reconstruct(shared.NewID(), tenant, "proven.com", "tok", verifieddomain.StatusVerified, &now, &now, now, now),
	}}, nil)
	tomb := &fakeTombstones{dead: map[string][]attribution.Rule{
		"www.listed.com": {attribution.RuleAssertedRoot}, // rejected under the same rule: stays out
		"www.proven.com": {attribution.RuleAssertedRoot}, // rejected before the domain was verified: a new rule now
	}}
	svc.SetTombstones(tomb)

	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if _, ok := inv.byName["www.listed.com"]; ok {
		t.Fatal("a rejected name was proposed again under the same rule")
	}
	for _, n := range []string{"api.listed.com", "www.proven.com"} {
		if _, ok := inv.byName[n]; !ok {
			t.Errorf("%s not promoted", n)
		}
	}
	if tomb.purged != 1 {
		t.Fatalf("expired tombstones purged %d times, want once per sweep", tomb.purged)
	}

	// A failed tombstone lookup promotes nothing rather than resurrecting names.
	srv2 := ctNames(t, "fresh")
	defer srv2.Close()
	svc2, inv2, _ := promotionService(t, srv2.URL, srv2.Client(), tenant, []*assetdom.Asset{listed})
	svc2.SetTombstones(&fakeTombstones{err: errors.New("db down")})
	_, _ = svc2.MonitorTenant(context.Background(), tenant)
	if _, ok := inv2.byName["fresh.listed.com"]; ok {
		t.Fatal("promoted without the tombstone check")
	}
}
