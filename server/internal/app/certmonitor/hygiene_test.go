package certmonitor

import (
	"context"
	"strings"
	"testing"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	exposuredom "github.com/openctemio/openctem/api/pkg/domain/exposure"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeTombs map[string]bool

func (f fakeTombs) Tombstoned(_ context.Context, _ shared.ID, names []string) (map[string][]attribution.Rule, error) {
	out := map[string][]attribution.Rule{}
	for _, n := range names {
		if f[n] {
			out[n] = []attribution.Rule{attribution.RuleAssertedRoot}
		}
	}
	return out, nil
}

func (f fakeTombs) PurgeExpiredTombstones(context.Context, shared.ID) (int64, error) { return 0, nil }

type fakeRelinker struct{ links map[string]shared.ID }

func (f *fakeRelinker) RelinkExposures(_ context.Context, _ shared.ID, source string, links map[string]shared.ID) (int, error) {
	if source != Source {
		panic("relink of another source")
	}
	f.links = links
	return len(links), nil
}

func ctEvents(r *fakeExposureRepo) map[string]*exposuredom.ExposureEvent {
	out := map[string]*exposuredom.ExposureEvent{}
	for _, e := range r.byKey {
		host, _ := e.Details()["domain"].(string)
		out[string(e.EventType())+"|"+host] = e
	}
	return out
}

// research/22 P0-9 (22c B2): a rejected name, a tombstoned name and every
// name under either produce no CT exposure; a promoted name's exposures
// link to its own asset; the identity does not depend on the link.
func TestCTSweep_RejectionHygieneAndLinking(t *testing.T) {
	tenant := shared.NewID()
	srv := ctNames(t, "www", "notours", "dev.gone", "keep")
	defer srv.Close()
	listed := mustDomainAsset(t, tenant, "listed.com")
	rejected, _ := assetdom.NewAssetWithTenant(tenant, "notours.listed.com", assetdom.AssetTypeSubdomain, assetdom.CriticalityLow)
	svc, inv, attr := promotionService(t, srv.URL, srv.Client(), tenant, []*assetdom.Asset{listed, rejected})
	attr.records[rejected.ID().String()] = attribution.Record{State: attribution.StateRejected, HumanDecided: true}
	svc.SetTombstones(fakeTombs{"gone.listed.com": true})
	rel := &fakeRelinker{}
	svc.SetRelinker(rel)

	if _, err := svc.MonitorTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	evs := ctEvents(svc.exposureRepo.(*fakeExposureRepo))
	for k := range evs {
		if strings.Contains(k, "notours.") || strings.Contains(k, "gone.") {
			t.Errorf("exposure for a rejected name: %s", k)
		}
	}
	www, ok := evs["subdomain_discovered|www.listed.com"]
	if !ok {
		t.Fatalf("no exposure for www: %v", evs)
	}
	wwwAsset := inv.byName["www.listed.com"]
	if wwwAsset == nil || www.AssetID() == nil || *www.AssetID() != wwwAsset.ID() {
		t.Fatalf("www exposure linked to %v, want its own asset", www.AssetID())
	}
	want := exposuredom.Fingerprint(tenant.String(), www.EventType().String(), www.Title(), Source, "", map[string]any{"domain": "www.listed.com"})
	if www.Fingerprint() != want {
		t.Fatal("CT fingerprint depends on the linked asset")
	}
	if rel.links[www.Fingerprint()] != wwwAsset.ID() {
		t.Fatalf("relink = %v", rel.links)
	}
}
