package assetfreshness

import (
	"context"
	"errors"
	"testing"
	"time"

	assetdom "github.com/openctemio/openctem/api/pkg/domain/asset"
	freshdom "github.com/openctemio/openctem/api/pkg/domain/assetfreshness"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeRepo struct {
	tenant shared.ID
	got    []freshdom.Observation
	err    error
}

func (f *fakeRepo) Record(_ context.Context, tenantID shared.ID, obs []freshdom.Observation) error {
	f.tenant, f.got = tenantID, obs
	return f.err
}

func (f *fakeRepo) ListForAsset(context.Context, shared.ID, shared.ID) ([]freshdom.Observation, error) {
	return nil, nil
}

func mustAsset(t *testing.T, name string, typ assetdom.AssetType) *assetdom.Asset {
	t.Helper()
	a, err := assetdom.NewAsset(name, typ, assetdom.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestRecorder_MapsWrittenAssetsToClasses(t *testing.T) {
	repo := &fakeRepo{}
	r := NewRecorder(repo, logger.NewNop())
	tenant := shared.NewID()
	at := time.Now().UTC()
	sub := mustAsset(t, "a.example.com", assetdom.AssetTypeSubdomain)
	ip := mustAsset(t, "192.0.2.10", assetdom.AssetTypeIPAddress)

	r.AssetsObserved(context.Background(), tenant, "dnsx", at, []*assetdom.Asset{sub, ip, nil})
	if repo.tenant != tenant || len(repo.got) != 1 || repo.got[0].AssetID != sub.ID() ||
		repo.got[0].Class != freshdom.ClassDNS || !repo.got[0].ObservedAt.Equal(at) || repo.got[0].Source != "dnsx" {
		t.Fatalf("recorded %+v for tenant %s", repo.got, repo.tenant)
	}

	// A tool that observes no class writes nothing.
	repo.got = nil
	r.AssetsObserved(context.Background(), tenant, "nuclei", at, []*assetdom.Asset{sub})
	if repo.got != nil {
		t.Fatalf("nuclei recorded %+v", repo.got)
	}

	// A failing store never panics or propagates.
	repo.err = errors.New("db down")
	r.AssetsObserved(context.Background(), tenant, "asn", at, []*assetdom.Asset{ip})
}

type fakeResolution struct {
	tenant shared.ID
	ids    []shared.ID
}

func (f *fakeResolution) RecordResolved(_ context.Context, t shared.ID, ids []shared.ID, _ time.Time) error {
	f.tenant, f.ids = t, append(f.ids, ids...)
	return nil
}

// A name a resolver reported (or a tool reached by name) is resolving again,
// so an active stage takes it; addresses and tools that prove nothing do not.
func TestRecorder_ResolvedNamesComeBack(t *testing.T) {
	res := &fakeResolution{}
	r := NewRecorder(&fakeRepo{}, logger.NewNop())
	r.SetResolution(res)
	tenant := shared.NewID()
	sub := mustAsset(t, "a.example.com", assetdom.AssetTypeSubdomain)
	ip := mustAsset(t, "192.0.2.10", assetdom.AssetTypeIPAddress)

	r.AssetsObserved(context.Background(), tenant, "dnsx", time.Now(), []*assetdom.Asset{sub, ip})
	if res.tenant != tenant || len(res.ids) != 1 || res.ids[0] != sub.ID() {
		t.Fatalf("resolved %v for %s", res.ids, res.tenant)
	}
	res.ids = nil
	r.AssetsObserved(context.Background(), tenant, "nuclei", time.Now(), []*assetdom.Asset{sub})
	if len(res.ids) != 0 {
		t.Fatalf("a tool that proves nothing marked %v resolving", res.ids)
	}
}
