package assettech

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/software"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type fakeLinkStore struct {
	rows     []VersionlessTechnology
	progress map[shared.ID]SoftwareLinkProgress
	done     map[shared.ID]bool
	scans    int
	failAt   int // the scan number that fails (0: none)
}

func (f *fakeLinkStore) PendingSoftwareLinkTenants(context.Context, int) ([]shared.ID, error) {
	var out []shared.ID
	for id := range f.progress {
		if !f.done[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

func (f *fakeLinkStore) SoftwareLinkProgress(_ context.Context, id shared.ID, _ int) (SoftwareLinkProgress, error) {
	return f.progress[id], nil
}

func (f *fakeLinkStore) ScanVersionlessTechnologies(_ context.Context, _ shared.ID, afterAsset, afterKey string, _ []string, limit int) ([]VersionlessTechnology, error) {
	f.scans++
	if f.failAt == f.scans {
		return nil, fmt.Errorf("connection lost")
	}
	var out []VersionlessTechnology
	for _, r := range f.rows {
		a := r.AssetID.String()
		if a < afterAsset || (a == afterAsset && r.Key <= afterKey) {
			continue
		}
		out = append(out, r)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (f *fakeLinkStore) SaveSoftwareLinkProgress(_ context.Context, id shared.ID, _ int, p SoftwareLinkProgress, done bool) error {
	f.progress[id] = p
	f.done[id] = done
	return nil
}

type fakeSoftwareRepo struct {
	software.Repository
	links    map[string]int // asset|product -> writes
	products map[string]shared.ID
}

func (r *fakeSoftwareRepo) EnsureCurated(context.Context, []software.Curated) error { return nil }

func (r *fakeSoftwareRepo) Resolve(_ context.Context, _ shared.ID, ids []software.Identity) (map[software.Identity]software.ProductRef, error) {
	out := map[software.Identity]software.ProductRef{}
	for _, id := range ids {
		if r.products == nil {
			r.products = map[string]shared.ID{}
		}
		if _, ok := r.products[id.Name]; !ok {
			r.products[id.Name] = shared.NewID()
		}
		out[id] = software.ProductRef{ID: r.products[id.Name], Global: true}
	}
	return out, nil
}

func (r *fakeSoftwareRepo) EnsureVersion(context.Context, shared.ID, software.ProductRef, software.VersionKey) (shared.ID, error) {
	return shared.NewID(), nil
}

func (r *fakeSoftwareRepo) UpsertLinks(_ context.Context, _ shared.ID, links []software.Link) (software.LinkResult, error) {
	res := software.LinkResult{}
	for _, l := range links {
		k := l.AssetID.String() + "|" + l.ProductID.String()
		if r.links[k] == 0 {
			res.Inserted++
			res.ChangedAssets = append(res.ChangedAssets, l.AssetID)
		}
		r.links[k]++
	}
	return res, nil
}

// A run stopped part-way resumes at the saved position: every technology
// is linked once and none is read twice after the stop.
func TestSoftwareLinkBackfillResumes(t *testing.T) {
	tenant := shared.NewID()
	store := &fakeLinkStore{progress: map[shared.ID]SoftwareLinkProgress{tenant: {}}, done: map[shared.ID]bool{}}
	at := time.Now().UTC()
	for i := 0; i < 2*softwareLinkBatch+7; i++ {
		store.rows = append(store.rows, VersionlessTechnology{AssetID: shared.NewID(), Key: "nginx", Name: "nginx", LastSeen: at})
	}
	sort.Slice(store.rows, func(i, j int) bool { return store.rows[i].AssetID.String() < store.rows[j].AssetID.String() })
	repo := &fakeSoftwareRepo{links: map[string]int{}}
	b := NewSoftwareLinkBackfill(store, repo, nil, logger.NewNop())

	store.failAt = 2 // the second batch fails: the first is saved
	if _, err := b.RunTenant(context.Background(), tenant); err == nil {
		t.Fatal("expected the failed batch to stop the run")
	}
	if store.done[tenant] || store.progress[tenant].Linked != softwareLinkBatch {
		t.Fatalf("after the stop: done=%v progress=%+v", store.done[tenant], store.progress[tenant])
	}
	store.failAt = 0
	n, err := b.Run(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("resume finished %d tenants, err %v", n, err)
	}
	if got := store.progress[tenant].Linked; got != len(store.rows) {
		t.Fatalf("linked %d, want %d", got, len(store.rows))
	}
	for k, writes := range repo.links {
		if writes != 1 {
			t.Fatalf("%s written %d times", k, writes)
		}
	}
	if n, _ := b.Run(context.Background()); n != 0 {
		t.Fatalf("a finished tenant ran again")
	}
}

// Only curated public names are linked: a private name or a CDN that a
// store would return is skipped.
func TestSoftwareLinkBackfillCuratedOnly(t *testing.T) {
	tenant := shared.NewID()
	at := time.Now().UTC()
	store := &fakeLinkStore{progress: map[shared.ID]SoftwareLinkProgress{tenant: {}}, done: map[shared.ID]bool{}, rows: []VersionlessTechnology{
		{AssetID: shared.NewID(), Key: "acme portal", Name: "Acme Portal", LastSeen: at},
		{AssetID: shared.NewID(), Key: "cloudflare", Name: "Cloudflare", LastSeen: at},
		{AssetID: shared.NewID(), Key: "nginx", Name: "nginx", LastSeen: at},
	}}
	repo := &fakeSoftwareRepo{links: map[string]int{}}
	if _, err := NewSoftwareLinkBackfill(store, repo, nil, logger.NewNop()).RunTenant(context.Background(), tenant); err != nil {
		t.Fatal(err)
	}
	if len(repo.links) != 1 {
		t.Fatalf("linked %d products, want only nginx", len(repo.links))
	}
}
