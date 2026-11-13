package assetcanon

import (
	"context"
	"sort"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// fakeStore keeps assets per tenant; names are unique per tenant as in the
// database (idx_assets_name_tenant_unique).
type fakeStore struct {
	assets  map[string][]Asset // tenant -> assets
	journal map[string][]string
}

func (f *fakeStore) Tenants(context.Context) ([]shared.ID, error) {
	var out []shared.ID
	for t := range f.assets {
		id, _ := shared.IDFromString(t)
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

func (f *fakeStore) Page(_ context.Context, tenant shared.ID, after string, limit int) ([]Asset, error) {
	list := append([]Asset(nil), f.assets[tenant.String()]...)
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	var out []Asset
	for _, a := range list {
		if a.ID > after && len(out) < limit {
			out = append(out, a)
		}
	}
	return out, nil
}

func (f *fakeStore) Holder(_ context.Context, tenant shared.ID, name string) (*Asset, error) {
	for _, a := range f.assets[tenant.String()] {
		if a.Name == name {
			a := a
			return &a, nil
		}
	}
	return nil, nil
}

func (f *fakeStore) Rename(ctx context.Context, tenant shared.ID, a Asset, name string) (bool, error) {
	if h, _ := f.Holder(ctx, tenant, name); h != nil {
		return false, nil
	}
	list := f.assets[tenant.String()]
	for i := range list {
		if list[i].ID == a.ID && list[i].Name == a.Name {
			list[i].Name = name
			f.journal[tenant.String()] = append(f.journal[tenant.String()], "rename "+a.ID)
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeStore) Merge(_ context.Context, tenant shared.ID, a, keep Asset) (bool, error) {
	list := f.assets[tenant.String()]
	out := list[:0]
	found := false
	for _, x := range list {
		if x.ID == a.ID {
			found = true
			continue
		}
		out = append(out, x)
	}
	f.assets[tenant.String()] = out
	f.journal[tenant.String()] = append(f.journal[tenant.String()], "merge "+a.ID+">"+keep.ID)
	return found, nil
}

func (f *fakeStore) Conflict(_ context.Context, tenant shared.ID, a Asset, _ string, _ string) error {
	f.journal[tenant.String()] = append(f.journal[tenant.String()], "conflict "+a.ID)
	return nil
}

func (f *fakeStore) Revert(context.Context, shared.ID) (int, int, error) { return 0, 0, nil }

const (
	tenantA = "00000000-0000-0000-0000-00000000000a"
	tenantB = "00000000-0000-0000-0000-00000000000b"
)

func TestRunRenamesMergesAndIsIdempotent(t *testing.T) {
	st := &fakeStore{journal: map[string][]string{}, assets: map[string][]Asset{
		tenantA: {
			{ID: "1", Type: "subdomain", Name: "bücher.example.com"},         // rename
			{ID: "2", Type: "subdomain", Name: "xn--bcher-kva.shop.example"}, // already canonical
			{ID: "3", Type: "subdomain", Name: "bücher.shop.example"},        // merge into 2
			{ID: "4", Type: "domain", Name: "xn--caf-dma.example.com"},       // canonical, held by another type
			{ID: "5", Type: "subdomain", Name: "café.example.com"},           // conflict with 4
			{ID: "6", Type: "ip_address", Name: "203.0.113.5"},               // unchanged
		},
		// Tenant B has the canonical name tenant A's asset 1 moves to: it
		// must play no part in tenant A's run.
		tenantB: {{ID: "9", Type: "subdomain", Name: "xn--bcher-kva.example.com"}},
	}}
	svc := NewService(st)
	ta, _ := shared.IDFromString(tenantA)

	dry, err := svc.Run(context.Background(), ta, false)
	if err != nil {
		t.Fatal(err)
	}
	if dry.Renamed != 1 || dry.Merged != 1 || dry.Conflicts != 1 || dry.Unchanged != 3 || len(st.journal[tenantA]) != 0 {
		t.Fatalf("dry run = %+v, journal %v; want 1 rename, 1 merge, 1 conflict, 3 unchanged and no change", dry, st.journal[tenantA])
	}

	rep, err := svc.Run(context.Background(), ta, true)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Renamed != 1 || rep.Merged != 1 || rep.Conflicts != 1 || rep.Scanned != 6 {
		t.Fatalf("run = %+v", rep)
	}
	if len(st.assets[tenantA]) != 5 {
		t.Fatalf("tenant A has %d assets after one merge, want 5", len(st.assets[tenantA]))
	}
	if got := st.assets[tenantB]; len(got) != 1 || got[0].Name != "xn--bcher-kva.example.com" || len(st.journal[tenantB]) != 0 {
		t.Fatalf("tenant B changed by tenant A's run: %+v %v", got, st.journal[tenantB])
	}

	// Second run: nothing to do but the standing conflict (recorded once in
	// the database by its unique index).
	again, err := svc.Run(context.Background(), ta, true)
	if err != nil {
		t.Fatal(err)
	}
	if again.Renamed != 0 || again.Merged != 0 {
		t.Fatalf("second run changed something: %+v", again)
	}
}
