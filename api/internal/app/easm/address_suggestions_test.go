package easm

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeResolved struct {
	tenant shared.ID
	rows   []ResolvedAddress
}

func (f fakeResolved) ResolvedAddresses(_ context.Context, t shared.ID, _ int) ([]ResolvedAddress, error) {
	if !t.Equals(f.tenant) {
		return nil, nil
	}
	return f.rows, nil
}

func rn(names ...string) []ResolvedName {
	out := make([]ResolvedName, 0, len(names))
	for _, n := range names {
		out = append(out, ResolvedName{AssetID: shared.NewID().String(), Name: n})
	}
	return out
}

// Offered: a public address an in-scope name resolves to that no entry
// covers, with its in-scope names and its cloud provider. Not offered: an
// address only out-of-scope names resolve to, one an entry already covers,
// a private one, an edge/CDN provider's, one names of three registrable
// domains share (counted as shared), and another tenant's.
func TestAddressSuggestions(t *testing.T) {
	f := newGateFixture(t) // entries: *.scoped.com, 198.51.100.0/24
	id := func() string { return shared.NewID().String() }
	store := fakeResolved{tenant: f.tenant, rows: []ResolvedAddress{
		{AssetID: id(), Address: "203.0.113.9", Names: rn("www.scoped.com", "other.example"),
			Properties: map[string]any{"asn_org": "Amazon.com, Inc."}},
		{AssetID: id(), Address: "203.0.113.10", Names: rn("only.example")},
		{AssetID: id(), Address: "198.51.100.7", Names: rn("api.scoped.com")},
		{AssetID: id(), Address: "10.0.0.8", Names: rn("intra.scoped.com")},
		{AssetID: id(), Address: "203.0.113.11", Names: rn("cdn.scoped.com"), Properties: map[string]any{"cdn": "cloudflare"}},
		{AssetID: id(), Address: "203.0.113.12", Names: rn("edge.scoped.com"), Properties: map[string]any{"asn_org": "Fastly, Inc."}},
		{AssetID: id(), Address: "203.0.113.13", Names: rn("a.scoped.com", "b.one.example", "c.two.example")},
	}}
	g := NewActiveGate(f, f, f, f)
	got, err := NewAddressSuggester(store, g, nil).Suggest(context.Background(), f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Data) != 1 || got.Data[0].Address != "203.0.113.9" || len(got.Data[0].Names) != 1 ||
		got.Data[0].Names[0] != "www.scoped.com" || got.Data[0].Provider != "Amazon.com, Inc." {
		t.Fatalf("suggestions %+v", got.Data)
	}
	if got.SkippedShared != 3 {
		t.Fatalf("skipped shared %d, want 3 (cdn, edge provider, shared hosting)", got.SkippedShared)
	}

	other, err := NewAddressSuggester(store, g, nil).Suggest(context.Background(), shared.NewID())
	if err != nil || len(other.Data) != 0 {
		t.Fatalf("another tenant: %+v %v", other, err)
	}
}

// scopeRows is a datascope.Repository for one restricted member who sees
// only the listed assets.
type scopeRows map[string]bool

func (s scopeRows) pick(ids []shared.ID) []shared.ID {
	out := []shared.ID{}
	for _, id := range ids {
		if s[id.String()] {
			out = append(out, id)
		}
	}
	return out
}
func (s scopeRows) AssetIDsInScope(_ context.Context, _, _ shared.ID, ids []shared.ID) ([]shared.ID, error) {
	return s.pick(ids), nil
}
func (scopeRows) FindingAssetID(context.Context, shared.ID, shared.ID) (shared.ID, error) {
	return shared.ID{}, shared.ErrNotFound
}
func (scopeRows) HasFullDataRole(context.Context, shared.ID, shared.ID) (bool, error) {
	return false, nil
}
func (scopeRows) FindingIDsInScope(context.Context, shared.ID, shared.ID, []shared.ID) ([]shared.ID, error) {
	return nil, nil
}
func (scopeRows) AssetIDsInTenant(_ context.Context, _ shared.ID, ids []shared.ID) ([]shared.ID, error) {
	return ids, nil
}
func (scopeRows) HasHiddenAssets(context.Context, shared.ID, shared.ID) (bool, error) {
	return false, nil
}
func (s scopeRows) AssetIDsVisible(_ context.Context, _, _ shared.ID, ids []shared.ID) ([]shared.ID, error) {
	return s.pick(ids), nil
}
func (scopeRows) FindingIDsVisible(context.Context, shared.ID, shared.ID, []shared.ID) ([]shared.ID, error) {
	return nil, nil
}

// A restricted member sees an address only when it and an in-scope name
// behind it are in their data scope.
func TestAddressSuggestions_DataScope(t *testing.T) {
	f := newGateFixture(t)
	visibleIP, hiddenIP := shared.NewID().String(), shared.NewID().String()
	visibleName, hiddenName := shared.NewID().String(), shared.NewID().String()
	store := fakeResolved{tenant: f.tenant, rows: []ResolvedAddress{
		{AssetID: visibleIP, Address: "203.0.113.20", Names: []ResolvedName{{AssetID: visibleName, Name: "a.scoped.com"}}},
		{AssetID: hiddenIP, Address: "203.0.113.21", Names: []ResolvedName{{AssetID: visibleName, Name: "a.scoped.com"}}},
		{AssetID: shared.NewID().String(), Address: "203.0.113.22", Names: []ResolvedName{{AssetID: hiddenName, Name: "b.scoped.com"}}},
	}}
	member := shared.NewID().String()
	enf := datascope.New(scopeRows{visibleIP: true, visibleName: true}, func(context.Context) datascope.Caller {
		return datascope.Caller{UserID: member}
	}, nil)
	got, err := NewAddressSuggester(store, NewActiveGate(f, f, f, f), enf).Suggest(context.Background(), f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Data) != 1 || got.Data[0].Address != "203.0.113.20" {
		t.Fatalf("restricted member sees %+v, want only 203.0.113.20", got.Data)
	}
}
