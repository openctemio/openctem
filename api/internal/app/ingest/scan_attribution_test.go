package ingest

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func mustAsset(t *testing.T, name string, typ asset.AssetType) *asset.Asset {
	t.Helper()
	a, err := asset.NewAsset(name, typ, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// A command-bound report attributes the assets it created and the existing
// ones its command covers, and says which of them the tenant typed; an
// unsolicited report only the ones it created; a trusted server-side ingest
// (CT promotion, uploads) nothing.
func TestScanStampTargets(t *testing.T) {
	allowed, other := shared.NewID(), shared.NewID()
	assetMap := map[string]shared.ID{"a": allowed, "b": other, "c": allowed, "z": {}}

	cmd := newAlterScope(Binding{Kind: BindingCommand, Targets: []string{"example.com", "198.51.100.0/24"}})
	cmd.allow(allowed)
	typedA := mustAsset(t, "example.com", asset.AssetTypeDomain)
	child := mustAsset(t, "api.example.com", asset.AssetTypeSubdomain)
	inRange := mustAsset(t, "198.51.100.7", asset.AssetTypeIPAddress)
	cmd.note(typedA, allowed, false)
	cmd.note(child, child.ID(), true)
	cmd.note(inRange, inRange.ID(), true)

	got := scanStampTargets(Binding{Kind: BindingCommand}, cmd, assetMap)
	byID := map[shared.ID]ScannedAsset{}
	for _, a := range got {
		byID[a.ID] = a
	}
	if len(got) != 3 {
		t.Fatalf("command-bound = %+v, want the covered asset and the two created ones", got)
	}
	if a := byID[allowed]; !a.Typed || a.Created {
		t.Fatalf("the command target itself = %+v, want typed, not created", a)
	}
	if a := byID[child.ID()]; a.Typed || !a.Created {
		t.Fatalf("a name found under the target = %+v, want discovered and created", a)
	}
	if a := byID[inRange.ID()]; !a.Typed {
		t.Fatalf("an address inside a range the tenant listed = %+v, want typed", a)
	}
	if _, ok := byID[other]; ok {
		t.Fatal("an asset the report may not change was attributed")
	}

	trusted := newAlterScope(TrustedBinding())
	trusted.allow(allowed)
	trusted.note(child, child.ID(), true)
	if got := scanStampTargets(TrustedBinding(), trusted, assetMap); len(got) != 0 {
		t.Fatalf("trusted ingest attributed %v", got)
	}

	unsolicited := newAlterScope(Binding{})
	unsolicited.allow(allowed)
	unsolicited.note(child, child.ID(), true)
	got = scanStampTargets(Binding{}, unsolicited, assetMap)
	if len(got) != 1 || got[0].ID != child.ID() || got[0].Typed || !got[0].Created {
		t.Fatalf("unsolicited = %+v, want only the created asset, never typed", got)
	}
}

// root_domain must be a registrable strict parent of the reported name.
func TestIsRegistrableParent(t *testing.T) {
	cases := []struct {
		root, name string
		want       bool
	}{
		{"example.com", "www.example.com", true},
		{"example.co.uk", "a.b.example.co.uk", true},
		{"sub.example.com", "a.sub.example.com", true},
		{"example.com", "example.com", false},    // not a strict parent
		{"victim.com", "www.example.com", false}, // unrelated
		{"com", "www.example.com", false},        // a public suffix
		{"co.uk", "www.example.co.uk", false},    // a public suffix
		{"ample.com", "www.example.com", false},  // suffix, not a label boundary
		{"", "www.example.com", false},
	}
	for _, c := range cases {
		if got := isRegistrableParent(c.root, c.name); got != c.want {
			t.Errorf("isRegistrableParent(%q, %q) = %v, want %v", c.root, c.name, got, c.want)
		}
	}
}
