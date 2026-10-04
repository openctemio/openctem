package asset

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Every input the registry accepts resolves to a stored pair: a core type and
// a sub-type from its closed list (RFC-042 §6.3.8 R1, R2).
func TestResolveInputType_EveryInputResolvesToAStoredPair(t *testing.T) {
	for from, to := range registryInputs {
		r, err := ResolveInputType(string(from.Type), from.SubType)
		if err != nil {
			t.Errorf("input %v: %v", from, err)
			continue
		}
		if !r.Type.IsStored() || !IsValidSubType(r.Type, r.SubType) {
			t.Errorf("input %v resolved to (%s, %q), not a stored pair", from, r.Type, r.SubType)
		}
		if r.Type != to.Type || r.SubType != to.SubType || r.Provider != to.Provider {
			t.Errorf("input %v resolved to %+v, registry says %+v", from, r, to)
		}
	}
}

// Every registry type is an accepted input, and every core type with every
// declared sub-type resolves to itself.
func TestResolveInputType_EveryRegistryType(t *testing.T) {
	for _, d := range registryTypes {
		r, err := ResolveInputType(string(d.Type), "")
		if err != nil {
			t.Fatalf("%s: %v", d.Type, err)
		}
		if !r.Type.IsStored() {
			t.Errorf("%s resolved to non-core %s", d.Type, r.Type)
		}
		if d.AliasOf == nil {
			if r.Type != d.Type || r.SubType != "" {
				t.Errorf("core %s resolved to (%s, %q)", d.Type, r.Type, r.SubType)
			}
			for _, st := range d.SubTypes {
				r, err := ResolveInputType(string(d.Type), st)
				if err != nil || r.Type != d.Type || r.SubType != st {
					t.Errorf("(%s, %s) resolved to %+v, %v", d.Type, st, r, err)
				}
			}
			continue
		}
		if r.Type != d.AliasOf.Type || r.SubType != d.AliasOf.SubType {
			t.Errorf("alias %s resolved to (%s, %q), want %v", d.Type, r.Type, r.SubType, *d.AliasOf)
		}
	}
}

func TestStoredAssetTypes_AreTheCoreTypes(t *testing.T) {
	var want []AssetType
	for _, d := range registryTypes {
		if d.AliasOf == nil {
			want = append(want, d.Type)
		}
	}
	if got := StoredAssetTypes(); !slices.Equal(got, want) {
		t.Errorf("StoredAssetTypes = %v, want %v", got, want)
	}
	for alias := range TypeAliases {
		if alias.IsStored() {
			t.Errorf("alias %s is storable", alias)
		}
		if !alias.IsValid() {
			t.Errorf("alias %s is not an accepted input", alias)
		}
	}
	if len(want) != 17 {
		t.Errorf("%d core types, RFC-042 §6.3.8 lists 17 until T4a", len(want))
	}
}

func TestResolveInputType_Examples(t *testing.T) {
	cases := []struct {
		typ, sub string
		want     ResolvedType
	}{
		{"website", "", ResolvedType{Type: AssetTypeApplication, SubType: "website"}},
		{"Website", "website", ResolvedType{Type: AssetTypeApplication, SubType: "website"}},
		{" FIREWALL ", "", ResolvedType{Type: AssetTypeNetwork, SubType: "firewall"}},
		{"database", "PostgreSQL", ResolvedType{Type: AssetTypeDatabase, SubType: "relational", Attributes: map[string]string{"engine": "postgresql"}}},
		{"cloud_account", "aws", ResolvedType{Type: AssetTypeCloudAccount, Provider: ProviderAWS, Attributes: map[string]string{"provider": "aws"}}},
		{"repository", "github", ResolvedType{Type: AssetTypeRepository, Provider: ProviderGitHub, Attributes: map[string]string{"provider": "github"}}},
		{"s3_bucket", "", ResolvedType{Type: AssetTypeStorage, SubType: "bucket", Provider: ProviderAWS, Attributes: map[string]string{"provider": "aws"}}},
		{"service", "port", ResolvedType{Type: AssetTypeService, SubType: "open_port"}},
		{"host", "server", ResolvedType{Type: AssetTypeHost}},
		{"host", "linux", ResolvedType{Type: AssetTypeHost, Attributes: map[string]string{"os_family": "linux"}}},
		{"host", "kubernetes_cluster", ResolvedType{Type: AssetTypeKubernetes, SubType: "cluster"}},
		{"container", "deployment", ResolvedType{Type: AssetTypeKubernetes, SubType: "workload", Attributes: map[string]string{"workload_kind": "deployment"}}},
		{"network", "wireless_ap", ResolvedType{Type: AssetTypeNetwork, SubType: "access_point"}},
		// data_store leaves the sub-type open; a kind is still validated.
		{"data_store", "", ResolvedType{Type: AssetTypeDatabase}},
		{"data_store", "mongodb", ResolvedType{Type: AssetTypeDatabase, SubType: "document", Attributes: map[string]string{"engine": "mongodb"}}},
	}
	for _, c := range cases {
		got, err := ResolveInputType(c.typ, c.sub)
		if err != nil {
			t.Errorf("(%q, %q): %v", c.typ, c.sub, err)
			continue
		}
		if got.Type != c.want.Type || got.SubType != c.want.SubType || got.Provider != c.want.Provider ||
			len(got.Attributes) != len(c.want.Attributes) {
			t.Errorf("(%q, %q) = %+v, want %+v", c.typ, c.sub, got, c.want)
			continue
		}
		for k, v := range c.want.Attributes {
			if got.Attributes[k] != v {
				t.Errorf("(%q, %q) attribute %s = %q, want %q", c.typ, c.sub, k, got.Attributes[k], v)
			}
		}
	}
}

func TestResolveInputType_StrictRejects(t *testing.T) {
	cases := []struct{ typ, sub, msg string }{
		{"", "", "required"},
		{"server", "", "invalid asset type"},   // a legacy code, never a registry type
		{"ip_range", "", "invalid asset type"}, // a legacy asset_types row
		{"not_a_type", "", "invalid asset type"},
		{"network", "lan", "invalid sub_type"},         // not in the closed list
		{"identity", "credential", "invalid sub_type"}, // removed: a secret (O4)
		{"application", "api_collection", "invalid sub_type"},
		{"website", "api", "contradicts"},           // alias fixes the sub-type
		{"domain", "subdomain", "invalid sub_type"}, // O1 lands in T4a
		{"host", strings.Repeat("x", 51), "longer than"},
	}
	for _, c := range cases {
		_, err := ResolveInputType(c.typ, c.sub)
		if err == nil || !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("(%q, %q): err = %v, want a validation error containing %q", c.typ, c.sub, err, c.msg)
		}
	}
}

// Machine producers are never refused for a sub-type: it is kept for
// re-classification instead.
func TestResolveInputTypeLenient_KeepsUnknownSubType(t *testing.T) {
	r, err := ResolveInputTypeLenient("network", "lan")
	if err != nil || r.Type != AssetTypeNetwork || r.SubType != "" || r.NativeSubType != "lan" {
		t.Fatalf("got %+v, %v", r, err)
	}
	r, err = ResolveInputTypeLenient("website", "api")
	if err != nil || r.SubType != "website" || r.NativeSubType != "api" {
		t.Fatalf("contradicting alias: got %+v, %v", r, err)
	}
	if _, err := ResolveInputTypeLenient("not_a_type", ""); err == nil {
		t.Fatal("an unknown type must still fail (callers map it to unclassified)")
	}
	props := r.MergeImplied(map[string]any{PropKeyNativeSubType: "kept"})
	if props[PropKeyNativeSubType] != "kept" {
		t.Errorf("MergeImplied overwrote an existing value: %v", props)
	}
}

func TestNewAssetWithSubType_RefusesInputNames(t *testing.T) {
	if _, err := NewAsset("https://app.example.com", AssetTypeWebsite, CriticalityLow); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("an alias type was accepted: %v", err)
	}
	if _, err := NewAssetWithSubType("10.0.0.0/8", AssetTypeNetwork, "lan", CriticalityLow); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("an undeclared sub-type was accepted: %v", err)
	}
	if _, err := NewAssetWithSubType("10.0.0.0/8", AssetTypeNetwork, "subnet", CriticalityLow); err != nil {
		t.Errorf("a declared sub-type was refused: %v", err)
	}
}

func TestAsset_ChangeSubTypeAndApplyResolvedType(t *testing.T) {
	a, err := NewAsset("orders-db", AssetTypeDatabase, CriticalityHigh)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.ChangeSubType("postgresql"); err == nil {
		t.Error("ChangeSubType accepted a legacy value without resolution")
	}
	a.SetProperties(map[string]any{"engine": "aurora-postgresql"})
	r, _ := ResolveInputType("database", "postgresql")
	a.ApplyResolvedType(r)
	if a.SubType() != "relational" {
		t.Errorf("sub-type = %q, want relational", a.SubType())
	}
	if a.Properties()["engine"] != "aurora-postgresql" {
		t.Errorf("an existing attribute was overwritten: %v", a.Properties())
	}

	// A resolution for another type changes nothing.
	other, _ := ResolveInputType("s3_bucket", "")
	before := a.SubType()
	a.ApplyResolvedType(other)
	if a.SubType() != before || a.Provider() == ProviderAWS {
		t.Error("ApplyResolvedType applied another type's resolution")
	}
	if err := a.ChangeSubType(""); err != nil || a.SubType() != "" {
		t.Errorf("clearing the sub-type: %v", err)
	}
}
