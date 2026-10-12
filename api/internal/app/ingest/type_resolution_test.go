package ingest

import (
	"testing"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// RFC-042 §6.3.8: ingest stores only core types; machine input is resolved
// leniently (an unknown sub-type is kept, never refused).
func TestResolveCTISAssetType(t *testing.T) {
	cases := []struct {
		name      string
		in        ctis.Asset
		wantType  asset.AssetType
		wantSub   string
		wantNorm  string
		wantNativ string
	}{
		{"alias", ctis.Asset{Type: ctis.AssetTypeWebsite}, asset.AssetTypeApplication, "website", "website", ""},
		{"kubernetes without kind is a cluster", ctis.Asset{Type: ctis.AssetTypeKubernetes}, asset.AssetTypeKubernetes, "cluster", "", ""},
		{"kubernetes namespace", ctis.Asset{Type: ctis.AssetTypeKubernetes, Properties: map[string]any{"kind": "Namespace"}}, asset.AssetTypeKubernetes, "namespace", "", ""},
		{"kubernetes workload", ctis.Asset{Type: ctis.AssetTypeKubernetes, Properties: map[string]any{"kind": "Deployment"}}, asset.AssetTypeKubernetes, "workload", "", ""},
		{"legacy sub-type", ctis.Asset{Type: ctis.AssetTypeDatabase, Properties: map[string]any{"sub_type": "postgresql"}}, asset.AssetTypeDatabase, "relational", "", ""},
		{"unknown sub-type is kept", ctis.Asset{Type: ctis.AssetTypeNetwork, Properties: map[string]any{"sub_type": "lan"}}, asset.AssetTypeNetwork, "", "", "lan"},
		{"unknown type", ctis.Asset{Type: "web3_wallet"}, asset.AssetTypeUnclassified, "", "", ""},
		{"server", ctis.Asset{Type: ctis.AssetTypeServer}, asset.AssetTypeHost, "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolveCTISAssetType(&c.in)
			if got.stored.Type != c.wantType || got.stored.SubType != c.wantSub || got.stored.NativeSubType != c.wantNativ {
				t.Errorf("stored = %+v, want (%s, %q, native %q)", got.stored, c.wantType, c.wantSub, c.wantNativ)
			}
			if got.normType != c.wantType || got.normSubType != c.wantNorm {
				t.Errorf("normalization key = (%s, %q), want (%s, %q)", got.normType, got.normSubType, c.wantType, c.wantNorm)
			}
			if !got.stored.Type.IsStored() {
				t.Errorf("non-core type %s", got.stored.Type)
			}
		})
	}
}

func TestCreateAssetFromCTIS_StoresCoreTypes(t *testing.T) {
	p := NewAssetProcessor(nil, logger.NewNop())
	cases := []struct {
		in       ctis.Asset
		wantType asset.AssetType
		wantSub  string
		check    func(t *testing.T, a *asset.Asset)
	}{
		{ctis.Asset{Type: ctis.AssetTypeFirewall, Value: "fw-1"}, asset.AssetTypeNetwork, "firewall", nil},
		{ctis.Asset{Type: ctis.AssetTypeDatabase, Value: "orders", Properties: map[string]any{"sub_type": "mongodb"}}, asset.AssetTypeDatabase, "document",
			func(t *testing.T, a *asset.Asset) {
				if a.Properties()["engine"] != "mongodb" {
					t.Errorf("engine = %v", a.Properties()["engine"])
				}
				if _, ok := a.Properties()["sub_type"]; ok {
					t.Error("sub_type kept as a property")
				}
			}},
		{ctis.Asset{Type: ctis.AssetTypeNetwork, Value: "lan-1", Properties: map[string]any{"sub_type": "lan"}}, asset.AssetTypeNetwork, "",
			func(t *testing.T, a *asset.Asset) {
				if a.Properties()[asset.PropKeyNativeSubType] != "lan" {
					t.Errorf("native sub-type not kept: %v", a.Properties())
				}
			}},
		{ctis.Asset{Type: ctis.AssetTypeKubernetes, Value: "shop/web", Properties: map[string]any{"kind": "deployment"}}, asset.AssetTypeKubernetes, "workload", nil},
	}
	tenant := shared.NewID()
	for _, c := range cases {
		in := c.in
		a, err := p.createAssetFromCTIS(tenant, &in, nil)
		if err != nil {
			t.Fatalf("%s: %v", c.in.Value, err)
		}
		if a.Type() != c.wantType || a.SubType() != c.wantSub {
			t.Errorf("%s stored as (%s, %q), want (%s, %q)", c.in.Value, a.Type(), a.SubType(), c.wantType, c.wantSub)
		}
		if c.check != nil {
			c.check(t, a)
		}
	}
}
