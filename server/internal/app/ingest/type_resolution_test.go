package ingest

import (
	"testing"

	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// RFC-042 §6.3.8: ingest stores only core types; machine input is resolved
// leniently (an unknown sub-type is kept, never refused).
func TestResolveCTISAssetType(t *testing.T) {
	ident := func(k ctis.IdentityKind) ctis.Asset {
		return ctis.Asset{Type: ctis.AssetTypeIdentity, Technical: &ctis.AssetTechnical{Identity: &ctis.IdentityTechnical{Kind: k}}}
	}
	cases := []struct {
		name      string
		in        ctis.Asset
		wantType  asset.AssetType
		wantSub   string
		wantNativ string
	}{
		{"web origin", ctis.Asset{Type: ctis.AssetTypeWebOrigin}, asset.AssetTypeService, "http", ""},
		{"kubernetes cluster", ctis.Asset{Type: ctis.AssetTypeKubernetesCluster}, asset.AssetTypeKubernetes, "cluster", ""},
		{"kubernetes workload", ctis.Asset{Type: ctis.AssetTypeKubernetesWorkload}, asset.AssetTypeKubernetes, "workload", ""},
		// properties carry no meaning: a kind or sub_type there moves nothing.
		{"kind property ignored", ctis.Asset{Type: ctis.AssetTypeKubernetesCluster, Properties: map[string]any{"kind": "Namespace"}}, asset.AssetTypeKubernetes, "cluster", ""},
		{"sub_type property ignored", ctis.Asset{Type: ctis.AssetTypeDatabase, Properties: map[string]any{"sub_type": "postgresql"}}, asset.AssetTypeDatabase, "", ""},
		{"ip range", ctis.Asset{Type: ctis.AssetTypeIPRange, Properties: map[string]any{"sub_type": "lan"}}, asset.AssetTypeNetwork, "", ""},
		{"unknown type", ctis.Asset{Type: "web3_wallet"}, asset.AssetTypeUnclassified, "", ""},
		{"host", ctis.Asset{Type: ctis.AssetTypeHost}, asset.AssetTypeHost, "", ""},
		{"identity user", ident(ctis.IdentityUser), asset.AssetTypeIdentity, "iam_user", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := resolveCTISAssetType(&c.in)
			if got.stored.Type != c.wantType || got.stored.SubType != c.wantSub || got.stored.NativeSubType != c.wantNativ {
				t.Errorf("stored = %+v, want (%s, %q, native %q)", got.stored, c.wantType, c.wantSub, c.wantNativ)
			}
			if got.normType != c.wantType || got.normSubType != c.wantSub {
				t.Errorf("normalization key = (%s, %q), want (%s, %q)", got.normType, got.normSubType, c.wantType, c.wantSub)
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
		// properties.sub_type / properties.kind carry no meaning in CTIS 2.0.
		{ctis.Asset{Type: ctis.AssetTypeDatabase, Value: "orders", Properties: map[string]any{"sub_type": "mongodb"}}, asset.AssetTypeDatabase, "",
			func(t *testing.T, a *asset.Asset) {
				if a.SubType() != "" {
					t.Errorf("sub_type property moved the sub-type to %q", a.SubType())
				}
			}},
		{ctis.Asset{Type: ctis.AssetTypeIPRange, Value: "10.0.0.0/24"}, asset.AssetTypeNetwork, "", nil},
		{ctis.Asset{Type: ctis.AssetTypeKubernetesWorkload, Value: "shop/web"}, asset.AssetTypeKubernetes, "workload", nil},
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
