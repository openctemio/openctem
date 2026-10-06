package unit

// RFC-042 §6.3.8 (T1): every write path stores only core types and
// sub-types from the registry's closed lists. Aliases and legacy sub-types
// are input names.

import (
	"context"
	"errors"
	"strings"
	"testing"

	assetapp "github.com/openctemio/openctem/api/internal/app/asset"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestCreateAsset_ResolvesSubTypeInputs(t *testing.T) {
	cases := []struct {
		typ, sub, propSub string
		wantType          asset.AssetType
		wantSub           string
		wantProvider      asset.Provider
		wantAttr          map[string]string
	}{
		{typ: "database", sub: "postgresql", wantType: "database", wantSub: "relational", wantAttr: map[string]string{"engine": "postgresql"}},
		{typ: "cloud_account", propSub: "aws", wantType: "cloud_account", wantProvider: asset.ProviderAWS, wantAttr: map[string]string{"provider": "aws"}},
		{typ: "s3_bucket", wantType: "storage", wantSub: "bucket", wantProvider: asset.ProviderAWS},
		{typ: "network", sub: "subnet", wantType: "network", wantSub: "subnet"},
		{typ: "application", sub: "api", wantType: "application", wantSub: "api"},
		// the request field wins over properties.sub_type
		{typ: "network", sub: "firewall", propSub: "router", wantType: "network", wantSub: "firewall"},
	}
	for _, c := range cases {
		t.Run(c.typ+"/"+c.sub+c.propSub, func(t *testing.T) {
			svc, _ := newTestService()
			in := assetapp.CreateAssetInput{
				TenantID: serviceTenantID.String(), Name: "asset-" + c.typ + c.sub + c.propSub,
				Type: c.typ, SubType: c.sub, Criticality: "medium",
			}
			if c.propSub != "" {
				in.Properties = map[string]any{"sub_type": c.propSub}
			}
			a, err := svc.CreateAsset(context.Background(), in)
			if err != nil {
				t.Fatalf("CreateAsset: %v", err)
			}
			if a.Type() != c.wantType || a.SubType() != c.wantSub {
				t.Errorf("stored (%s, %q), want (%s, %q)", a.Type(), a.SubType(), c.wantType, c.wantSub)
			}
			if c.wantProvider != "" && a.Provider() != c.wantProvider {
				t.Errorf("provider = %q, want %q", a.Provider(), c.wantProvider)
			}
			for k, v := range c.wantAttr {
				if a.Properties()[k] != v {
					t.Errorf("properties[%s] = %v, want %q", k, a.Properties()[k], v)
				}
			}
			if _, leaked := a.Properties()["__promoted_sub_type"]; leaked {
				t.Error("internal __promoted_sub_type key stored")
			}
		})
	}
}

// Every rejected input is a validation error (HTTP 400), so a caller learns
// the closed list instead of storing free text.
func TestCreateAsset_RejectsUnknownTypesAndSubTypes(t *testing.T) {
	cases := []struct{ typ, sub, propType string }{
		{typ: "network", sub: "lan"},
		{typ: "identity", sub: "credential"},
		{typ: "website", sub: "api"},    // contradicts the alias
		{typ: "server"},                 // a legacy asset_types code, not a registry type
		{typ: "host", propType: "nope"}, // a non-alias properties.type does not change the type ...
	}
	for _, c := range cases {
		svc, repo := newTestService()
		in := assetapp.CreateAssetInput{TenantID: serviceTenantID.String(), Name: "bad-" + c.typ + c.sub, Type: c.typ, SubType: c.sub, Criticality: "low"}
		if c.propType != "" {
			in.Properties = map[string]any{"type": c.propType}
			a, err := svc.CreateAsset(context.Background(), in)
			// ... and is kept as an ordinary property (it used to fail the request).
			if err != nil || a.Type() != asset.AssetTypeHost || a.Properties()["type"] != c.propType {
				t.Errorf("properties.type=%q: %v, %+v", c.propType, err, a)
			}
			continue
		}
		_, err := svc.CreateAsset(context.Background(), in)
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("(%s, %s): err = %v, want a validation error", c.typ, c.sub, err)
		}
		if len(repo.assets) != 0 {
			t.Errorf("(%s, %s): an asset was stored", c.typ, c.sub)
		}
	}
}

// A properties.type alias cannot be used to slip in a sub-type that the
// request field would be refused for.
func TestCreateAsset_PropertiesTypeAliasIsValidatedLikeTheField(t *testing.T) {
	svc, repo := newTestService()
	_, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID: serviceTenantID.String(), Name: "fw-x", Type: "host", Criticality: "low",
		Properties: map[string]any{"type": "firewall", "sub_type": "router"},
	})
	if !errors.Is(err, shared.ErrValidation) || len(repo.assets) != 0 {
		t.Fatalf("contradicting alias + sub_type accepted: %v", err)
	}
	a, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{
		TenantID: serviceTenantID.String(), Name: "fw-y", Type: "host", Criticality: "low",
		Properties: map[string]any{"type": "firewall"},
	})
	if err != nil || a.Type() != asset.AssetTypeNetwork || a.SubType() != "firewall" {
		t.Fatalf("properties.type alias: %v, %+v", err, a)
	}
}

func TestUpdateAsset_SubType(t *testing.T) {
	svc, _ := newTestService()
	tenant := serviceTenantID.String()
	a, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{TenantID: tenant, Name: "orders-db", Type: "database", Criticality: "high"})
	if err != nil {
		t.Fatal(err)
	}
	ptr := func(s string) *string { return &s }

	// a legacy value of the same type is mapped
	got, err := svc.UpdateAsset(context.Background(), a.ID().String(), tenant, assetapp.UpdateAssetInput{SubType: ptr("MySQL")})
	if err != nil || got.SubType() != "relational" || got.Properties()["engine"] != "mysql" {
		t.Fatalf("legacy sub-type: %v, %+v", err, got)
	}
	// a value outside the closed list is refused and changes nothing
	if _, err := svc.UpdateAsset(context.Background(), a.ID().String(), tenant, assetapp.UpdateAssetInput{SubType: ptr("lan")}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unknown sub-type: %v", err)
	}
	// a legacy value that maps to another type cannot change the type
	// (host/kubernetes_cluster is stored as kubernetes/cluster)
	h, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{TenantID: tenant, Name: "node-1", Type: "host", Criticality: "low"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.UpdateAsset(context.Background(), h.ID().String(), tenant, assetapp.UpdateAssetInput{SubType: ptr("kubernetes_cluster")})
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "cannot be changed") || h.Type() != asset.AssetTypeHost {
		t.Fatalf("cross-type sub-type: %v", err)
	}
	// "" clears
	got, err = svc.UpdateAsset(context.Background(), a.ID().String(), tenant, assetapp.UpdateAssetInput{SubType: ptr("")})
	if err != nil || got.SubType() != "" {
		t.Fatalf("clear: %v, %q", err, got.SubType())
	}
}

// PATCH resolves against the caller's tenant only: another tenant's asset id
// is not found, whatever the sub-type.
func TestUpdateAsset_SubType_OtherTenantNotFound(t *testing.T) {
	svc, _ := newTestService()
	a, err := svc.CreateAsset(context.Background(), assetapp.CreateAssetInput{TenantID: serviceTenantID.String(), Name: "net-a", Type: "network", Criticality: "low"})
	if err != nil {
		t.Fatal(err)
	}
	sub := "firewall"
	_, err = svc.UpdateAsset(context.Background(), a.ID().String(), shared.NewID().String(), assetapp.UpdateAssetInput{SubType: &sub})
	if err == nil {
		t.Fatal("updated another tenant's asset")
	}
	if a.SubType() != "" {
		t.Fatal("sub-type changed through another tenant")
	}
}

func TestImportCSV_ResolvesAliasesAndRejectsUnknownSubTypes(t *testing.T) {
	repo := NewMockAssetRepository()
	svc := assetapp.NewAssetImportService(repo, logger.NewNop())
	csv := "name,type,sub_type\n" +
		"https://shop.example.com,website,\n" +
		"orders-db,database,postgresql\n" +
		"edge,network,lan\n" +
		"weird,server,\n"
	res, err := svc.ImportCSVAssets(context.Background(), serviceTenantID.String(), strings.NewReader(csv))
	if err != nil {
		t.Fatal(err)
	}
	if res.AssetsCreated != 2 || len(res.Errors) != 2 {
		t.Fatalf("created %d, errors %v", res.AssetsCreated, res.Errors)
	}
	for _, a := range repo.assets {
		if !a.Type().IsStored() || !asset.IsValidSubType(a.Type(), a.SubType()) {
			t.Errorf("stored (%s, %q)", a.Type(), a.SubType())
		}
		switch a.Name() {
		case "orders-db":
			if a.SubType() != "relational" || a.Properties()["engine"] != "postgresql" {
				t.Errorf("orders-db stored as %q %v", a.SubType(), a.Properties())
			}
		default:
			if a.Type() != asset.AssetTypeApplication || a.SubType() != "website" {
				t.Errorf("%s stored as (%s, %q)", a.Name(), a.Type(), a.SubType())
			}
		}
	}
}

func TestImportKubernetes_StoresKubernetesTypes(t *testing.T) {
	repo := NewMockAssetRepository()
	svc := assetapp.NewAssetImportService(repo, logger.NewNop())
	_, err := svc.ImportKubernetes(context.Background(), serviceTenantID.String(), assetapp.K8sDiscoveryInput{
		ClusterName: "prod",
		Namespaces:  []assetapp.K8sNamespace{{Name: "shop", Workloads: []assetapp.K8sWorkload{{Kind: "Deployment", Name: "web"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, a := range repo.assets {
		if a.Type() != asset.AssetTypeKubernetes {
			t.Errorf("%s stored as %s", a.Name(), a.Type())
		}
		switch a.SubType() {
		case "cluster":
			found++
		case "workload":
			found++
			if a.Properties()["workload_kind"] != "deployment" {
				t.Errorf("workload_kind = %v", a.Properties()["workload_kind"])
			}
		default:
			t.Errorf("%s sub-type %q", a.Name(), a.SubType())
		}
	}
	if found != 2 {
		t.Fatalf("got %d kubernetes assets", found)
	}
}
