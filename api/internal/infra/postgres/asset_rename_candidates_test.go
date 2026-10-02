package postgres

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Two rows in one batch cannot both take one name; those are left to the
// insert (which falls back to the per-row path for such a batch), and rows
// with no tenant are never renamed.
func TestRenameCandidates(t *testing.T) {
	tenant := shared.NewID()
	mk := func(name string, tenantID shared.ID) *asset.Asset {
		a, err := asset.NewAsset(name, asset.AssetTypeHost, asset.CriticalityMedium)
		if err != nil {
			t.Fatal(err)
		}
		a.SetTenantID(tenantID)
		return a
	}
	unique := mk("web-01", tenant)
	dupA, dupB := mk("web-02", tenant), mk("web-02", tenant)
	noTenant := mk("web-03", shared.ID{})

	ids, tenants, names := renameCandidates([]*asset.Asset{unique, dupA, dupB, noTenant})
	if len(ids) != 1 || ids[0] != unique.ID().String() || tenants[0] != tenant.String() || names[0] != "web-01" {
		t.Fatalf("got ids=%v tenants=%v names=%v, want only web-01", ids, tenants, names)
	}
}
