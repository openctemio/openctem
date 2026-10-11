package unit

// A connector's synced inventory is in scope (RFC-054 §14.8): the exact
// entries of the synced names, addresses and hosts are added through the
// bulk path as a system decision with one notice, unless the connector's
// switch is off; nothing in Strict, for another tenant's integration, or for
// what an entry already covers; the signer still refuses per item.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type fakeConnectors map[shared.ID]*integration.Integration

func (f fakeConnectors) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*integration.Integration, error) {
	if i, ok := f[id]; ok && i.TenantID() == tenantID {
		return i, nil
	}
	return nil, integration.ErrIntegrationNotFound
}

func connector(tenantID shared.ID, cfg map[string]any) *integration.Integration {
	i := integration.NewIntegration(shared.NewID(), tenantID, "Tenable.sc prod", integration.CategorySecurity, "tenable_sc", "api_key")
	if cfg != nil {
		i.SetConfig(cfg)
	}
	return i
}

func ids(t *testing.T, ar *assetsByTenant, tid shared.ID, specs map[string]asset.AssetType) []shared.ID {
	t.Helper()
	out := make([]shared.ID, 0, len(specs))
	for name, typ := range specs {
		id, _ := shared.IDFromString(ar.add(t, tid, name, typ))
		out = append(out, id)
	}
	return out
}

func TestScopeConnectorInventory(t *testing.T) {
	ctx := context.Background()
	svc, tr, ar, notes := confirmService(t, scangov.ModeOff, tenant.ScopeSettings{})
	tid := shared.NewID()
	on, off := connector(tid, nil), connector(tid, map[string]any{scope.ConnectorInventoryInScopeKey: false})
	foreign := connector(shared.NewID(), nil)
	svc.SetConnectorIntegrations(fakeConnectors{on.ID(): on, off.ID(): off, foreign.ID(): foreign})
	if _, err := create(svc, tid, member, "*.covered.example", nil); err != nil {
		t.Fatal(err)
	}
	synced := ids(t, ar, tid, map[string]asset.AssetType{
		"db01.corp.example":   asset.AssetTypeHost,
		"203.0.113.40":        asset.AssetTypeIPAddress,
		"www.covered.example": asset.AssetTypeDomain,
		"10.1.1.1":            asset.AssetTypeHost,
		"github.com/acme/app": asset.AssetTypeRepository,
	})
	before := len(notes.titles)

	got, err := svc.CoverConnectorAssets(ctx, tid, on.ID(), synced)
	if err != nil || got == nil || got.Added != 2 || got.Covered != 1 || got.Refused != 0 {
		t.Fatalf("switch on: %+v %v, want 2 added, 1 covered", got, err)
	}
	var added []*scopedom.Target
	for _, x := range tr.targets {
		if x.TenantID() == tid && x.Origin() == scopedom.OriginImport {
			added = append(added, x)
		}
	}
	if len(added) != 2 || !added[0].IsActive() {
		t.Fatalf("connector entries %d, want 2 in effect", len(added))
	}
	if n := len(notes.titles) - before; n != 2 { // one notice per administrator (2)
		t.Fatalf("notices %d, want one per administrator for the sync", n)
	}

	for name, integ := range map[string]shared.ID{"switch off": off.ID(), "another tenant's connector": foreign.ID(), "unknown": shared.NewID()} {
		more := ids(t, ar, tid, map[string]asset.AssetType{"new-" + shared.NewID().String()[:8] + ".corp.example": asset.AssetTypeHost})
		if got, err := svc.CoverConnectorAssets(ctx, tid, integ, more); err != nil || got != nil {
			t.Fatalf("%s: %+v %v, want nothing", name, got, err)
		}
	}

	svc.SetGovernance(fixedMode{scangov.ModeStrict})
	more := ids(t, ar, tid, map[string]asset.AssetType{"strict.corp.example": asset.AssetTypeHost})
	if got, err := svc.CoverConnectorAssets(ctx, tid, on.ID(), more); err != nil || got != nil {
		t.Fatalf("strict: %+v %v, want nothing", got, err)
	}
}
