package unit

// A person confirming assets also puts them in scope (RFC-054 §14, R3):
// exact entries through the bulk path, only in Off and On and while the
// setting is on; names an entry already covers are left alone; without a
// recent re-authentication nothing is added and the pending entries are
// returned; repositories and private addresses get no entry; another
// tenant's asset ids add nothing.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// assetsByTenant is an asset repository that answers GetByIDs per tenant.
type assetsByTenant struct {
	*mockAssetRepo
	by map[shared.ID]map[string]*asset.Asset
}

func (a *assetsByTenant) GetByIDs(_ context.Context, tid shared.ID, ids []shared.ID) (map[string]*asset.Asset, error) {
	out := map[string]*asset.Asset{}
	for _, id := range ids {
		if x, ok := a.by[tid][id.String()]; ok {
			out[id.String()] = x
		}
	}
	return out, nil
}

func (a *assetsByTenant) add(t *testing.T, tid shared.ID, name string, typ asset.AssetType) string {
	t.Helper()
	x, err := asset.NewAsset(name, typ, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	if a.by[tid] == nil {
		a.by[tid] = map[string]*asset.Asset{}
	}
	a.by[tid][x.ID().String()] = x
	return x.ID().String()
}

func confirmService(t *testing.T, mode scangov.Mode, st tenant.ScopeSettings) (*scope.Service, *mockTargetRepo, *assetsByTenant, *noticeLog) {
	t.Helper()
	tr := newMockTargetRepo()
	ar := &assetsByTenant{mockAssetRepo: newMockAssetRepo(), by: map[shared.ID]map[string]*asset.Asset{}}
	svc := scope.NewService(tr, newMockExclusionRepo(), ar, logger.NewNop())
	svc.SetStepUpGate(passGate{})
	notes := &noticeLog{}
	svc.SetEntryPolicy(fixedSettings{st}, adminDir{2}, notes)
	svc.SetGovernance(fixedMode{mode})
	return svc, tr, ar, notes
}

func TestScopeConfirmAdds_ExactEntriesForNetworkAssets(t *testing.T) {
	ctx := context.Background()
	svc, tr, ar, _ := confirmService(t, scangov.ModeOff, tenant.ScopeSettings{})
	tid := shared.NewID()
	if _, err := create(svc, tid, member, "*.covered.example", nil); err != nil {
		t.Fatal(err)
	}
	ids := []string{
		ar.add(t, tid, "shop.example.com", asset.AssetTypeDomain),
		ar.add(t, tid, "203.0.113.9", asset.AssetTypeIPAddress),
		ar.add(t, tid, "api.covered.example", asset.AssetTypeDomain), // already covered
		ar.add(t, tid, "10.0.0.5", asset.AssetTypeIPAddress),         // private: zones
		ar.add(t, tid, "github.com/acme/web", asset.AssetTypeRepository),
		ar.add(t, tid, "db01.example.com", asset.AssetTypeHost), // hosts are not judged by entries
	}
	got, err := svc.CoverConfirmedAssets(ctx, tid.String(), member, ids)
	if err != nil || got == nil {
		t.Fatalf("cover: %+v %v", got, err)
	}
	if got.Added != 2 || got.Covered != 1 || got.Refused != 0 || got.StepUpRequired {
		t.Fatalf("coverage %+v, want 2 added, 1 covered", got)
	}
	var patterns []string
	for _, x := range tr.targets {
		if x.TenantID() == tid {
			patterns = append(patterns, x.Pattern())
			if x.Pattern() != "*.covered.example" && (x.Origin() != scopedom.OriginManual || !x.IsActive()) {
				t.Fatalf("%s: origin %s active %v, want manual and in effect", x.Pattern(), x.Origin(), x.IsActive())
			}
		}
	}
	if len(patterns) != 3 {
		t.Fatalf("entries %v, want the wildcard plus shop.example.com and 203.0.113.9", patterns)
	}
}

func TestScopeConfirmAdds_NotInStrictNorWhenOff(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		mode scangov.Mode
		st   tenant.ScopeSettings
	}{
		"strict":       {scangov.ModeStrict, tenant.ScopeSettings{}},
		"unknown mode": {scangov.Mode(""), tenant.ScopeSettings{}},
		"setting off":  {scangov.ModeOn, tenant.ScopeSettings{ConfirmAddsDisabled: true}},
	} {
		t.Run(name, func(t *testing.T) {
			svc, tr, ar, _ := confirmService(t, c.mode, c.st)
			tid := shared.NewID()
			id := ar.add(t, tid, "shop.example.com", asset.AssetTypeDomain)
			got, err := svc.CoverConfirmedAssets(ctx, tid.String(), approverA, []string{id})
			if err != nil || got != nil || countTenantTargets(t, tr, tid) != 0 {
				t.Fatalf("got %+v %v, %d entries; want nothing", got, err, countTenantTargets(t, tr, tid))
			}
		})
	}
}

func TestScopeConfirmAdds_StepUpReturnsPending(t *testing.T) {
	svc, tr, ar, notes := confirmService(t, scangov.ModeOff, tenant.ScopeSettings{})
	svc.SetStepUpGate(staleGate{})
	tid := shared.NewID()
	id := ar.add(t, tid, "shop.example.com", asset.AssetTypeDomain)
	got, err := svc.CoverConfirmedAssets(context.Background(), tid.String(), member, []string{id})
	if err != nil || got == nil || !got.StepUpRequired || len(got.Pending) != 1 || got.Pending[0].Pattern != "shop.example.com" {
		t.Fatalf("got %+v %v, want step-up with the pending entry", got, err)
	}
	if countTenantTargets(t, tr, tid) != 0 || len(notes.titles) != 0 {
		t.Fatal("an entry or a notice was written without step-up")
	}
}

func TestScopeConfirmAdds_OtherTenantAssetsAddNothing(t *testing.T) {
	svc, tr, ar, _ := confirmService(t, scangov.ModeOff, tenant.ScopeSettings{})
	org, other := shared.NewID(), shared.NewID()
	id := ar.add(t, other, "victim.example.com", asset.AssetTypeDomain)
	got, err := svc.CoverConfirmedAssets(context.Background(), org.String(), member, []string{id})
	if err != nil || got != nil || countTenantTargets(t, tr, org) != 0 || countTenantTargets(t, tr, other) != 0 {
		t.Fatalf("another tenant's asset: %+v %v", got, err)
	}
}

// A system path (no person) never widens through this rule.
func TestScopeConfirmAdds_SystemActorNoop(t *testing.T) {
	svc, tr, ar, _ := confirmService(t, scangov.ModeOff, tenant.ScopeSettings{})
	tid := shared.NewID()
	id := ar.add(t, tid, "shop.example.com", asset.AssetTypeDomain)
	got, err := svc.CoverConfirmedAssets(context.Background(), tid.String(), scope.Actor{}, []string{id})
	if err != nil || got != nil || countTenantTargets(t, tr, tid) != 0 {
		t.Fatalf("system actor: %+v %v", got, err)
	}
}
