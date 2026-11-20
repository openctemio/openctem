package scan

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/server/internal/app/actscope"
	"github.com/openctemio/openctem/server/internal/app/scope"
	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// holdEnforcer lets every actor act on every asset (data scope is not under test).
type holdEnforcer struct{}

func (holdEnforcer) CanActOnAssets(context.Context, shared.ID, *shared.ID, []shared.ID) (func(shared.ID) bool, bool, error) {
	return func(shared.ID) bool { return true }, true, nil
}
func (holdEnforcer) HasActor(context.Context) bool { return true }

type holdNames struct{}

func (holdNames) GetByNames(context.Context, shared.ID, []string) (map[string]*asset.Asset, error) {
	return map[string]*asset.Asset{}, nil
}

type holdRoots struct{}

func (holdRoots) VerifiedDomainNames(context.Context, shared.ID) ([]string, error) { return nil, nil }
func (holdRoots) RootDomainNames(context.Context, shared.ID) ([]string, error)     { return nil, nil }

// A scope entry on a provider's shared address is held by default: the real
// dispatch gate (ResolveDispatchTargets with the real scope service and the
// act-scope checker, hold on as nothing turned it off) refuses it with the
// provider_address code, while an ordinary entry still passes.
func TestResolveDispatchTargets_HeldProviderEntryIsRefused(t *testing.T) {
	var shared365 string
	for _, p := range edgeaddr.Default().SharedFrontEndPrefixes() {
		if !p.Addr().Is4() {
			continue
		}
		a := p.Addr().Next().String()
		if r, ok := edgeaddr.Default().SharedFrontEnd(a); ok && r.Provider == "Microsoft 365" {
			shared365 = a
			break
		}
	}
	if shared365 == "" {
		t.Fatal("no Microsoft 365 address in the dataset")
	}
	tenant := shared.NewID()
	const ordinary = "203.0.113.9"
	targets := map[shared.ID][]*scopedom.Target{tenant: {
		scopeEntry(t, tenant, scopedom.TargetTypeIPAddress, shared365),
		scopeEntry(t, tenant, scopedom.TargetTypeIPAddress, ordinary),
	}}
	sc := scope.NewService(&tenantTargetRepo{byTenant: targets}, &tenantExclusionRepo{}, nil, logger.NewNop())
	svc := &Service{
		scopeExclusions: sc,
		attributionGate: &stubGate{},
		actScope:        actscope.New(holdEnforcer{}, holdNames{}, sc, holdRoots{}),
		logger:          logger.NewNop(),
	}
	user := shared.NewID()
	got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{
		TenantID: tenant, Targets: []string{shared365, ordinary},
		ActScope: true, FallbackUser: &user, SkipZoneRouting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Allowed) != 1 || got.Allowed[0] != ordinary {
		t.Fatalf("allowed = %v, want only %s", got.Allowed, ordinary)
	}
	if len(got.Refused) != 1 || got.Refused[0].Target != shared365 || got.Refused[0].Code != scopedom.RefusalProviderAddress {
		t.Fatalf("refused = %+v, want %s with the provider_address code", got.Refused, shared365)
	}
}
