package proxypool

import (
	"context"
	"errors"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	pooldom "github.com/openctemio/openctem/api/pkg/domain/proxypool"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeRepo is an in-memory, tenant-scoped repository for the methods the
// enabled-needs-a-proxy rule touches.
type fakeRepo struct {
	pooldom.Repository // unimplemented methods panic: the tests never call them
	pools              map[string]*pooldom.Pool
}

func newFakeRepo() *fakeRepo { return &fakeRepo{pools: map[string]*pooldom.Pool{}} }

func key(tenant, id shared.ID) string { return tenant.String() + "/" + id.String() }

func (r *fakeRepo) CountPools(context.Context, shared.ID) (int, error) { return len(r.pools), nil }
func (r *fakeRepo) CreatePool(_ context.Context, p *pooldom.Pool) error {
	cp := *p
	cp.Endpoints = []*pooldom.Endpoint{}
	r.pools[key(p.TenantID, p.ID)] = &cp
	return nil
}
func (r *fakeRepo) GetPool(_ context.Context, tenant, id shared.ID) (*pooldom.Pool, error) {
	p, ok := r.pools[key(tenant, id)]
	if !ok {
		return nil, pooldom.ErrPoolNotFound
	}
	cp := *p
	return &cp, nil
}
func (r *fakeRepo) UpdatePool(_ context.Context, p *pooldom.Pool) error {
	cp := *p
	r.pools[key(p.TenantID, p.ID)] = &cp
	return nil
}
func (r *fakeRepo) ReplaceEndpoints(_ context.Context, p *pooldom.Pool, eps []*pooldom.Endpoint) error {
	cp := *p
	cp.Endpoints = eps
	r.pools[key(p.TenantID, p.ID)] = &cp
	return nil
}

func newTestService() (*Service, *fakeRepo, string) {
	repo := newFakeRepo()
	return NewService(repo, nil, nil, logger.NewNop()), repo, shared.NewID().String()
}

func b(v bool) *bool     { return &v }
func s(v string) *string { return &v }

const oneProxy = "http://proxy1.example.net:8080\n"

func TestCreatePoolRefusesEnabledWithoutProxy(t *testing.T) {
	svc, repo, tenant := newTestService()
	ctx := context.Background()
	actx := auditapp.AuditContext{TenantID: tenant}

	for name, in := range map[string]CreatePoolInput{
		"enabled by default, no list": {TenantID: tenant, Name: "a"},
		"enabled, empty list":         {TenantID: tenant, Name: "b", Enabled: b(true), EndpointsText: s("# nothing\n")},
	} {
		if _, err := svc.CreatePool(ctx, in, actx); !errors.Is(err, pooldom.ErrEnabledNeedsEndpoint) {
			t.Fatalf("%s: want ErrEnabledNeedsEndpoint, got %v", name, err)
		}
	}
	if len(repo.pools) != 0 {
		t.Fatalf("a refused pool was stored")
	}
	// Disabled without a list, and enabled with one, are fine.
	if _, err := svc.CreatePool(ctx, CreatePoolInput{TenantID: tenant, Name: "c", Enabled: b(false)}, actx); err != nil {
		t.Fatalf("disabled empty pool: %v", err)
	}
	if _, err := svc.CreatePool(ctx, CreatePoolInput{TenantID: tenant, Name: "d", EndpointsText: s(oneProxy)}, actx); err != nil {
		t.Fatalf("enabled pool with a proxy: %v", err)
	}
}

func TestUpdatePoolRefusesEnablingAnEmptyPool(t *testing.T) {
	svc, _, tenant := newTestService()
	ctx := context.Background()
	actx := auditapp.AuditContext{TenantID: tenant}
	p, err := svc.CreatePool(ctx, CreatePoolInput{TenantID: tenant, Name: "p", Enabled: b(false)}, actx)
	if err != nil {
		t.Fatal(err)
	}
	in := UpdatePoolInput{TenantID: tenant, PoolID: p.ID.String(), Enabled: b(true)}
	if _, err := svc.UpdatePool(ctx, in, actx); !errors.Is(err, pooldom.ErrEnabledNeedsEndpoint) {
		t.Fatalf("enable empty pool: got %v", err)
	}
	if _, err := svc.ReplaceEndpoints(ctx, tenant, p.ID.String(), oneProxy, actx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdatePool(ctx, in, actx); err != nil {
		t.Fatalf("enable pool with a proxy: %v", err)
	}
}

func TestReplaceEndpointsRefusesEmptyingAnEnabledPool(t *testing.T) {
	svc, repo, tenant := newTestService()
	ctx := context.Background()
	actx := auditapp.AuditContext{TenantID: tenant}
	p, err := svc.CreatePool(ctx, CreatePoolInput{TenantID: tenant, Name: "p", EndpointsText: s(oneProxy)}, actx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReplaceEndpoints(ctx, tenant, p.ID.String(), "", actx); !errors.Is(err, pooldom.ErrEnabledNeedsEndpoint) {
		t.Fatalf("empty an enabled pool: got %v", err)
	}
	if got := repo.pools[key(p.TenantID, p.ID)]; len(got.Endpoints) != 1 {
		t.Fatalf("the refused change altered the pool: %d endpoints", len(got.Endpoints))
	}
	// Disable first, then the list may be emptied.
	if _, err := svc.UpdatePool(ctx, UpdatePoolInput{TenantID: tenant, PoolID: p.ID.String(), Enabled: b(false)}, actx); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReplaceEndpoints(ctx, tenant, p.ID.String(), "", actx); err != nil {
		t.Fatalf("empty a disabled pool: %v", err)
	}
}

func TestPoolRulesStayInsideTheTenant(t *testing.T) {
	svc, _, tenant := newTestService()
	ctx := context.Background()
	p, err := svc.CreatePool(ctx, CreatePoolInput{TenantID: tenant, Name: "p", EndpointsText: s(oneProxy)},
		auditapp.AuditContext{TenantID: tenant})
	if err != nil {
		t.Fatal(err)
	}
	other := shared.NewID().String()
	_, err = svc.ReplaceEndpoints(ctx, other, p.ID.String(), "", auditapp.AuditContext{TenantID: other})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant must see not found, got %v", err)
	}
}
