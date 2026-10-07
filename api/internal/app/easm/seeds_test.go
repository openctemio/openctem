package easm

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type memSeeds struct {
	byTenant map[shared.ID][]easmseed.Seed
	count    int // overrides the count when > 0
}

func (m *memSeeds) ListSeeds(_ context.Context, tid shared.ID) ([]easmseed.Seed, error) {
	return m.byTenant[tid], nil
}

func (m *memSeeds) CountSeeds(_ context.Context, tid shared.ID) (int, error) {
	if m.count > 0 {
		return m.count, nil
	}
	return len(m.byTenant[tid]), nil
}

func (m *memSeeds) CreateSeed(_ context.Context, s easmseed.Seed) error {
	for _, x := range m.byTenant[s.TenantID] {
		if x.Kind == s.Kind && x.Value == s.Value {
			return shared.ErrConflict
		}
	}
	m.byTenant[s.TenantID] = append(m.byTenant[s.TenantID], s)
	return nil
}

func (m *memSeeds) UpdateSeed(_ context.Context, tid, id shared.ID, label string, d bool) (*easmseed.Seed, error) {
	for i, x := range m.byTenant[tid] {
		if x.ID == id {
			m.byTenant[tid][i].Label, m.byTenant[tid][i].DiscoveryEnabled = label, d
			return &m.byTenant[tid][i], nil
		}
	}
	return nil, shared.ErrNotFound
}

func (m *memSeeds) DeleteSeed(_ context.Context, tid, id shared.ID) (*easmseed.Seed, error) {
	for i, x := range m.byTenant[tid] {
		if x.ID == id {
			m.byTenant[tid] = append(m.byTenant[tid][:i], m.byTenant[tid][i+1:]...)
			return &x, nil
		}
	}
	return nil, shared.ErrNotFound
}

type verifiedFor map[shared.ID][]string

func (v verifiedFor) VerifiedDomainNames(_ context.Context, tid shared.ID) ([]string, error) {
	return v[tid], nil
}

// preload stores a seed as an existing row (new seeds are scope entries,
// tests/unit/easm_seed_widening_test.go).
func preload(store *memSeeds, tenant shared.ID, value string) shared.ID {
	id := shared.NewID()
	store.byTenant[tenant] = append(store.byTenant[tenant], easmseed.Seed{
		ID: id, TenantID: tenant, Kind: easmseed.KindRootDomain, Value: value, DiscoveryEnabled: true,
	})
	return id
}

// Verification comes only from the tenant's own verified domains: another
// tenant's verification of the same name never shows; a parent verifies.
func TestSeedService_VerificationIsPerTenant(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	store := &memSeeds{byTenant: map[shared.ID][]easmseed.Seed{}}
	preload(store, a, "eu.acme.com")
	list, err := NewSeedService(store, verifiedFor{b: {"acme.com"}}).List(context.Background(), a)
	if err != nil || len(list) != 1 || list[0].Verification != VerificationNone || list[0].VerifiedBy != "" {
		t.Fatalf("another tenant's verification leaked: %+v %v", list, err)
	}
	list, _ = NewSeedService(store, verifiedFor{a: {"notacme.com"}}).List(context.Background(), a)
	if list[0].Verification != VerificationNone {
		t.Fatalf("look-alike verified the seed: %+v", list)
	}
	list, _ = NewSeedService(store, verifiedFor{a: {"acme.com"}}).List(context.Background(), a)
	if list[0].Verification != VerificationDNSTXT || list[0].VerifiedBy != "acme.com" {
		t.Fatalf("a verified parent did not verify the seed: %+v", list)
	}
}

func TestSeedService_UpdateAndDeleteAreTenantScoped(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	store := &memSeeds{byTenant: map[shared.ID][]easmseed.Seed{}}
	svc := NewSeedService(store, nil)
	id := preload(store, a, "acme.com")
	off := false
	if _, _, err := svc.Update(context.Background(), b, id, nil, &off); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}
	if _, err := svc.Delete(context.Background(), b, id); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	bad := "a\nb"
	if _, _, err := svc.Update(context.Background(), a, id, &bad, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("control characters in label: %v", err)
	}
	got, turnedOn, err := svc.Update(context.Background(), a, id, nil, &off)
	if err != nil || got.DiscoveryEnabled || turnedOn {
		t.Fatalf("update = %+v %v %v", got, turnedOn, err)
	}
}
