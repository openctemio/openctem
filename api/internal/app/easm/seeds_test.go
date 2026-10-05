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

func TestSeedService_CreateValidatesAndAttests(t *testing.T) {
	tenant := shared.NewID()
	store := &memSeeds{byTenant: map[shared.ID][]easmseed.Seed{}}
	svc := NewSeedService(store, verifiedFor{tenant: {"acme.com"}})
	ctx := context.Background()

	if _, err := svc.Create(ctx, tenant, CreateSeedInput{Kind: "root_domain", Value: "eu.acme.com"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("unattested seed accepted: %v", err)
	}
	for _, v := range []string{"com", "shop.azurewebsites.net", "acme.local"} {
		if _, err := svc.Create(ctx, tenant, CreateSeedInput{Kind: "root_domain", Value: v, Attested: true}); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%q accepted", v)
		}
	}
	if _, err := svc.Create(ctx, tenant, CreateSeedInput{Kind: "cidr", Value: "203.0.113.0/24", Attested: true}); !errors.Is(err, shared.ErrValidation) {
		t.Error("a kind with no consumer was accepted")
	}

	actor := shared.NewID()
	v, err := svc.Create(ctx, tenant, CreateSeedInput{Kind: "root_domain", Value: "EU.Acme.com.", Label: "Europe", Attested: true, ActorID: actor.String()})
	if err != nil {
		t.Fatal(err)
	}
	// A verified parent domain verifies the seed; the attester is recorded.
	if v.Value != "eu.acme.com" || v.Verification != VerificationDNSTXT || v.VerifiedBy != "acme.com" ||
		v.AttestedBy != actor.String() || !v.DiscoveryEnabled {
		t.Fatalf("view = %+v", v)
	}
	if _, err := svc.Create(ctx, tenant, CreateSeedInput{Kind: "root_domain", Value: "eu.acme.com", Attested: true}); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}

	store.count = easmseed.MaxPerTenant
	if _, err := svc.Create(ctx, tenant, CreateSeedInput{Kind: "root_domain", Value: "acme.org", Attested: true}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("over the cap: %v", err)
	}
}

// Verification comes only from the tenant's own verified domains: another
// tenant's verification of the same name never shows.
func TestSeedService_VerificationIsPerTenant(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	store := &memSeeds{byTenant: map[shared.ID][]easmseed.Seed{}}
	svc := NewSeedService(store, verifiedFor{b: {"acme.com"}})
	v, err := svc.Create(context.Background(), a, CreateSeedInput{Kind: "root_domain", Value: "acme.com", Attested: true})
	if err != nil {
		t.Fatal(err)
	}
	if v.Verification != VerificationNone || v.VerifiedBy != "" {
		t.Fatalf("another tenant's verification leaked: %+v", v)
	}
	// "notacme.com" verified does not cover "acme.com".
	svc2 := NewSeedService(store, verifiedFor{a: {"notacme.com"}})
	list, _ := svc2.List(context.Background(), a)
	if len(list) != 1 || list[0].Verification != VerificationNone {
		t.Fatalf("look-alike verified the seed: %+v", list)
	}
}

func TestSeedService_UpdateAndDeleteAreTenantScoped(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	store := &memSeeds{byTenant: map[shared.ID][]easmseed.Seed{}}
	svc := NewSeedService(store, nil)
	v, _ := svc.Create(context.Background(), a, CreateSeedInput{Kind: "root_domain", Value: "acme.com", Attested: true})
	id, _ := shared.IDFromString(v.ID)
	off := false
	if _, err := svc.Update(context.Background(), b, id, nil, &off); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}
	if _, err := svc.Delete(context.Background(), b, id); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	bad := "a\nb"
	if _, err := svc.Update(context.Background(), a, id, &bad, nil); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("control characters in label: %v", err)
	}
	got, err := svc.Update(context.Background(), a, id, nil, &off)
	if err != nil || got.DiscoveryEnabled {
		t.Fatalf("update = %+v %v", got, err)
	}
}

// research/22 P0-13 (22c B9): a root domain under one of the tenant's seeds
// is refused; a parent, a look-alike and another tenant's seed are not.
func TestSeedService_RefusesSubdomainOfSeed(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	store := &memSeeds{byTenant: map[shared.ID][]easmseed.Seed{}}
	svc := NewSeedService(store, verifiedFor{})
	ctx := context.Background()
	add := func(tn shared.ID, v string) error {
		_, err := svc.Create(ctx, tn, CreateSeedInput{Kind: "root_domain", Value: v, Attested: true})
		return err
	}
	if err := add(a, "eu.acme.com"); err != nil {
		t.Fatal(err)
	}
	if err := add(a, "www.eu.acme.com"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("subdomain of a seed: %v", err)
	}
	if err := add(a, "acme.com"); err != nil {
		t.Fatalf("parent of a seed refused: %v", err)
	}
	if err := add(a, "neweu.acme.com"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("now under acme.com: %v", err)
	}
	if err := add(a, "notacme.com"); err != nil {
		t.Fatalf("look-alike refused: %v", err)
	}
	if err := add(b, "www.eu.acme.com"); err != nil {
		t.Fatalf("another tenant's seed applied: %v", err)
	}
}
