package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// EASM seeds against the real schema (migration 000700): tenant isolation on
// every read and write, per-tenant uniqueness (two tenants may seed the same
// domain), and the CT monitor's view (discovery on only). Requires
// DATABASE_URL.
func TestEASMSeedRepository(t *testing.T) {
	db := openSensorDB(t)
	ctx := context.Background()
	repo := NewEASMSeedRepository(&DB{DB: db})
	tenant := seedTestTenant(ctx, t, db)
	other := seedTestTenant(ctx, t, db)

	mk := func(tid shared.ID, value string, discovery bool) easmseed.Seed {
		now := time.Now().UTC()
		return easmseed.Seed{ID: shared.NewID(), TenantID: tid, Kind: easmseed.KindRootDomain, Value: value,
			DiscoveryEnabled: discovery, AttestedAt: now, CreatedAt: now}
	}
	acme := mk(tenant, "acme.com", true)
	if err := repo.CreateSeed(ctx, acme); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateSeed(ctx, mk(tenant, "acme.com", true)); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate seed: %v, want conflict", err)
	}
	// Another tenant may seed the same domain: nothing relates the rows.
	theirs := mk(other, "acme.com", true)
	if err := repo.CreateSeed(ctx, theirs); err != nil {
		t.Fatalf("second tenant's seed: %v", err)
	}
	if err := repo.CreateSeed(ctx, mk(tenant, "old.acme.net", false)); err != nil {
		t.Fatal(err)
	}

	list, err := repo.ListSeeds(ctx, tenant)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %d %v", len(list), err)
	}
	for _, s := range list {
		if s.TenantID != tenant || s.ID == theirs.ID {
			t.Fatal("another tenant's seed listed")
		}
	}
	if n, _ := repo.CountSeeds(ctx, tenant); n != 2 {
		t.Fatalf("count = %d", n)
	}
	roots, err := repo.DiscoveryRootDomains(ctx, tenant)
	if err != nil || len(roots) != 1 || roots[0] != "acme.com" {
		t.Fatalf("discovery roots = %v %v", roots, err)
	}

	// The other tenant cannot change or delete this tenant's seed.
	if _, err := repo.UpdateSeed(ctx, other, acme.ID, "x", false); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant update: %v", err)
	}
	if _, err := repo.DeleteSeed(ctx, other, acme.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	got, err := repo.UpdateSeed(ctx, tenant, acme.ID, "Main", false)
	if err != nil || got.Label != "Main" || got.DiscoveryEnabled {
		t.Fatalf("update = %+v %v", got, err)
	}
	if roots, _ := repo.DiscoveryRootDomains(ctx, tenant); len(roots) != 0 {
		t.Fatalf("a seed with discovery off is still watched: %v", roots)
	}
	if _, err := repo.DeleteSeed(ctx, tenant, acme.ID); err != nil {
		t.Fatal(err)
	}
	if roots, _ := repo.DiscoveryRootDomains(ctx, other); len(roots) != 1 {
		t.Fatal("deleting one tenant's seed touched the other tenant's")
	}

	// Verified domains are read for the tenant only.
	if _, err := db.ExecContext(ctx, `INSERT INTO verified_domains (id, tenant_id, domain, verification_token, status, verified_at)
		VALUES ($1, $2, 'acme.com', 'tok', 'verified', now())`, shared.NewID().String(), other.String()); err != nil {
		t.Fatal(err)
	}
	if names, _ := repo.VerifiedDomainNames(ctx, tenant); len(names) != 0 {
		t.Fatalf("another tenant's verification leaked: %v", names)
	}
	if names, _ := repo.VerifiedDomainNames(ctx, other); len(names) != 1 {
		t.Fatalf("own verification = %v", names)
	}
}
