package postgres

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/easmseed"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Network seeds against the real schema. Requires DATABASE_URL.
func TestEASMNetworkSeedRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	repo := NewEASMNetworkSeedRepository(&DB{DB: sqlDB})
	tenant := seedTestTenant(ctx, t, sqlDB)
	other := seedTestTenant(ctx, t, sqlDB)
	now := time.Now().UTC()

	asn, err := repo.Create(ctx, tenant, easmseed.KindASN, "AS3333", "main", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Create(ctx, tenant, easmseed.KindASN, "as3333", "", nil); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("duplicate (case-insensitive): %v", err)
	}
	org, err := repo.Create(ctx, tenant, easmseed.KindOrgName, "Examplecorp", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	// The same value in another tenant is independent.
	foreign, err := repo.Create(ctx, other, easmseed.KindASN, "AS3333", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	// Expansion: cooldown claim, then stored data.
	if ok, err := repo.ClaimExpansion(ctx, tenant, asn.ID, now, time.Minute); err != nil || !ok {
		t.Fatalf("first claim: %v %v", ok, err)
	}
	if ok, _ := repo.ClaimExpansion(ctx, tenant, asn.ID, now.Add(time.Second), time.Minute); ok {
		t.Fatal("claim inside the cooldown")
	}
	if ok, _ := repo.ClaimExpansion(ctx, other, asn.ID, now.Add(time.Hour), time.Minute); ok {
		t.Fatal("another tenant claimed this tenant's seed")
	}
	if err := repo.SaveExpansion(ctx, tenant, asn.ID, "RIPE-NCC-AS", []string{"193.0.10.0/23"}, nil, ""); err != nil {
		t.Fatal(err)
	}
	if err := repo.SaveExpansion(ctx, tenant, org.ID, "", nil, []easmseed.ASNSuggestion{{ASN: "AS1", Description: "Examplecorp"}}, ""); err != nil {
		t.Fatal(err)
	}
	// A failed refresh keeps the data and records the error.
	if err := repo.SaveExpansion(ctx, tenant, asn.ID, "", nil, nil, "source down"); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Get(ctx, tenant, asn.ID)
	if err != nil || got.Holder != "RIPE-NCC-AS" || len(got.Prefixes) != 1 || got.ExpandError != "source down" || got.LastExpandedAt == nil {
		t.Fatalf("after expansion: %v %+v", err, got)
	}
	nets, err := repo.Networks(ctx, tenant)
	if err != nil || !nets.ASNs["AS3333"] || len(nets.OrgNames) != 1 || nets.Prefixes[0] != "193.0.10.0/23" {
		t.Fatalf("networks: %v %+v", err, nets)
	}

	// Tenant isolation.
	if _, err := repo.Get(ctx, tenant, foreign.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant get: %v", err)
	}
	if err := repo.Delete(ctx, tenant, foreign.ID); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	if list, _ := repo.List(ctx, other); len(list) != 1 {
		t.Fatal("other tenant's list changed")
	}

	due, err := repo.DueForExpansion(ctx, now.Add(time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, r := range due {
		found[r.ID] = true
	}
	if !found[foreign.ID] || !found[asn.ID] {
		t.Fatalf("due: %+v", due)
	}

	// The cap holds.
	for i := 2; i < easmseed.MaxSeedsPerTenant; i++ {
		if _, err := repo.Create(ctx, tenant, easmseed.KindASN, "AS"+strconv.Itoa(100000+i), "", nil); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	if _, err := repo.Create(ctx, tenant, easmseed.KindASN, "AS7", "", nil); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("over the cap: %v", err)
	}
	if err := repo.Delete(ctx, tenant, org.ID); err != nil {
		t.Fatal(err)
	}
}
