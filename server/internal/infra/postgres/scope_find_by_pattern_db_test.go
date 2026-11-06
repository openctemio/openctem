package postgres

// FindByPattern names the tenant's own existing entry or exclusion with its
// effective status (an active row past its expiry reads as expired), never
// another tenant's; TenantsWithPending lists the tenants with pending rows.

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scope"
)

func TestScopeFindByPattern_DB(t *testing.T) {
	db := openScopeApproversDB(t)
	ctx := context.Background()
	tenant := newApproverSeed(t, db).tenant
	other := newApproverSeed(t, db).tenant
	targets := NewScopeTargetRepository(&DB{DB: db})
	exclusions := NewScopeExclusionRepository(&DB{DB: db})

	pending, err := scope.NewEntry(tenant, scope.TargetTypeDomain, "*.dup.example", "", "", scope.EntryOptions{ApprovalsRequired: 1})
	if err != nil || !pending.IsPending() {
		t.Fatalf("pending entry: %v", err)
	}
	past := time.Now().Add(-48 * time.Hour)
	end := past.Add(time.Hour)
	lapsed, err := scope.NewEntry(tenant, scope.TargetTypeDomain, "old.dup.example", "", "", scope.EntryOptions{Reason: "r", ExpiresAt: &end, Now: past})
	if err != nil {
		t.Fatal(err)
	}
	for _, tg := range []*scope.Target{pending, lapsed} {
		if err := targets.Create(ctx, tg); err != nil {
			t.Fatal(err)
		}
	}
	got, err := targets.FindByPattern(ctx, tenant, scope.TargetTypeDomain, "*.dup.example")
	if err != nil || got == nil || got.ID != pending.ID() || got.Status != scope.StatusPending {
		t.Fatalf("pending: %+v %v", got, err)
	}
	if got, _ := targets.FindByPattern(ctx, tenant, scope.TargetTypeDomain, "old.dup.example"); got == nil || got.Status != scope.StatusExpired {
		t.Fatalf("lapsed: %+v, want expired", got)
	}
	if got, err := targets.FindByPattern(ctx, other, scope.TargetTypeDomain, "*.dup.example"); err != nil || got != nil {
		t.Fatalf("another tenant sees the entry: %+v %v", got, err)
	}
	if got, err := targets.FindByPattern(ctx, tenant, scope.TargetTypeDomain, "none.dup.example"); err != nil || got != nil {
		t.Fatalf("missing: %+v %v", got, err)
	}

	x, err := scope.NewExclusion(tenant, scope.ExclusionTypeDomain, "prod.dup.example", "prod", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := exclusions.Create(ctx, x); err != nil {
		t.Fatal(err)
	}
	if got, err := exclusions.FindByPattern(ctx, tenant, scope.ExclusionTypeDomain, "prod.dup.example"); err != nil || got == nil || got.ID != x.ID() || got.Status != x.Status() {
		t.Fatalf("exclusion: %+v %v", got, err)
	}
	if got, err := exclusions.FindByPattern(ctx, other, scope.ExclusionTypeDomain, "prod.dup.example"); err != nil || got != nil {
		t.Fatalf("another tenant sees the exclusion: %+v %v", got, err)
	}

	ids, err := targets.TenantsWithPending(ctx)
	if err != nil || !slices.Contains(ids, tenant) || slices.Contains(ids, other) {
		t.Fatalf("tenants with pending: %v %v", ids, err)
	}
}
