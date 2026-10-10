package postgres

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scangov"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The organizations a platform default change reaches (their tier
// ceilings follow it, RFC-073 §7): those without an override, never one
// with its own (tenant_controlled included).
func TestScanPolicy_ListFollowingDefault_DB(t *testing.T) {
	ctx := context.Background()
	db := openScanDB(t)
	follows := seedScanTriggerTenant(ctx, t, db)
	pinned := seedScanTriggerTenant(ctx, t, db)
	controlled := seedScanTriggerTenant(ctx, t, db)
	repo := NewScanPolicyRepository(&DB{DB: db})
	strict, tc := scangov.PolicyStrict, scangov.PolicyTenantControlled
	if err := repo.SetOverride(ctx, pinned, &strict); err != nil {
		t.Fatal(err)
	}
	if err := repo.SetOverride(ctx, controlled, &tc); err != nil {
		t.Fatal(err)
	}
	ids, err := repo.ListFollowingDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[shared.ID]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if !seen[follows] || seen[pinned] || seen[controlled] {
		t.Fatalf("follows %v pinned %v controlled %v", seen[follows], seen[pinned], seen[controlled])
	}
}
