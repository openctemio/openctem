package integration

// Scope entries on a real database (RFC-054 §5): expiry, approvals, the
// in-effect read and the sweep, tenant-scoped.

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
)

func TestScopeEntriesRepository(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	repo := postgres.NewScopeTargetRepository(&postgres.DB{DB: db})

	soon := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Microsecond)
	pending, err := scopedom.NewEntry(tenantA, scopedom.TargetTypeDomain, "*.pending-a.example", "", "admin-a",
		scopedom.EntryOptions{Reason: "M&A", ExpiresAt: &soon, MaxTier: scopedom.TierActive, ApprovalsRequired: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, pending); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetByID(ctx, tenantA, pending.ID())
	if err != nil {
		t.Fatal(err)
	}
	if got.Status() != scopedom.StatusPending || got.Reason() != "M&A" || got.ApprovalsRequired() != 2 ||
		got.ExpiresAt() == nil || !got.ExpiresAt().Equal(soon) || got.MaxTier() != scopedom.TierActive {
		t.Fatalf("round trip: %+v", got)
	}
	if active, _ := repo.ListActive(ctx, tenantA); len(active) != 0 {
		t.Fatal("a pending entry is listed as active")
	}

	// Two approvals, persisted; the second puts it into effect.
	if eff, err := got.Approve("admin-b", time.Now()); err != nil || eff {
		t.Fatalf("first approval: %v %v", eff, err)
	}
	if err := repo.Update(ctx, got); err != nil {
		t.Fatal(err)
	}
	again, _ := repo.GetByID(ctx, tenantA, pending.ID())
	if len(again.Approvals()) != 1 || again.Approvals()[0].UserID != "admin-b" {
		t.Fatalf("approvals not persisted: %+v", again.Approvals())
	}
	if eff, err := again.Approve("admin-c", time.Now()); err != nil || !eff {
		t.Fatalf("second approval: %v %v", eff, err)
	}
	if err := repo.Update(ctx, again); err != nil {
		t.Fatal(err)
	}
	if active, _ := repo.ListActive(ctx, tenantA); len(active) != 1 {
		t.Fatalf("approved entry not active: %d", len(active))
	}
	// Tenant B sees nothing of it.
	if _, err := repo.GetByID(ctx, tenantB, pending.ID()); err == nil {
		t.Fatal("tenant B read tenant A's entry")
	}
	if active, _ := repo.ListActive(ctx, tenantB); len(active) != 0 {
		t.Fatal("tenant B lists tenant A's entry")
	}
	// An approval row cannot point at another tenant's entry.
	if _, err := db.ExecContext(ctx, `INSERT INTO scope_target_approvals (tenant_id, target_id, approver_id) VALUES ($1, $2, 'x')`,
		tenantB.String(), pending.ID().String()); err == nil {
		t.Fatal("an approval row crossed tenants")
	}

	// Past its expiry it stops authorizing at once, then the sweep marks it.
	if _, err := db.ExecContext(ctx, `UPDATE scope_targets SET expires_at = now() - interval '1 minute' WHERE id = $1`, pending.ID().String()); err != nil {
		t.Fatal(err)
	}
	if active, _ := repo.ListActive(ctx, tenantA); len(active) != 0 {
		t.Fatal("an expired entry is still listed as active")
	}
	if n, err := repo.ExpireOld(ctx); err != nil || n < 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	swept, _ := repo.GetByID(ctx, tenantA, pending.ID())
	if swept.Status() != scopedom.StatusExpired {
		t.Fatalf("after the sweep: %s", swept.Status())
	}

	// A permanent entry and a plain target keep working; deleting an entry
	// removes its approvals (cascade).
	plain, _ := scopedom.NewTarget(tenantA, scopedom.TargetTypeDomain, "plain-a.example", "", "")
	if err := repo.Create(ctx, plain); err != nil {
		t.Fatal(err)
	}
	if active, _ := repo.ListActive(ctx, tenantA); len(active) != 1 || active[0].ExpiresAt() != nil {
		t.Fatalf("permanent entry: %+v", active)
	}
	if err := repo.Delete(ctx, tenantA, pending.ID()); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = db.QueryRowContext(ctx, `SELECT count(*) FROM scope_target_approvals WHERE target_id = $1`, pending.ID().String()).Scan(&n)
	if n != 0 {
		t.Fatalf("approvals left after delete: %d", n)
	}
}
