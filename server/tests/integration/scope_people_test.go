package integration

// People and provenance on scope entries (research/53 §4.6): names come only
// from the tenant's current members; the origin a path records is stored.

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/postgres"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
)

func TestScopeActorNamesAndOrigin(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenantA := seedLifecycleTenant(ctx, t, db)
	tenantB := seedLifecycleTenant(ctx, t, db)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	member, left, other := seedActUser(t, db), seedActUser(t, db), seedActUser(t, db)
	exec(`UPDATE users SET name = 'Nguyen Manh' WHERE id = $1`, member.String())
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role, status) VALUES ($1, $2, 'admin', 'active')`, member.String(), tenantA.String())
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role, status) VALUES ($1, $2, 'member', 'offboarded')`, left.String(), tenantA.String())
	exec(`INSERT INTO tenant_members (user_id, tenant_id, role, status) VALUES ($1, $2, 'admin', 'active')`, other.String(), tenantB.String())

	names, err := postgres.NewScopeActorRepository(&postgres.DB{DB: db}).MemberNames(ctx, tenantA,
		[]string{member.String(), left.String(), other.String(), "not-an-id"})
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[member.String()] != "Nguyen Manh" {
		t.Fatalf("names = %v (only the current member of tenant A)", names)
	}

	// The origin a path records round-trips; old rows read as manual.
	repo := postgres.NewScopeTargetRepository(&postgres.DB{DB: db})
	e, err := scopedom.NewEntry(tenantA, scopedom.TargetTypeDomain, "*.people-a.example", "", member.String(),
		scopedom.EntryOptions{Reason: "rule", MaxTier: scopedom.TierActive})
	if err != nil {
		t.Fatal(err)
	}
	e.SetOrigin(scopedom.OriginReviewRule)
	if err := repo.Create(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetByID(ctx, tenantA, e.ID())
	if err != nil || got.Origin() != scopedom.OriginReviewRule {
		t.Fatalf("origin = %v %v", got, err)
	}
	seedScopeTarget(t, db, tenantA, "domain", "*.legacy-a.example")
	var origin string
	if err := db.QueryRowContext(ctx, `SELECT origin FROM scope_targets WHERE tenant_id = $1 AND pattern = '*.legacy-a.example'`,
		tenantA.String()).Scan(&origin); err != nil || origin != "manual" {
		t.Fatalf("default origin = %q %v", origin, err)
	}
	// An unknown origin is refused by the column check.
	if _, err := db.ExecContext(ctx, `INSERT INTO scope_targets (tenant_id, target_type, pattern, status, origin) VALUES ($1, 'domain', 'x.people-a.example', 'active', 'hacker')`,
		tenantA.String()); err == nil {
		t.Fatal("an unknown origin was stored")
	}
}
