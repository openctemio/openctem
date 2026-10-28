package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/platformrole"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/platformauthz"
)

// The role store writes the audit entry in the change's transaction, and a
// break-glass account holds its base role only (migration 003525).
func TestPlatformRoleStore_AuditAtomicAndBreakGlassBaseOnly(t *testing.T) {
	db := openConsoleDB(t)
	admins := postgres.NewAdminRepository(db)
	store := postgres.NewPlatformRoleRepository(db)
	stamp := time.Now().Format("150405.000000")
	ctx := t.Context()

	mk := func(email string) (*admin.AdminUser, string) {
		a, err := admin.NewAdminUser(email, "IT", admin.AdminRoleReadonly, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := admins.Create(ctx, a); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = admins.Delete(context.Background(), a.ID()) })
		return a, createUser(t, db, email).String()
	}
	actor, _ := mk("role-actor-" + stamp + "@example.test")
	target, _ := mk("role-target-" + stamp + "@example.test")
	entry := func(act *admin.AdminUser, tgt *admin.AdminUser) *admin.AuditLog {
		id := tgt.ID()
		return admin.NewAuditLogBuilder(act, platformrole.ActionAssigned).Resource("admin_user", &id, tgt.Email()).Build()
	}
	held := func(a *admin.AdminUser) int {
		roles, err := store.HeldRoles(ctx, a.ID().String())
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, r := range roles {
			if r == platformauthz.RoleSupport {
				n++
			}
		}
		return n
	}

	// A failed audit write (the entry's id is already taken) rolls the change
	// back.
	bad := entry(actor, target)
	seed := *bad
	seed.Action = "test.seed"
	if err := postgres.NewAuditLogRepository(db).Create(ctx, &seed); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Assign(ctx, target.ID(), platformauthz.RoleSupport, actor.ID(), bad); !errors.Is(err, platformrole.ErrAuditUnavailable) {
		t.Fatalf("a failed audit write must refuse the change, got %v", err)
	}
	if held(target) != 0 {
		t.Fatal("the role was stored although its audit row failed")
	}
	if _, err := store.Assign(ctx, target.ID(), platformauthz.RoleSupport, actor.ID(), nil); !errors.Is(err, platformrole.ErrAuditUnavailable) {
		t.Fatalf("no audit entry, no change: %v", err)
	}

	// The change and its audit row commit together, once.
	count := func() (n int) {
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM admin_audit_logs WHERE action = $1 AND resource_id = $2`,
			platformrole.ActionAssigned, target.ID().String()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for i := 0; i < 2; i++ {
		if _, err := store.Assign(ctx, target.ID(), platformauthz.RoleSupport, actor.ID(), entry(actor, target)); err != nil {
			t.Fatal(err)
		}
	}
	if held(target) != 1 || count() != 1 {
		t.Fatalf("held %d, audit rows %d (a repeated grant audits nothing)", held(target), count())
	}

	// A break-glass account takes no extra role, by SQL and through the store;
	// an account holding one cannot be marked break-glass.
	glass, _ := mk("role-glass-" + stamp + "@example.test")
	if err := glass.SetBreakGlass(true); err != nil {
		t.Fatal(err)
	}
	if err := admins.GuardedUpdate(ctx, glass); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Assign(ctx, glass.ID(), platformauthz.RoleSupport, actor.ID(), entry(actor, glass)); !errors.Is(err, admin.ErrBreakGlassHasRoles) {
		t.Fatalf("store grant to break-glass: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO platform_role_assignments (admin_id, role_id)
		SELECT $1, id FROM platform_roles WHERE key = 'support'`, glass.ID().String()); err == nil {
		t.Fatal("SQL grant of an extra role to a break-glass account must be refused")
	}
	if err := target.SetBreakGlass(true); err != nil {
		t.Fatal(err)
	}
	if err := admins.GuardedUpdate(ctx, target); !errors.Is(err, admin.ErrBreakGlassHasRoles) {
		t.Fatalf("marking an account that holds an extra role break-glass: %v", err)
	}
}
