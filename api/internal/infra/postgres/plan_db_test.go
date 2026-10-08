package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/plan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func planTestTenant(t *testing.T, db *sql.DB, slug string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`, id.String(), slug, slug); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM tenants WHERE id = $1`, id.String()) })
	return id
}

func planTestUser(t *testing.T, db *sql.DB, email string) shared.ID {
	t.Helper()
	id := shared.NewID()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO users (id, email, name, status) VALUES ($1, $2, 'Plan Test', 'active')`, id.String(), email); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.ExecContext(context.Background(), `DELETE FROM users WHERE id = $1`, id.String()) })
	return id
}

// Plans, overrides and usage (migration 001325) as the application role:
// every read and write stays inside its organization.
// Requires DATABASE_URL.
func TestPlanRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	r := NewPlanRepository(&DB{DB: sqlDB})
	suffix := shared.NewID().String()[:8]
	a := planTestTenant(t, sqlDB, "plan-a-"+suffix)
	b := planTestTenant(t, sqlDB, "plan-b-"+suffix)
	owner := planTestUser(t, sqlDB, "plan-owner-"+suffix+"@example.test")
	member := planTestUser(t, sqlDB, "plan-member-"+suffix+"@example.test")
	now := time.Now().UTC()

	// Defaults: absent, then saved, then a stale save refused.
	_, _ = sqlDB.ExecContext(ctx, `DELETE FROM platform_settings WHERE key = $1`, plan.SettingKey)
	t.Cleanup(func() {
		_, _ = sqlDB.ExecContext(context.Background(), `DELETE FROM platform_settings WHERE key = $1`, plan.SettingKey)
	})
	if _, _, err := r.GetDefaults(ctx); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("empty defaults: %v", err)
	}
	d := plan.BuiltinDefaults()
	v, err := r.SaveDefaults(ctx, d, 0, owner, now)
	if err != nil || v != 1 {
		t.Fatalf("first save v=%d err=%v", v, err)
	}
	if _, err := r.SaveDefaults(ctx, d, 0, owner, now); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("second insert must conflict: %v", err)
	}
	d[plan.Free][plan.Seats] = 3
	if v, err = r.SaveDefaults(ctx, d, 1, owner, now); err != nil || v != 2 {
		t.Fatalf("update v=%d err=%v", v, err)
	}
	if _, err := r.SaveDefaults(ctx, d, 1, owner, now); !errors.Is(err, shared.ErrConflict) {
		t.Fatalf("stale version must conflict: %v", err)
	}
	got, gv, err := r.GetDefaults(ctx)
	if err != nil || gv != 2 || got.For(plan.Free).Get(plan.Seats) != 3 {
		t.Fatalf("read back: %v v=%d err=%v", got, gv, err)
	}

	// Plans: none stored, then set, then changed; b untouched.
	if _, ok, err := r.TenantPlan(ctx, a); ok || err != nil {
		t.Fatalf("no plan yet: ok=%v err=%v", ok, err)
	}
	if err := r.SetTenantPlan(ctx, a, plan.Free, nil, now); err != nil {
		t.Fatal(err)
	}
	if err := r.SetTenantPlan(ctx, a, plan.Pro, &owner, now); err != nil {
		t.Fatal(err)
	}
	if p, ok, _ := r.TenantPlan(ctx, a); !ok || p != plan.Pro {
		t.Fatalf("plan a: %q %v", p, ok)
	}
	if _, ok, _ := r.TenantPlan(ctx, b); ok {
		t.Fatal("plan b must be untouched")
	}
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenant_plans (tenant_id, plan) VALUES ($1, 'gold')`, b.String()); err == nil {
		t.Fatal("an unknown plan must be refused by the check constraint")
	}

	// Overrides are per organization.
	exp := now.Add(24 * time.Hour)
	if err := r.SetOverride(ctx, plan.Override{TenantID: a, Key: plan.Seats, Value: 10, Reason: "pilot", ExpiresAt: &exp, SetBy: &owner, SetAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := r.SetOverride(ctx, plan.Override{TenantID: a, Key: plan.Seats, Value: 12, Reason: "pilot+", SetAt: now}); err != nil {
		t.Fatal(err)
	}
	oa, _ := r.ListOverrides(ctx, a)
	if len(oa) != 1 || oa[0].Value != 12 || oa[0].ExpiresAt != nil || oa[0].Reason != "pilot+" {
		t.Fatalf("overrides a: %+v", oa)
	}
	if ob, _ := r.ListOverrides(ctx, b); len(ob) != 0 {
		t.Fatalf("overrides b must be empty: %+v", ob)
	}
	if err := r.DeleteOverride(ctx, b, plan.Seats); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("deleting b's (absent) override must not touch a's: %v", err)
	}
	if err := r.DeleteOverride(ctx, a, plan.Seats); err != nil {
		t.Fatal(err)
	}
	if err := r.SetOverride(ctx, plan.Override{TenantID: a, Key: plan.Seats, Value: 1, Reason: "", SetAt: now}); err == nil {
		t.Fatal("an empty reason must be refused by the check constraint")
	}

	// Usage counts only the organization's own rows.
	for _, m := range []struct {
		tenant shared.ID
		user   shared.ID
		role   string
	}{{a, owner, "owner"}, {a, member, "member"}, {b, member, "owner"}} {
		if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenant_members (tenant_id, user_id, role, status) VALUES ($1, $2, $3, 'active')`,
			m.tenant.String(), m.user.String(), m.role); err != nil {
			t.Fatalf("insert member: %v", err)
		}
	}
	ua, err := r.Usage(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if ua[plan.Seats] != 2 || ua[plan.Assets] != 0 || ua[plan.APIKeys] != 0 {
		t.Fatalf("usage a: %v", ua)
	}
	if ub, _ := r.Usage(ctx, b); ub[plan.Seats] != 1 {
		t.Fatalf("usage b: %v", ub)
	}

	// Free organizations a person owns: a is Pro, b has no plan.
	if n, _ := r.CountOwnedFreeTenants(ctx, member); n != 0 {
		t.Fatalf("member owns b (no plan): %d", n)
	}
	if err := r.SetTenantPlan(ctx, b, plan.Free, nil, now); err != nil {
		t.Fatal(err)
	}
	if n, _ := r.CountOwnedFreeTenants(ctx, member); n != 1 {
		t.Fatalf("member owns Free b: %d", n)
	}
	if n, _ := r.CountOwnedFreeTenants(ctx, owner); n != 0 {
		t.Fatalf("owner owns Pro a only: %d", n)
	}
}
