package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/lifecycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The idle lifecycle (migration 001347) as the application role: only Free
// organizations are listed, sign-ins come from active members, the
// read-only check lifts on a sign-in after the stage started, and every
// read stays inside its organization. Requires DATABASE_URL.
func TestIdleLifecycleRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	r := NewIdleLifecycleRepository(&DB{DB: sqlDB})
	suffix := shared.NewID().String()[:8]
	free := planTestTenant(t, sqlDB, "idle-free-"+suffix)
	pro := planTestTenant(t, sqlDB, "idle-pro-"+suffix)
	owner := planTestUser(t, sqlDB, "idle-owner-"+suffix+"@example.test")
	member := planTestUser(t, sqlDB, "idle-member-"+suffix+"@example.test")
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenant_plans (tenant_id, plan) VALUES ($1, 'free'), ($2, 'pro')`, []any{free.String(), pro.String()}},
		{`INSERT INTO tenant_members (tenant_id, user_id, role, status) VALUES ($1, $2, 'owner', 'active'), ($1, $3, 'member', 'active'), ($4, $2, 'owner', 'active')`,
			[]any{free.String(), owner.String(), member.String(), pro.String()}},
		{`UPDATE users SET last_login_at = now() - interval '100 days' WHERE id = $1`, []any{owner.String()}},
		{`UPDATE users SET last_login_at = now() - interval '95 days' WHERE id = $1`, []any{member.String()}},
	} {
		if _, err := sqlDB.ExecContext(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	list, err := r.FreeWorkspaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got *lifecycle.Workspace
	for i := range list {
		if list[i].TenantID == pro {
			t.Fatal("a Pro organization must not be swept")
		}
		if list[i].TenantID == free {
			got = &list[i]
		}
	}
	if got == nil || got.Stage != lifecycle.StageActive || got.LastSignIn.IsZero() {
		t.Fatalf("free workspace: %+v", got)
	}
	if idle := time.Since(got.LastSignIn); idle < 94*24*time.Hour || idle > 96*24*time.Hour {
		t.Fatalf("latest member sign-in should be 95 days ago, got %v", idle)
	}

	// Read-only: stage set now, nobody signed in since.
	if err := r.SetStage(ctx, free, lifecycle.StageReadOnly, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if ro, _ := r.ReadOnly(ctx, free); !ro {
		t.Fatal("want read-only")
	}
	if ro, _ := r.ReadOnly(ctx, pro); ro {
		t.Fatal("another organization must not be read-only")
	}
	if rs, _ := r.Recipients(ctx, free); len(rs) != 1 || rs[0] != "idle-owner-"+suffix+"@example.test" {
		t.Fatalf("recipients (owners and admins only): %v", rs)
	}

	// A member signs in: read-only lifts at once.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, member.String()); err != nil {
		t.Fatal(err)
	}
	if ro, _ := r.ReadOnly(ctx, free); ro {
		t.Fatal("a sign-in must lift read-only")
	}

	// Exempt: back to active, never read-only.
	if err := r.SetStage(ctx, free, lifecycle.StageDeletionDue, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	by := shared.NewID()
	if err := r.SetExemption(ctx, free, lifecycle.Exemption{Exempt: true, Reason: "partner", By: &by, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	st, err := r.Status(ctx, free)
	if err != nil || !st.Exempt || st.Stage != lifecycle.StageActive || st.ExemptReason != "partner" {
		t.Fatalf("status: %+v %v", st, err)
	}
	if err := r.SetExemption(ctx, free, lifecycle.Exemption{Exempt: false}); err != nil {
		t.Fatal(err)
	}
	if st, _ = r.Status(ctx, free); st.Exempt {
		t.Fatal("exemption must be lifted")
	}
	if err := r.SetStage(ctx, free, lifecycle.Stage("bogus"), time.Now()); err == nil {
		t.Fatal("an unknown stage must be refused")
	}
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenant_idle_lifecycle (tenant_id, exempt) VALUES ($1, true)`, pro.String()); err == nil {
		t.Fatal("an exemption without a reason must be refused by the check constraint")
	}
}
