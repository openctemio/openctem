package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/lifecycle"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The idle policy as the application role: only organizations an
// administrator turned the policy on for are listed or ever read-only (a
// Free-plan organization without the policy is neither, owner rule: no
// organization goes read-only unless an operator chose that), sign-ins come
// from active members, the read-only check lifts on a sign-in after the stage
// started, turning the policy off lifts read-only at once, and every read
// stays inside its organization. Requires DATABASE_URL.
func TestIdleLifecycleRepository(t *testing.T) {
	sqlDB := openSensorDB(t)
	ctx := context.Background()
	r := NewIdleLifecycleRepository(&DB{DB: sqlDB})
	suffix := shared.NewID().String()[28:]
	opted := planTestTenant(t, sqlDB, "idle-opted-"+suffix)
	free := planTestTenant(t, sqlDB, "idle-free-"+suffix)
	owner := planTestUser(t, sqlDB, "idle-owner-"+suffix+"@example.test")
	member := planTestUser(t, sqlDB, "idle-member-"+suffix+"@example.test")
	for _, q := range []struct {
		sql  string
		args []any
	}{
		// A Free-plan organization idle for 100 days, with a read-only stage
		// left from before the policy became opt-in.
		{`INSERT INTO tenant_plans (tenant_id, plan) VALUES ($1, 'free')`, []any{free.String()}},
		{`INSERT INTO tenant_idle_lifecycle (tenant_id, stage, stage_changed_at) VALUES ($1, 'read_only', now() - interval '1 day')`, []any{free.String()}},
		{`INSERT INTO tenant_members (tenant_id, user_id, role, status) VALUES ($1, $2, 'owner', 'active'), ($1, $3, 'member', 'active'), ($4, $2, 'owner', 'active')`,
			[]any{opted.String(), owner.String(), member.String(), free.String()}},
		{`UPDATE users SET last_login_at = now() - interval '100 days' WHERE id = $1`, []any{owner.String()}},
		{`UPDATE users SET last_login_at = now() - interval '95 days' WHERE id = $1`, []any{member.String()}},
	} {
		if _, err := sqlDB.ExecContext(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	listed := func() map[shared.ID]lifecycle.Workspace {
		t.Helper()
		list, err := r.Workspaces(ctx)
		if err != nil {
			t.Fatal(err)
		}
		out := map[shared.ID]lifecycle.Workspace{}
		for _, w := range list {
			out[w.TenantID] = w
		}
		return out
	}

	// Default: the policy is off everywhere.
	got := listed()
	for _, id := range []shared.ID{opted, free} {
		if _, ok := got[id]; ok {
			t.Fatalf("no organization is under the policy by default: %s", id)
		}
	}
	if ro, _ := r.ReadOnly(ctx, free); ro {
		t.Fatal("a Free-plan organization without the policy must never be read-only")
	}
	if st, err := r.Status(ctx, free); err != nil || st.PolicyEnabled {
		t.Fatalf("status: %+v %v", st, err)
	}

	by := shared.NewID()
	if err := r.SetPolicy(ctx, opted, lifecycle.Policy{Enabled: true, Reason: "hosted free tier", By: &by, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	got = listed()
	if _, ok := got[free]; ok {
		t.Fatal("a Free-plan organization without the policy must not be swept")
	}
	w, ok := got[opted]
	if !ok || w.Stage != lifecycle.StageActive || w.LastSignIn.IsZero() {
		t.Fatalf("opted-in organization: %+v", w)
	}
	if idle := time.Since(w.LastSignIn); idle < 94*24*time.Hour || idle > 96*24*time.Hour {
		t.Fatalf("latest member sign-in should be 95 days ago, got %v", idle)
	}
	st, err := r.Status(ctx, opted)
	if err != nil || !st.PolicyEnabled || st.PolicyReason != "hosted free tier" || st.PolicySetAt == nil {
		t.Fatalf("status: %+v %v", st, err)
	}

	// Read-only: stage set now, nobody signed in since.
	if err := r.SetStage(ctx, opted, lifecycle.StageReadOnly, time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if ro, _ := r.ReadOnly(ctx, opted); !ro {
		t.Fatal("want read-only")
	}
	if ro, _ := r.ReadOnly(ctx, free); ro {
		t.Fatal("another organization must not be read-only")
	}
	if rs, _ := r.Recipients(ctx, opted); len(rs) != 1 || rs[0] != "idle-owner-"+suffix+"@example.test" {
		t.Fatalf("recipients (owners and admins only): %v", rs)
	}

	// A member signs in: read-only lifts at once.
	if _, err := sqlDB.ExecContext(ctx, `UPDATE users SET last_login_at = now() WHERE id = $1`, member.String()); err != nil {
		t.Fatal(err)
	}
	if ro, _ := r.ReadOnly(ctx, opted); ro {
		t.Fatal("a sign-in must lift read-only")
	}

	// Turning the policy off: back to active, never read-only, not swept.
	if err := r.SetStage(ctx, opted, lifecycle.StageDeletionDue, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := r.SetPolicy(ctx, opted, lifecycle.Policy{Enabled: false, Reason: "customer asked", By: &by, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if st, _ = r.Status(ctx, opted); st.PolicyEnabled || st.Stage != lifecycle.StageActive {
		t.Fatalf("policy off: %+v", st)
	}
	if ro, _ := r.ReadOnly(ctx, opted); ro {
		t.Fatal("policy off must lift read-only")
	}
	if _, ok := listed()[opted]; ok {
		t.Fatal("policy off: not swept")
	}
	if err := r.SetStage(ctx, opted, lifecycle.Stage("bogus"), time.Now()); err == nil {
		t.Fatal("an unknown stage must be refused")
	}
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO tenant_idle_lifecycle (tenant_id, policy_enabled, policy_reason) VALUES ($1, true, '')`, free.String()); err == nil {
		t.Fatal("an empty reason must be refused by the check constraint")
	}
}
