package postgres

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// The task owner's access to the findings of the live tasks they own: exactly
// the task's findings, never the asset's other findings, and only while the
// relation holds. Skipped unless DATABASE_URL is set.
func TestTaskOwnerRelation_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping schema-level check")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("exec %q: %v", q, err)
		}
	}

	tenantID, otherTenant := shared.NewID(), shared.NewID()
	for _, id := range []shared.ID{tenantID, otherTenant} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'tor', $2)`, id.String(), "tor-"+id.String()[24:])
		id := id
		defer func() { _, _ = db.ExecContext(ctx, `DELETE FROM tenants WHERE id = $1`, id.String()) }()
	}
	user := func(tenant shared.ID) shared.ID {
		id := shared.NewID()
		exec(`INSERT INTO users (id, email, name) VALUES ($1, $2, 'tor')`, id.String(), id.String()+"@tor.test")
		exec(`INSERT INTO tenant_members (user_id, tenant_id, role) VALUES ($1, $2, 'member')`, id.String(), tenant.String())
		t.Cleanup(func() { _, _ = db.ExecContext(ctx, `DELETE FROM users WHERE id = $1`, id.String()) })
		return id
	}
	owner, other, outsider := user(tenantID), user(tenantID), user(otherTenant)

	assetA, assetB := seedAsset(ctx, t, db, tenantID), seedAsset(ctx, t, db, tenantID)
	inTask := seedFinding(ctx, t, db, tenantID, assetA, "external", "high", "new")
	sameAsset := seedFinding(ctx, t, db, tenantID, assetA, "external", "high", "new")
	otherAsset := seedFinding(ctx, t, db, tenantID, assetB, "external", "high", "new")
	pentest := seedFinding(ctx, t, db, tenantID, assetB, "pentest", "high", "new")
	all := []shared.ID{inTask, sameAsset, otherAsset, pentest}

	repo := NewRemediationTaskRepository(&DB{DB: db})
	taskID := shared.NewID()
	rec := &remediation.NewTaskRecord{
		Task: remediation.Task{ID: taskID, TenantID: tenantID, Title: "owned"},
		Action: remediation.Action{TenantID: tenantID, Key: remediation.ManualActionKey(taskID), Kind: remediation.ActionKindManual,
			Title: "owned", Origin: remediation.ActionOriginManual},
		Members: []shared.ID{inTask, pentest}, Source: remediation.JoinSourceManual,
	}
	if err := repo.CreateTask(ctx, rec); err != nil {
		t.Fatalf("create task: %v", err)
	}
	setOwner := func(u *shared.ID, g *string) {
		t.Helper()
		var us, gs any
		if u != nil {
			us = u.String()
		}
		if g != nil {
			gs = *g
		}
		exec(`UPDATE remediation_tasks SET assignee_user_id = $1, assignee_group_id = $2 WHERE id = $3`, us, gs, taskID.String())
	}

	scopes := NewDataScopeRepository(&DB{DB: db})
	owned := func(who, tenant shared.ID) map[shared.ID]bool {
		t.Helper()
		ids, err := scopes.FindingIDsOwnedViaTask(ctx, tenant, who, all)
		if err != nil {
			t.Fatalf("owned via task: %v", err)
		}
		m := map[shared.ID]bool{}
		for _, id := range ids {
			m[id] = true
		}
		return m
	}
	want := func(step string, got map[shared.ID]bool, ids ...shared.ID) {
		t.Helper()
		exp := map[shared.ID]bool{}
		for _, id := range ids {
			exp[id] = true
		}
		for _, id := range all {
			if got[id] != exp[id] {
				t.Fatalf("%s: finding %s owned=%v, want %v", step, id, got[id], exp[id])
			}
		}
	}

	want("no owner", owned(owner, tenantID))

	// A user owner: exactly the task's finding; not the same asset's other
	// finding, not another asset's; never the pentest finding.
	setOwner(&owner, nil)
	want("user owner", owned(owner, tenantID), inTask)
	want("another member", owned(other, tenantID))
	want("other tenant", owned(outsider, otherTenant))
	want("owner id in the other tenant", owned(owner, otherTenant))

	// The view scope of the task reads: the owner sees the task's finding and
	// nothing of the asset's others; a stranger sees nothing.
	view := func(who shared.ID) []shared.ID {
		t.Helper()
		res, err := repo.ListMembers(ctx, tenantID, taskID, remediation.MemberFilter{Scope: &shared.DataScope{TenantID: tenantID, UserID: who}}, pagination.New(1, 50))
		if err != nil {
			t.Fatalf("list members: %v", err)
		}
		var out []shared.ID
		for _, m := range res.Data {
			out = append(out, m.FindingID)
		}
		return out
	}
	if got := view(owner); len(got) != 2 {
		// the pentest finding is a member; the view layer (pentest rule) hides it elsewhere.
		t.Fatalf("owner's task view: want the 2 members, got %v", got)
	}
	if got := view(other); len(got) != 0 {
		t.Fatalf("stranger's task view: want none, got %v", got)
	}
	counts, err := repo.ScopedCounts(ctx, tenantID, []shared.ID{taskID}, &shared.DataScope{TenantID: tenantID, UserID: owner})
	if err != nil || counts[taskID].Total != 2 {
		t.Fatalf("owner's counters: %v %+v", err, counts[taskID])
	}

	// The same owner reading as a non-admin finding viewer who is not a member
	// of the pentest finding's campaign: the owner rule admits the task's
	// findings and the pentest rule removes the pentest one, in the member list
	// and in the counters alike.
	vctx := shared.WithFindingViewer(ctx, shared.FindingViewer{UserID: owner})
	vres, err := repo.ListMembers(vctx, tenantID, taskID, remediation.MemberFilter{Scope: &shared.DataScope{TenantID: tenantID, UserID: owner}}, pagination.New(1, 50))
	if err != nil {
		t.Fatalf("list members as viewer: %v", err)
	}
	if len(vres.Data) != 1 || vres.Data[0].FindingID != inTask {
		t.Fatalf("owner as non-admin viewer: want only the non-pentest finding, got %+v", vres.Data)
	}
	vcounts, err := repo.ScopedCounts(vctx, tenantID, []shared.ID{taskID}, &shared.DataScope{TenantID: tenantID, UserID: owner})
	if err != nil || vcounts[taskID].Total != 1 {
		t.Fatalf("owner as non-admin viewer: counters want total 1, got %v %+v", err, vcounts[taskID])
	}

	// The task list filtered by a finding uses the same view scope: the owner
	// finds the task through the finding they own via it, a stranger does not.
	listBy := func(who shared.ID, finding shared.ID) int {
		t.Helper()
		res, err := repo.ListTasks(ctx, tenantID, remediation.TaskFilter{FindingID: &finding, Scope: &shared.DataScope{TenantID: tenantID, UserID: who}}, pagination.New(1, 50))
		if err != nil {
			t.Fatalf("list tasks by finding: %v", err)
		}
		return len(res.Data)
	}
	if n := listBy(owner, inTask); n != 1 {
		t.Fatalf("owner's task list filtered by the owned finding: want 1 task, got %d", n)
	}
	if n := listBy(owner, sameAsset); n != 0 {
		t.Fatalf("owner filtering by a finding outside the task: want 0, got %d", n)
	}
	if n := listBy(other, inTask); n != 0 {
		t.Fatalf("stranger's task list filtered by the finding: want 0, got %d", n)
	}

	// Owner change ends it at once.
	setOwner(&other, nil)
	want("owner changed", owned(owner, tenantID))
	want("new owner", owned(other, tenantID), inTask)

	// Team owner: an active member, an expired member, a non-member.
	grp := shared.NewID().String()
	exec(`INSERT INTO groups (id, tenant_id, name, slug) VALUES ($1, $2, 'sq', $3)`, grp, tenantID.String(), "sq-"+grp[24:])
	exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`, grp, owner.String())
	exec(`INSERT INTO group_members (group_id, user_id, expires_at) VALUES ($1, $2, now() - interval '1 hour')`, grp, other.String())
	setOwner(nil, &grp)
	want("team member", owned(owner, tenantID), inTask)
	want("expired team member", owned(other, tenantID))
	exec(`DELETE FROM group_members WHERE group_id = $1 AND user_id = $2`, grp, owner.String())
	want("left the team", owned(owner, tenantID))
	exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`, grp, owner.String())
	want("rejoined", owned(owner, tenantID), inTask)
	exec(`UPDATE tenant_members SET status = 'suspended' WHERE user_id = $1 AND tenant_id = $2`, owner.String(), tenantID.String())
	want("suspended member", owned(owner, tenantID))
	exec(`UPDATE tenant_members SET status = 'active' WHERE user_id = $1 AND tenant_id = $2`, owner.String(), tenantID.String())
	exec(`UPDATE groups SET is_active = FALSE WHERE id = $1`, grp)
	want("inactive team", owned(owner, tenantID))
	exec(`UPDATE groups SET is_active = TRUE WHERE id = $1`, grp)

	// The finding leaves the task; the task closes.
	exec(`UPDATE remediation_task_members SET left_at = now(), left_reason = 'removed' WHERE task_id = $1 AND finding_id = $2`, taskID.String(), inTask.String())
	want("finding left the task", owned(owner, tenantID))
	exec(`UPDATE remediation_task_members SET left_at = NULL, left_reason = NULL WHERE task_id = $1 AND finding_id = $2`, taskID.String(), inTask.String())
	want("back in the task", owned(owner, tenantID), inTask)
	for _, st := range []string{"done", "closed_unverified", "canceled", "archived"} {
		exec(`UPDATE remediation_tasks SET state = $1 WHERE id = $2`, st, taskID.String())
		want("task "+st, owned(owner, tenantID))
	}
	for _, st := range []string{"open", "in_progress", "verifying", "on_hold"} {
		exec(`UPDATE remediation_tasks SET state = $1 WHERE id = $2`, st, taskID.String())
		want("task "+st, owned(owner, tenantID), inTask)
	}

	// A related membership gives nothing; a finding on an asset hidden from
	// the owner (private program) stays hidden.
	exec(`UPDATE remediation_task_members SET role = 'related' WHERE task_id = $1 AND finding_id = $2`, taskID.String(), inTask.String())
	want("related member", owned(owner, tenantID))
	exec(`UPDATE remediation_task_members SET role = 'primary' WHERE task_id = $1 AND finding_id = $2`, taskID.String(), inTask.String())
	prog := shared.NewID().String()
	exec(`INSERT INTO bounty_programs (id, tenant_id, name, terms_sha256, visibility) VALUES ($1, $2, 'p', repeat('a', 64), 'private')`, prog, tenantID.String())
	exec(`UPDATE assets SET program_only = TRUE WHERE id = $1`, assetA.String())
	exec(`INSERT INTO asset_program_links (tenant_id, asset_id, program_id, source) VALUES ($1, $2, $3, 'program_manual')`, tenantID.String(), assetA.String(), prog)
	want("asset hidden from the owner", owned(owner, tenantID))
}
