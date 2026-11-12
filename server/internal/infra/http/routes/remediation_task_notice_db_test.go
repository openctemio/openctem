package routes

// Task owner notices and their read scope (research 215, B2): a new owner is
// told, a move tells the owners of both tasks, and the inbox, unread count and
// live push show a task notice only to members who can read one of its
// findings. Real Postgres.

import (
	"context"
	"slices"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	appremediation "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// repoNotifier stores what the task service sends, as the notification
// service does (without the WebSocket push).
type repoNotifier struct {
	repo *postgres.NotificationRepository
}

func (n repoNotifier) Notify(ctx context.Context, p notificationdom.NotificationParams) error {
	return n.repo.Create(ctx, notificationdom.NewNotification(p))
}

func TestTaskOwnerNotices_DB(t *testing.T) {
	h := newCampaignTasksHarness(t)
	db := &postgres.DB{DB: h.db}
	notifs := postgres.NewNotificationRepository(db)
	tasks := appremediation.NewTaskService(postgres.NewRemediationTaskRepository(db), logger.NewNop())
	tasks.SetAssigneeChecker(postgres.NewAccessControlRepository(db))
	tasks.SetNotifier(repoNotifier{repo: notifs})
	ctx := context.Background()
	tenant := h.tenant

	// Leave only task notices to count (the harness seeds finding broadcasts).
	h.exec(`DELETE FROM notifications WHERE tenant_id = $1 AND notification_type <> 'remediation_task'`, tenant.String())
	count := h.countRows
	taskNotices := func(task shared.ID, audience string, audienceID shared.ID) int {
		return count(`SELECT COUNT(*) FROM notifications WHERE tenant_id = $1 AND notification_type = 'remediation_task'
			AND resource_id = $2 AND audience = $3 AND audience_id = $4`, tenant.String(), task.String(), audience, audienceID.String())
	}

	// A new owner (user) is told; the actor assigning themself is not.
	owner := &h.memberA
	if _, err := tasks.UpdateTask(ctx, appremediation.UpdateTaskInput{TenantID: tenant, TaskID: h.taskA, Version: 1,
		ActorID: &h.owner, AssigneeUserID: &owner}, auditapp.AuditContext{TenantID: tenant.String()}); err != nil {
		t.Fatalf("assign owner: %v", err)
	}
	if n := taskNotices(h.taskA, "user", h.memberA); n != 1 {
		t.Fatalf("new owner notices = %d, want 1", n)
	}
	self := &h.owner
	if _, err := tasks.UpdateTask(ctx, appremediation.UpdateTaskInput{TenantID: tenant, TaskID: h.taskB, Version: 1,
		ActorID: &h.owner, AssigneeUserID: &self}, auditapp.AuditContext{TenantID: tenant.String()}); err != nil {
		t.Fatalf("self assign: %v", err)
	}
	if n := taskNotices(h.taskB, "user", h.owner); n != 0 {
		t.Fatalf("self-assignment notices = %d, want 0", n)
	}

	// A team owner is told through the team audience.
	team := shared.NewID()
	h.exec(`INSERT INTO groups (id, tenant_id, name, slug, group_type, is_active) VALUES ($1, $2, 'task-team', $3, 'team', true)`,
		team.String(), tenant.String(), "task-team-"+team.String()[:8])
	h.exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, team.String(), h.memberFree.String())
	tg := &team
	if _, err := tasks.UpdateTask(ctx, appremediation.UpdateTaskInput{TenantID: tenant, TaskID: h.taskA2, Version: 1,
		ActorID: &h.owner, AssigneeGroupID: &tg}, auditapp.AuditContext{TenantID: tenant.String()}); err != nil {
		t.Fatalf("assign team: %v", err)
	}
	if n := taskNotices(h.taskA2, "group", team); n != 1 {
		t.Fatalf("team owner notices = %d, want 1", n)
	}

	// A move tells the owners of both tasks (taskA is memberA's, taskA2 the team's).
	f := h.finding(h.assetA)
	h.exec(`INSERT INTO remediation_task_members (tenant_id, task_id, finding_id, role, join_source) VALUES ($1, $2, $3, 'primary', 'manual')`,
		tenant.String(), h.taskA.String(), f.String())
	to := h.taskA2
	if _, err := tasks.Move(ctx, appremediation.MoveInput{TenantID: tenant, FromTaskID: h.taskA, FromVersion: 2, ToTaskID: &to, ToVersion: 2,
		FindingIDs: []shared.ID{f}, Confirm: true, ActorID: &h.owner}, auditapp.AuditContext{TenantID: tenant.String()}); err != nil {
		t.Fatalf("move: %v", err)
	}
	if n := taskNotices(h.taskA, "user", h.memberA); n != 2 {
		t.Errorf("source owner notices = %d, want 2 (assigned, finding left)", n)
	}
	if n := taskNotices(h.taskA2, "group", team); n != 2 {
		t.Errorf("target owner notices = %d, want 2 (assigned, finding joined)", n)
	}

	// Read scope. A notice about taskB (its only finding is on asset B) is
	// invisible to memberA (scope: asset A); one about taskA is visible; the
	// unrestricted reader sees both.
	for _, task := range []shared.ID{h.taskA, h.taskB} {
		h.exec(`INSERT INTO notifications (tenant_id, audience, audience_id, notification_type, title, body, severity, resource_type, resource_id)
			VALUES ($1, 'user', $2, 'remediation_task', 'scope probe', 'b', 'info', 'remediation_task', $3)`,
			tenant.String(), h.memberA.String(), task.String())
	}
	scopeA := &shared.DataScope{TenantID: tenant, UserID: h.memberA}
	visible := func(scope *shared.DataScope) map[string]bool {
		t.Helper()
		page, err := notifs.List(ctx, tenant, h.memberA, notificationdom.ListFilter{Type: "remediation_task", DataScope: scope}, pagination.New(1, 50))
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]bool{}
		for _, n := range page.Data {
			if n.Title() == "scope probe" && n.ResourceID() != nil {
				out[n.ResourceID().String()] = true
			}
		}
		return out
	}
	got := visible(scopeA)
	if !got[h.taskA.String()] || got[h.taskB.String()] {
		t.Errorf("restricted member sees task notices %v, want taskA only", got)
	}
	if got := visible(nil); !got[h.taskA.String()] || !got[h.taskB.String()] {
		t.Errorf("unrestricted reader sees %v, want both", got)
	}
	unreadScoped, err := notifs.UnreadCount(ctx, tenant, h.memberA, scopeA)
	if err != nil {
		t.Fatal(err)
	}
	unreadAll, err := notifs.UnreadCount(ctx, tenant, h.memberA, nil)
	if err != nil {
		t.Fatal(err)
	}
	if unreadAll-unreadScoped != 1 {
		t.Errorf("unread count hides %d task notices, want 1 (all %d, scoped %d)", unreadAll-unreadScoped, unreadAll, unreadScoped)
	}

	// The live push goes to the same people.
	recipients := func(task shared.ID) []shared.ID {
		t.Helper()
		n := notificationdom.NewNotification(notificationdom.NotificationParams{TenantID: tenant, Audience: notificationdom.AudienceAll,
			NotificationType: notificationdom.TypeRemediationTask, Title: "t", Body: "b", ResourceType: "remediation_task", ResourceID: &task})
		ids, err := notifs.ListRecipients(ctx, n)
		if err != nil {
			t.Fatal(err)
		}
		return ids
	}
	for _, c := range []struct {
		name  string
		task  shared.ID
		user  shared.ID
		wants bool
	}{
		{"memberA, task in scope", h.taskA, h.memberA, true},
		{"memberA, task out of scope", h.taskB, h.memberA, false},
		{"member without scope", h.taskA, h.memberStrict, false},
		{"member with full data", h.taskB, h.memberFull, true},
		{"tenant owner", h.taskB, h.owner, true},
	} {
		if got := slices.Contains(recipients(c.task), c.user); got != c.wants {
			t.Errorf("%s: push recipient = %v, want %v", c.name, got, c.wants)
		}
	}

	// Another tenant's task id reaches nobody here.
	if got := recipients(shared.NewID()); slices.Contains(got, h.memberA) || slices.Contains(got, h.memberFree) {
		t.Errorf("a task of no member finding reaches scoped members: %v", got)
	}
}
