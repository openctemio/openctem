package remediation

// In-app notices to the people who own a task. A notice names the task and
// counts only (never a finding title): the inbox and the live push show it
// only to members who can read at least one finding of the task
// (postgres.notificationScopeCond / ListRecipients), so the title of a task
// reaches nobody outside its scope.

import (
	"context"
	"fmt"

	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SetNotifier wires the in-app notices to task owners (*notification service).
func (s *TaskService) SetNotifier(n QueryTaskNotifier) { s.notifier = n }

// notifyOwners sends one notice to the owner user and one to the owner team
// of t, none to the actor themself. Best effort: a failure is logged.
func (s *TaskService) notifyOwners(ctx context.Context, tenantID shared.ID, taskID shared.ID, user, group, actor *shared.ID, title, body string) {
	if s.notifier == nil {
		return
	}
	send := func(audience string, id shared.ID) {
		tid, aid := taskID, id
		if err := s.notifier.Notify(ctx, notificationdom.NotificationParams{
			TenantID: tenantID, Audience: audience, AudienceID: &aid,
			NotificationType: notificationdom.TypeRemediationTask, Title: title, Body: body,
			Severity: "info", ResourceType: string(auditdom.ResourceTypeRemediationTask), ResourceID: &tid,
			URL: "/remediation/tasks/" + taskID.String(), ActorID: actor,
		}); err != nil {
			s.logger.Warn("notify task owner failed", "task_id", taskID.String(), "error", logger.SanitizeError(err))
		}
	}
	if user != nil && (actor == nil || *actor != *user) {
		send(notificationdom.AudienceUser, *user)
	}
	if group != nil {
		send(notificationdom.AudienceGroup, *group)
	}
}

// notifyNewOwner tells the person (or the team) a task was given to.
func (s *TaskService) notifyNewOwner(ctx context.Context, t *remediationdom.Task, user, group, actor *shared.ID) {
	s.notifyOwners(ctx, t.TenantID, t.ID, user, group, actor,
		"A remediation task was assigned to you", t.Title)
}

// notifyMoveOwners tells the owners of the task findings left and of the task
// they joined (a finding belongs to one active task, so a move changes both).
func (s *TaskService) notifyMoveOwners(ctx context.Context, ev remediationdom.TaskMoveEvent) {
	if s.notifier == nil || ev.Findings <= 0 {
		return
	}
	n := fmt.Sprintf("%d finding", ev.Findings)
	if ev.Findings != 1 {
		n += "s"
	}
	if src, err := s.repo.GetTask(ctx, ev.TenantID, ev.FromTaskID); err == nil {
		body := fmt.Sprintf("%s taken out of task %q.", n, src.Title)
		if ev.ToTaskID != nil {
			body = fmt.Sprintf("%s moved from task %q to %q.", n, src.Title, ev.ToTitle)
		}
		s.notifyOwners(ctx, ev.TenantID, src.ID, src.AssigneeUserID, src.AssigneeGroupID, ev.ActorID,
			"Findings left your remediation task", body)
	}
	if ev.ToTaskID == nil {
		return
	}
	if dst, err := s.repo.GetTask(ctx, ev.TenantID, *ev.ToTaskID); err == nil {
		s.notifyOwners(ctx, ev.TenantID, dst.ID, dst.AssigneeUserID, dst.AssigneeGroupID, ev.ActorID,
			"Findings joined your remediation task", fmt.Sprintf("%s joined task %q from %q.", n, dst.Title, ev.FromTitle))
	}
}
