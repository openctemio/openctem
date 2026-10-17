package remediation

// Remediation tasks: docs/rfcs/RFC-098-remediation-tasks.md.
//
// A person creates a task (by hand, or later by accepting a suggestion),
// names its owner and may tighten its deadline. Everything else is derived
// from the member findings: the state, the deadline (the earliest open
// member's SLA deadline), the counters and the risk left.
//
// Authorization: the route gates (findings:remediation:read / :write) decide
// who may read and change tasks at all; this service adds the data scope. A
// restricted reader sees a task only through its in-scope members (counters
// over those only) and may change a task only when every member is in their
// scope. Every finding a caller names must be in their scope.

import (
	"context"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// TaskAuditLogger writes audit events (*auditapp.AuditService).
type TaskAuditLogger interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// TaskAssigneeChecker validates a task owner (postgres.AccessControlRepository).
type TaskAssigneeChecker interface {
	IsActiveTenantMember(ctx context.Context, tenantID, userID shared.ID) (bool, error)
	IsGroupInTenant(ctx context.Context, tenantID, groupID shared.ID) (bool, error)
}

// TaskService manages remediation tasks.
type TaskService struct {
	repo       remediationdom.TaskRepository
	dataScope  *datascope.Enforcer
	assignees  TaskAssigneeChecker
	audit      TaskAuditLogger
	claimer    TaskFixClaimer
	guard      TaskBulkGuard
	moves      TaskMoveNotifier
	exceptions TaskExceptionRequester
	logger     *logger.Logger
}

// NewTaskService creates the service. Without SetAssigneeChecker naming an
// owner is refused (fail closed).
func NewTaskService(repo remediationdom.TaskRepository, log *logger.Logger) *TaskService {
	return &TaskService{repo: repo, logger: log}
}

// SetDataScope wires the data-scope enforcer (nil = unrestricted, tests).
func (s *TaskService) SetDataScope(e *datascope.Enforcer) { s.dataScope = e }

// SetAssigneeChecker wires the owner checks.
func (s *TaskService) SetAssigneeChecker(c TaskAssigneeChecker) { s.assignees = c }

// SetAuditLogger wires the audit log.
func (s *TaskService) SetAuditLogger(a TaskAuditLogger) { s.audit = a }

// Errors answered to callers.
var (
	// ErrInvalidTaskAssignee is the one answer for an owner who is not an
	// active member, so the endpoint is no oracle for user ids elsewhere.
	ErrInvalidTaskAssignee = fmt.Errorf("%w: the assignee must be an active member of this organization", shared.ErrValidation)
	// ErrInvalidTaskGroup is the one answer for a group of another
	// organization or none.
	ErrInvalidTaskGroup = fmt.Errorf("%w: the group must be a group of this organization", shared.ErrValidation)
	// ErrTaskFindingNotFound is the one answer for a finding of another
	// organization, of none, or outside the caller's data scope.
	ErrTaskFindingNotFound = fmt.Errorf("%w: one or more findings were not found", shared.ErrNotFound)
	// ErrTaskFindingClosed: a closed finding never joins a task.
	ErrTaskFindingClosed = fmt.Errorf("%w: closed findings cannot join a remediation task", shared.ErrValidation)
	// ErrTaskNoFindings: a task needs at least one finding.
	ErrTaskNoFindings = fmt.Errorf("%w: a remediation task needs at least one finding", shared.ErrValidation)
	// ErrTaskTooManyFindings bounds one request.
	ErrTaskTooManyFindings = fmt.Errorf("%w: at most %d findings per request", shared.ErrValidation, remediationdom.MaxMembersPerRequest)
	// ErrTaskCampaignNotFound: the campaign is not one of this organization.
	ErrTaskCampaignNotFound = fmt.Errorf("%w: the campaign was not found", shared.ErrValidation)
	// ErrTaskVersionRequired: every change names the version it was based on.
	ErrTaskVersionRequired = fmt.Errorf("%w: version is required", shared.ErrValidation)
)

// CreateTaskInput creates a task by hand.
type CreateTaskInput struct {
	TenantID        shared.ID
	ActorID         *shared.ID
	Title           string
	Description     string
	ActionID        *shared.ID // an existing action; nil = a new manual action for this task
	FindingIDs      []shared.ID
	RelatedIDs      []shared.ID
	AssigneeUserID  *shared.ID
	AssigneeGroupID *shared.ID
	CampaignID      *shared.ID
	Deadline        *time.Time
}

// CreateTask creates a task with its findings as primary members.
func (s *TaskService) CreateTask(ctx context.Context, in CreateTaskInput, actx auditapp.AuditContext) (*remediationdom.Task, error) {
	title, err := remediationdom.NormalizeTaskTitle(in.Title)
	if err != nil {
		return nil, err
	}
	desc, err := normalizeDescription(in.Description)
	if err != nil {
		return nil, err
	}
	members, related := dedupeIDs(in.FindingIDs), dedupeIDs(in.RelatedIDs)
	related = withoutIDs(related, members)
	if len(members) == 0 {
		return nil, ErrTaskNoFindings
	}
	if len(members) > remediationdom.MaxMembersPerRequest || len(related) > remediationdom.MaxMembersPerRequest {
		return nil, ErrTaskTooManyFindings
	}
	if err := s.checkFindings(ctx, in.TenantID, append(append([]shared.ID{}, members...), related...), members); err != nil {
		return nil, err
	}
	if err := s.checkOwner(ctx, in.TenantID, in.AssigneeUserID, in.AssigneeGroupID); err != nil {
		return nil, err
	}
	if err := s.checkCampaign(ctx, in.TenantID, in.CampaignID); err != nil {
		return nil, err
	}

	taskID := shared.NewID()
	rec := &remediationdom.NewTaskRecord{
		Task: remediationdom.Task{
			ID: taskID, TenantID: in.TenantID, CampaignID: in.CampaignID, Title: title, Description: desc,
			AssigneeUserID: in.AssigneeUserID, AssigneeGroupID: in.AssigneeGroupID, ManualDeadline: in.Deadline,
			CreatedBy: in.ActorID,
		},
		Members: members, Related: related, Source: remediationdom.JoinSourceManual, ActorID: in.ActorID,
		EventData: map[string]any{"title": title},
	}
	if in.ActionID != nil {
		action, aerr := s.repo.GetAction(ctx, in.TenantID, *in.ActionID)
		if aerr != nil {
			return nil, fmt.Errorf("%w: the remediation action was not found", shared.ErrValidation)
		}
		rec.Action = *action
	} else {
		rec.Action = remediationdom.Action{
			TenantID: in.TenantID, Key: remediationdom.ManualActionKey(taskID), Kind: remediationdom.ActionKindManual,
			Title: title, Origin: remediationdom.ActionOriginManual, CreatedBy: in.ActorID,
		}
	}
	if err := s.repo.CreateTask(ctx, rec); err != nil {
		return nil, err
	}
	task, err := s.repo.GetTask(ctx, in.TenantID, taskID)
	if err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskCreated, auditdom.ResourceTypeRemediationTask, taskID.String()).
		WithResourceName(title).
		WithMessage(fmt.Sprintf("Remediation task %q created with %d finding(s)", title, len(members))).
		WithMetadata("findings", len(members)).WithMetadata("related", len(related)).
		WithMetadata("action_id", task.ActionID.String()))
	return task, nil
}

// checkFindings refuses findings of another tenant or outside the caller's
// scope (one not-found answer for both), and closed findings as primary
// members.
func (s *TaskService) checkFindings(ctx context.Context, tenantID shared.ID, all, primary []shared.ID) error {
	statuses, err := s.repo.FindingStatuses(ctx, tenantID, all)
	if err != nil {
		return err
	}
	if len(statuses) != len(all) {
		return ErrTaskFindingNotFound
	}
	scope, err := s.resolveScope(ctx, tenantID)
	if err != nil {
		return err
	}
	if scope != nil {
		in, ferr := s.dataScope.FilterFindings(ctx, scope, all)
		if ferr != nil {
			return ferr
		}
		for _, id := range all {
			if !in(id) {
				return ErrTaskFindingNotFound
			}
		}
	}
	for _, id := range primary {
		if vulnerability.FindingStatus(statuses[id]).IsClosed() {
			return ErrTaskFindingClosed
		}
	}
	return nil
}

func (s *TaskService) resolveScope(ctx context.Context, tenantID shared.ID) (*shared.DataScope, error) {
	if s.dataScope == nil {
		return nil, nil
	}
	scope, err := s.dataScope.Resolve(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve data scope: %w", err)
	}
	return scope, nil
}

func (s *TaskService) checkOwner(ctx context.Context, tenantID shared.ID, user, group *shared.ID) error {
	if user != nil {
		if s.assignees == nil {
			return ErrInvalidTaskAssignee
		}
		ok, err := s.assignees.IsActiveTenantMember(ctx, tenantID, *user)
		if err != nil {
			return fmt.Errorf("check task assignee: %w", err)
		}
		if !ok {
			return ErrInvalidTaskAssignee
		}
	}
	if group != nil {
		if s.assignees == nil {
			return ErrInvalidTaskGroup
		}
		ok, err := s.assignees.IsGroupInTenant(ctx, tenantID, *group)
		if err != nil {
			return fmt.Errorf("check task group: %w", err)
		}
		if !ok {
			return ErrInvalidTaskGroup
		}
	}
	return nil
}

func (s *TaskService) checkCampaign(ctx context.Context, tenantID shared.ID, campaignID *shared.ID) error {
	if campaignID == nil {
		return nil
	}
	ok, err := s.repo.CampaignInTenant(ctx, tenantID, *campaignID)
	if err != nil {
		return err
	}
	if !ok {
		return ErrTaskCampaignNotFound
	}
	return nil
}

// GetTask returns a task as the caller may see it: a restricted caller sees
// it only when at least one member is in their scope, with the counters over
// those members.
func (s *TaskService) GetTask(ctx context.Context, tenantID, taskID shared.ID) (*remediationdom.Task, error) {
	t, err := s.repo.GetTask(ctx, tenantID, taskID)
	if err != nil {
		return nil, err
	}
	scope, err := s.resolveScope(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if scope == nil {
		return t, nil
	}
	if err := s.applyScope(ctx, tenantID, []*remediationdom.Task{t}, scope); err != nil {
		return nil, err
	}
	if t.Counts.Total == 0 && t.Counts.Related == 0 {
		return nil, remediationdom.ErrTaskNotFound
	}
	return t, nil
}

// applyScope replaces the counters of each task, in memory, with the ones
// over the members in scope, and sets HiddenMembers.
func (s *TaskService) applyScope(ctx context.Context, tenantID shared.ID, tasks []*remediationdom.Task, scope *shared.DataScope) error {
	if len(tasks) == 0 {
		return nil
	}
	ids := make([]shared.ID, len(tasks))
	for i, t := range tasks {
		ids[i] = t.ID
	}
	counts, err := s.repo.ScopedCounts(ctx, tenantID, ids, scope)
	if err != nil {
		return err
	}
	for _, t := range tasks {
		visible := counts[t.ID]
		hidden := t.Counts.Total - visible.Total
		if hidden < 0 {
			hidden = 0
		}
		t.HiddenMembers = hidden
		t.Counts = visible
		if hidden > 0 {
			// The deadline and risk of hidden members are not the caller's
			// to see: show the ones over the visible members.
			dl, src := remediationdom.EffectiveDeadline(visible.MemberDeadline, t.ManualDeadline, nil)
			if t.DeadlineSource != nil && *t.DeadlineSource == remediationdom.DeadlineSourceCampaign {
				dl, src = t.Deadline, t.DeadlineSource
			}
			t.Deadline, t.DeadlineSource = dl, src
		}
	}
	return nil
}

// ListTasksInput lists tasks.
type ListTasksInput struct {
	TenantID shared.ID
	CallerID *shared.ID
	Filter   remediationdom.TaskFilter
	// Mine lists the caller's tasks: assigned to them or to one of their
	// groups.
	Mine bool
}

// ListTasks lists the tasks the caller may see.
func (s *TaskService) ListTasks(ctx context.Context, in ListTasksInput, page pagination.Pagination) (pagination.Result[*remediationdom.Task], error) {
	f := in.Filter
	if in.Mine {
		if in.CallerID == nil {
			return pagination.NewResult([]*remediationdom.Task{}, 0, page), nil
		}
		f.AssigneeID, f.Mine = in.CallerID, true
	}
	scope, err := s.resolveScope(ctx, in.TenantID)
	if err != nil {
		return pagination.Result[*remediationdom.Task]{}, err
	}
	f.Scope = scope
	res, err := s.repo.ListTasks(ctx, in.TenantID, f, page)
	if err != nil {
		return res, err
	}
	if scope != nil {
		if err := s.applyScope(ctx, in.TenantID, res.Data, scope); err != nil {
			return res, err
		}
	}
	return res, nil
}

// writableTask loads a task for a change: visible to the caller and with no
// member outside their scope.
func (s *TaskService) writableTask(ctx context.Context, tenantID, taskID shared.ID) (*remediationdom.Task, error) {
	t, err := s.GetTask(ctx, tenantID, taskID)
	if err != nil {
		return nil, err
	}
	if t.HiddenMembers > 0 {
		return nil, remediationdom.ErrTaskHiddenMembers
	}
	return t, nil
}

// TaskForChange returns a task the caller may change (visible, with no
// member outside their scope): what an action that carries the task
// elsewhere, such as creating its tracker issue, checks first.
func (s *TaskService) TaskForChange(ctx context.Context, tenantID, taskID shared.ID) (*remediationdom.Task, error) {
	return s.writableTask(ctx, tenantID, taskID)
}

// AddMembersInput adds findings to a task.
type AddMembersInput struct {
	TenantID   shared.ID
	TaskID     shared.ID
	ActorID    *shared.ID
	Version    int
	FindingIDs []shared.ID
	Role       remediationdom.MemberRole
}

// AddMembers adds findings to a task, as primary or related members.
func (s *TaskService) AddMembers(ctx context.Context, in AddMembersInput, actx auditapp.AuditContext) (*remediationdom.Task, error) {
	if in.Version <= 0 {
		return nil, ErrTaskVersionRequired
	}
	role := in.Role
	if role == "" {
		role = remediationdom.MemberRolePrimary
	}
	if role != remediationdom.MemberRolePrimary && role != remediationdom.MemberRoleRelated {
		return nil, fmt.Errorf("%w: role must be primary or related", shared.ErrValidation)
	}
	ids := dedupeIDs(in.FindingIDs)
	if len(ids) == 0 {
		return nil, ErrTaskNoFindings
	}
	if len(ids) > remediationdom.MaxMembersPerRequest {
		return nil, ErrTaskTooManyFindings
	}
	if _, err := s.writableTask(ctx, in.TenantID, in.TaskID); err != nil {
		return nil, err
	}
	var primary []shared.ID
	if role == remediationdom.MemberRolePrimary {
		primary = ids
	}
	if err := s.checkFindings(ctx, in.TenantID, ids, primary); err != nil {
		return nil, err
	}
	t, err := s.repo.AddMembers(ctx, in.TenantID, in.TaskID, in.Version, ids, role, remediationdom.JoinSourceManual, in.ActorID)
	if err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskMembersAdded, auditdom.ResourceTypeRemediationTask, t.ID.String()).
		WithResourceName(t.Title).
		WithMessage(fmt.Sprintf("%d finding(s) added to remediation task %q as %s", len(ids), t.Title, role)).
		WithMetadata("findings", len(ids)).WithMetadata("role", string(role)))
	return t, nil
}

// UpdateTaskInput changes a task; nil fields are left as they are.
type UpdateTaskInput struct {
	TenantID    shared.ID
	TaskID      shared.ID
	ActorID     *shared.ID
	Version     int
	Title       *string
	Description *string
	// AssigneeUserID / AssigneeGroupID / Deadline / CampaignID: a pointer
	// to nil clears the value.
	AssigneeUserID  **shared.ID
	AssigneeGroupID **shared.ID
	Deadline        **time.Time
	CampaignID      **shared.ID
	// Hold puts the task on hold (true) or resumes it (false); Cancel
	// cancels it (terminal). StateNote is the reason.
	Hold      *bool
	Cancel    bool
	StateNote string
}

// UpdateTask changes a task's title, description, owner, deadline, campaign
// or manual state, at the caller's version.
func (s *TaskService) UpdateTask(ctx context.Context, in UpdateTaskInput, actx auditapp.AuditContext) (*remediationdom.Task, error) {
	if in.Version <= 0 {
		return nil, ErrTaskVersionRequired
	}
	before, err := s.writableTask(ctx, in.TenantID, in.TaskID)
	if err != nil {
		return nil, err
	}
	ch := remediationdom.TaskChanges{}
	changes := auditdom.NewChanges()
	data := map[string]any{}
	if in.Title != nil {
		title, terr := remediationdom.NormalizeTaskTitle(*in.Title)
		if terr != nil {
			return nil, terr
		}
		if title != before.Title {
			ch.Title = &title
			changes.Set("title", before.Title, title)
			data["title"] = title
		}
	}
	if in.Description != nil {
		desc, derr := normalizeDescription(*in.Description)
		if derr != nil {
			return nil, derr
		}
		if desc != before.Description {
			ch.Description = &desc
			changes.Set("description", "", "changed")
			data["description"] = true
		}
	}
	if in.AssigneeUserID != nil || in.AssigneeGroupID != nil {
		var u, g *shared.ID
		if in.AssigneeUserID != nil {
			u = *in.AssigneeUserID
		}
		if in.AssigneeGroupID != nil {
			g = *in.AssigneeGroupID
		}
		if err := s.checkOwner(ctx, in.TenantID, u, g); err != nil {
			return nil, err
		}
		if in.AssigneeUserID != nil && idStr(u) != idStr(before.AssigneeUserID) {
			ch.AssigneeUserID = in.AssigneeUserID
			changes.Set("assignee_user_id", idStr(before.AssigneeUserID), idStr(u))
			data["assignee_user_id"] = idStr(u)
		}
		if in.AssigneeGroupID != nil && idStr(g) != idStr(before.AssigneeGroupID) {
			ch.AssigneeGroupID = in.AssigneeGroupID
			changes.Set("assignee_group_id", idStr(before.AssigneeGroupID), idStr(g))
			data["assignee_group_id"] = idStr(g)
		}
	}
	if in.Deadline != nil {
		ch.ManualDeadline = in.Deadline
		changes.Set("manual_deadline", timeStr(before.ManualDeadline), timeStr(*in.Deadline))
		data["manual_deadline"] = timeStr(*in.Deadline)
	}
	if in.CampaignID != nil {
		if err := s.checkCampaign(ctx, in.TenantID, *in.CampaignID); err != nil {
			return nil, err
		}
		ch.CampaignID = in.CampaignID
		changes.Set("campaign_id", idStr(before.CampaignID), idStr(*in.CampaignID))
		data["campaign_id"] = idStr(*in.CampaignID)
	}
	kind, action := remediationdom.TaskEventUpdated, auditdom.ActionRemediationTaskUpdated
	if in.Cancel || in.Hold != nil {
		note := strings.TrimSpace(in.StateNote)
		if len(note) > remediationdom.MaxStateNote {
			return nil, fmt.Errorf("%w: the note is longer than %d characters", shared.ErrValidation, remediationdom.MaxStateNote)
		}
		var ms *remediationdom.ManualState
		switch {
		case in.Cancel:
			if note == "" {
				return nil, fmt.Errorf("%w: a reason is required to cancel a task", shared.ErrValidation)
			}
			v := remediationdom.ManualStateCanceled
			ms = &v
		case *in.Hold:
			v := remediationdom.ManualStateOnHold
			ms = &v
		}
		ch.ManualState = &ms
		ch.ManualStateNote = &note
		kind, action = remediationdom.TaskEventStateChanged, auditdom.ActionRemediationTaskStateChanged
		to := "resumed"
		if ms != nil {
			to = string(*ms)
		}
		changes.Set("manual_state", manualStr(before.ManualState), to)
		data["manual_state"], data["note"] = to, note
	}
	if len(data) == 0 {
		return before, nil
	}
	t, err := s.repo.UpdateTask(ctx, in.TenantID, in.TaskID, in.Version, ch, in.ActorID, kind, data)
	if err != nil {
		return nil, err
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(action, auditdom.ResourceTypeRemediationTask, t.ID.String()).
		WithResourceName(t.Title).WithChanges(changes).
		WithMessage(fmt.Sprintf("Remediation task %q updated", t.Title)))
	return t, nil
}

// ListMembers lists a task's members the caller may see.
func (s *TaskService) ListMembers(ctx context.Context, tenantID, taskID shared.ID, f remediationdom.MemberFilter, page pagination.Pagination) (pagination.Result[remediationdom.TaskMember], error) {
	if _, err := s.GetTask(ctx, tenantID, taskID); err != nil {
		return pagination.Result[remediationdom.TaskMember]{}, err
	}
	scope, err := s.resolveScope(ctx, tenantID)
	if err != nil {
		return pagination.Result[remediationdom.TaskMember]{}, err
	}
	f.Scope = scope
	return s.repo.ListMembers(ctx, tenantID, taskID, f, page)
}

// ListEvents lists a task's timeline (the caller must see the task).
func (s *TaskService) ListEvents(ctx context.Context, tenantID, taskID shared.ID, page pagination.Pagination) (pagination.Result[remediationdom.TaskEvent], error) {
	if _, err := s.GetTask(ctx, tenantID, taskID); err != nil {
		return pagination.Result[remediationdom.TaskEvent]{}, err
	}
	return s.repo.ListEvents(ctx, tenantID, taskID, page)
}

// ReconcileBatch is how many stale tasks one reconcile pass recomputes.
const ReconcileBatch = 500

// Reconcile recomputes tasks whose member findings changed since their last
// recompute (a scan closed one, a person claimed a fix, an SLA moved). It
// runs in the background, as the platform.
func (s *TaskService) Reconcile(ctx context.Context) (int, error) {
	refs, err := s.repo.StaleTasksForPlatform(ctx, ReconcileBatch)
	if err != nil {
		return 0, err
	}
	byTenant := map[shared.ID][]shared.ID{}
	for _, r := range refs {
		byTenant[r.TenantID] = append(byTenant[r.TenantID], r.TaskID)
	}
	n := 0
	for tenantID, ids := range byTenant {
		if err := s.repo.Recompute(ctx, tenantID, ids, nil); err != nil {
			s.logger.Warn("remediation task reconcile failed", "tenant", tenantID.String(), "error", logger.SanitizeError(err))
			continue
		}
		n += len(ids)
	}
	return n, nil
}

func (s *TaskService) logAudit(ctx context.Context, actx auditapp.AuditContext, ev auditapp.AuditEvent) {
	if s.audit == nil {
		return
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Warn("remediation task audit failed", "error", logger.SanitizeError(err))
	}
}

func normalizeDescription(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) > remediationdom.MaxTaskDescription {
		return "", fmt.Errorf("%w: description is longer than %d characters", shared.ErrValidation, remediationdom.MaxTaskDescription)
	}
	return s, nil
}

func dedupeIDs(ids []shared.ID) []shared.ID {
	seen := make(map[shared.ID]bool, len(ids))
	out := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		if id.IsZero() || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

func withoutIDs(ids, remove []shared.ID) []shared.ID {
	drop := make(map[shared.ID]bool, len(remove))
	for _, id := range remove {
		drop[id] = true
	}
	out := make([]shared.ID, 0, len(ids))
	for _, id := range ids {
		if !drop[id] {
			out = append(out, id)
		}
	}
	return out
}

func idStr(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func timeStr(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func manualStr(m *remediationdom.ManualState) string {
	if m == nil {
		return ""
	}
	return string(*m)
}
