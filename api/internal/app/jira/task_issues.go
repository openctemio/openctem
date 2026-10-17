package jira

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
	"github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/safetext"
)

// Task issues (research 157 P1-1, one issue per remediation task by default;
// docs/rfcs/RFC-098-remediation-tasks.md). A person creates the issue of a
// task; the platform then keeps the issue's status in step with the task's
// derived state and comments every move with the task's progress. Moves in
// the tracker come back through the inbound webhook as status changes of the
// task's open findings (Done is a fix claim for each of them), never as a
// task state written directly.

// TaskAccess loads a task the caller may change: every member in the
// caller's data scope (implemented by remediation.TaskService). The issue
// carries the task to the tracker, so creating it is a change of the task.
type TaskAccess interface {
	TaskForChange(ctx context.Context, tenantID, taskID shared.ID) (*remediation.Task, error)
	// GetTask returns the task when the caller sees at least one member.
	GetTask(ctx context.Context, tenantID, taskID shared.ID) (*remediation.Task, error)
}

// TaskReader loads a task and its open primary members as the platform (the
// background sync and the inbound webhook have no caller scope).
type TaskReader interface {
	GetTask(ctx context.Context, tenantID, taskID shared.ID) (*remediation.Task, error)
	// OpenMemberIDs lists the task's active primary members (at most limit).
	OpenMemberIDs(ctx context.Context, tenantID, taskID shared.ID, limit int) ([]shared.ID, error)
}

// SetTaskSources wires the task access check and the platform task reader.
func (s *SyncService) SetTaskSources(access TaskAccess, reader TaskReader) {
	s.taskAccess, s.taskReader = access, reader
}

// SetWebBaseURL sets the console's base URL for links back to OpenCTEM.
func (s *SyncService) SetWebBaseURL(u string) { s.webBase = strings.TrimRight(u, "/") }

// ErrTaskHasIssue: the task already has its issue (one issue per task).
var ErrTaskHasIssue = fmt.Errorf("%w: the task already has an issue", shared.ErrConflict)

// ErrTaskClosedForIssue: a canceled or archived task gets no new issue.
var ErrTaskClosedForIssue = fmt.Errorf("%w: a canceled or archived task gets no new issue", shared.ErrValidation)

// taskCreateLock bounds how long a create of a task's issue holds the
// per-task guard (two clicks create one issue).
const taskCreateLock = 30 * time.Second

// CreateTaskIssueInput asks for a task's issue.
type CreateTaskIssueInput struct {
	TenantID   shared.ID
	TaskID     shared.ID
	ProjectKey string // "" = the integration's default project
	By         *shared.ID
}

// CreateTaskIssue creates the task's issue in the tracker and records the
// link. The project must be one configured for ticketing.
func (s *SyncService) CreateTaskIssue(ctx context.Context, in CreateTaskIssueInput) (*ticketlink.Link, error) {
	if s.links == nil || s.taskAccess == nil {
		return nil, fmt.Errorf("%w: task issues are not configured", shared.ErrValidation)
	}
	task, err := s.taskAccess.TaskForChange(ctx, in.TenantID, in.TaskID)
	if err != nil {
		return nil, err
	}
	if task.State == remediation.TaskStateCanceled || task.State == remediation.TaskStateArchived {
		return nil, ErrTaskClosedForIssue
	}
	existing, err := s.links.ListForTask(ctx, in.TenantID, in.TaskID)
	if err != nil {
		return nil, err
	}
	for _, l := range existing {
		if l.State == ticketlink.StateActive && l.Role == ticketlink.RoleOwn {
			return nil, ErrTaskHasIssue
		}
	}
	client, err := s.resolveClient(ctx, in.TenantID)
	if err != nil {
		return nil, err
	}
	ii, ok := client.(IssueIdentifier)
	if !ok {
		return nil, ErrLinksUnavailable
	}
	project := strings.ToUpper(strings.TrimSpace(in.ProjectKey))
	if project == "" {
		project = strings.ToUpper(s.resolveMapping(ctx, in.TenantID).DefaultProjectKey)
	}
	if project == "" {
		return nil, fmt.Errorf("%w: choose a project (the integration has no default project)", shared.ErrValidation)
	}
	allowed, err := s.allowedProjects(ctx, in.TenantID, ii.IntegrationID())
	if err != nil {
		return nil, err
	}
	if !allowed[project] {
		return nil, ErrProjectNotConfigured
	}
	if s.refusalGuard != nil {
		first, err := s.refusalGuard.FirstDelivery(ctx, "jira-task-create:"+in.TenantID.String()+":"+in.TaskID.String(), taskCreateLock)
		if err != nil {
			return nil, fmt.Errorf("guard the task issue create: %w", err)
		}
		if !first {
			return nil, ErrTaskHasIssue
		}
	}

	res, err := client.CreateIssue(ctx, CreateIssueInput{
		ProjectKey:  project,
		Summary:     taskIssueSummary(task),
		Description: s.taskIssueDescription(task),
		IssueType:   s.resolveMapping(ctx, in.TenantID).DefaultIssueType,
		Labels:      []string{"openctem", "openctem-task"},
	})
	if err != nil {
		return nil, fmt.Errorf("create the task's issue: %w", err)
	}
	l, err := ticketlink.New(in.TenantID, ii.IntegrationID(), ticketlink.ForTask(in.TaskID), res.Key, res.ID,
		ii.SiteURL(), ticketlink.BrowseURL(ii.SiteURL(), res.Key), ticketlink.RoleOwn, ticketlink.SourcePerson, in.By)
	if err == nil {
		// The issue starts where the task is: nothing to push until it moves.
		l.LastPushedState = string(task.State)
		err = s.links.Create(ctx, l)
	}
	if err != nil {
		s.logger.Error("create task issue: the issue exists but its link was not recorded",
			"task_id", in.TaskID.String(), "issue_key", res.Key, "error", err)
		return nil, fmt.Errorf("issue %s was created but could not be recorded on the task; link it again: %w", res.Key, err)
	}
	return l, nil
}

// TaskVisible returns the task when the caller may see it (a member in
// their data scope); not found otherwise.
func (s *SyncService) TaskVisible(ctx context.Context, tenantID, taskID shared.ID) (*remediation.Task, error) {
	if s.taskAccess == nil {
		return nil, fmt.Errorf("%w: task issues are not configured", shared.ErrValidation)
	}
	return s.taskAccess.GetTask(ctx, tenantID, taskID)
}

// TaskLinks lists a task's links.
func (s *SyncService) TaskLinks(ctx context.Context, tenantID, taskID shared.ID) ([]*ticketlink.Link, error) {
	if s.links == nil {
		return []*ticketlink.Link{}, nil
	}
	return s.links.ListForTask(ctx, tenantID, taskID)
}

// taskStatusTargets is where the built-in map moves a task's issue (a
// workflow status name). A state without a target only comments.
var taskStatusTargets = map[remediation.TaskState]string{
	remediation.TaskStateInProgress:       "In Progress",
	remediation.TaskStateDone:             "Done",
	remediation.TaskStateClosedUnverified: "Done",
}

// TaskChanged pushes a task's state to its issue now (the hook a task change
// may call; the task ticket controller catches up otherwise). Best effort.
func (s *SyncService) TaskChanged(ctx context.Context, tenantID, taskID shared.ID) {
	if err := s.SyncTaskIssue(ctx, tenantID, taskID); err != nil {
		s.logger.Warn("task issue sync failed", "task_id", taskID.String(), "error", err)
	}
}

// SyncTaskIssue moves the task's issue to the status of the task's state and
// comments the move with the task's progress, once per state change. A
// workflow that offers no such move gets the comment alone. A transient
// tracker error is returned (retried by the next pass); the state is then
// not recorded as pushed.
func (s *SyncService) SyncTaskIssue(ctx context.Context, tenantID, taskID shared.ID) error {
	if s.links == nil || s.taskReader == nil {
		return nil
	}
	links, err := s.links.ListForTask(ctx, tenantID, taskID)
	if err != nil {
		return err
	}
	var link *ticketlink.Link
	for _, l := range links {
		if l.State == ticketlink.StateActive && l.Role == ticketlink.RoleOwn {
			link = l
			break
		}
	}
	if link == nil {
		return nil
	}
	task, err := s.taskReader.GetTask(ctx, tenantID, taskID)
	if err != nil {
		return err
	}
	if string(task.State) == link.LastPushedState {
		return nil
	}
	client, err := s.resolveClient(ctx, tenantID)
	if err != nil {
		return err
	}
	if ii, ok := client.(IssueIdentifier); ok && ii.IntegrationID() != link.IntegrationID {
		// The tenant's integration changed: this link's issue is not on it.
		return s.links.RecordSync(ctx, tenantID, link.ID, link.LastStatus, "the issue belongs to another integration", time.Now().UTC())
	}

	comment := taskMoveComment(task)
	status := link.LastStatus
	if target, ok := taskStatusTargets[task.State]; ok {
		terr := client.TransitionToStatus(ctx, link.ExternalKey, target, comment)
		switch {
		case terr == nil:
			status = target
		case errors.Is(terr, ErrNoMatchingTransition) || isPermanent(terr):
			// The workflow has no such move: the comment still tells the
			// people on the issue.
			if cerr := client.AddComment(ctx, link.ExternalKey, comment); cerr != nil && !isPermanent(cerr) {
				return cerr
			}
		default:
			_ = s.links.RecordSync(ctx, tenantID, link.ID, link.LastStatus, safetext.SingleLine(terr.Error(), 200), time.Now().UTC())
			return terr
		}
	} else if cerr := client.AddComment(ctx, link.ExternalKey, comment); cerr != nil && !isPermanent(cerr) {
		return cerr
	}
	s.logger.Info("task issue synced", "task_id", taskID.String(), "issue_key", logger.SanitizeValue(link.ExternalKey), "state", task.State)
	return s.links.RecordPush(ctx, tenantID, link.ID, string(task.State), status, time.Now().UTC())
}

func isPermanent(err error) bool {
	var p interface{ Permanent() bool }
	return errors.As(err, &p) && p.Permanent()
}

// taskIssueSummary is the issue summary: the task title, one line, capped.
func taskIssueSummary(t *remediation.Task) string {
	return safetext.SingleLine(safetext.RedactSecrets(t.Title), safetext.MaxTitleRunes)
}

// taskIssueDescription is the issue description: what the task fixes, how
// many findings, the deadline and a link back. It names no finding (the data
// level is a summary): the findings are in OpenCTEM, behind its data scope.
func (s *SyncService) taskIssueDescription(t *remediation.Task) string {
	inline := func(v string) string {
		return safetext.JiraWikiInline(safetext.RedactSecrets(v), safetext.MaxInlineRunes)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "*Remediation task:* %s\n", inline(t.Title))
	if t.ActionTitle != "" {
		fmt.Fprintf(&b, "*Fix:* %s\n", inline(t.ActionTitle))
	}
	fmt.Fprintf(&b, "*Findings:* %d\n", t.Counts.Total)
	if t.Deadline != nil {
		fmt.Fprintf(&b, "*Due:* %s\n", t.Deadline.UTC().Format("2006-01-02"))
	}
	if desc := strings.TrimSpace(t.Description); desc != "" {
		b.WriteString("\n")
		b.WriteString(safetext.JiraWikiBlock(safetext.RedactSecrets(desc), safetext.MaxDescriptionRunes))
		b.WriteString("\n")
	}
	if s.webBase != "" {
		fmt.Fprintf(&b, "\nOpen the task in OpenCTEM: %s/remediation/tasks/%s\n", s.webBase, t.ID.String())
	}
	b.WriteString("\nMoving this issue to Done claims the fix of the task's open findings; OpenCTEM verifies each of them (a retest, a covered scan or a reviewer).")
	return b.String()
}

// taskStateLabels name a task state in an issue comment.
var taskStateLabels = map[remediation.TaskState]string{
	remediation.TaskStateOpen:             "open",
	remediation.TaskStateInProgress:       "in progress",
	remediation.TaskStateVerifying:        "verifying (every open finding has a fix claim)",
	remediation.TaskStateDone:             "done (every finding closed, fixes verified)",
	remediation.TaskStateClosedUnverified: "closed without a verified fix",
	remediation.TaskStateOnHold:           "on hold",
	remediation.TaskStateCanceled:         "canceled",
	remediation.TaskStateArchived:         "archived",
}

// taskMoveComment is the comment posted with a task's move: the new state,
// the task's progress and, for a person's hold or cancel, nothing more (the
// note stays in OpenCTEM).
func taskMoveComment(t *remediation.Task) string {
	label := taskStateLabels[t.State]
	if label == "" {
		label = string(t.State)
	}
	c := t.Counts
	return fmt.Sprintf("OpenCTEM: the remediation task is now %s.\n\nProgress: %d of %d findings closed (%d verified fixed), %d fix claimed (verifying), %d in progress, %d open.",
		label, c.Closed, c.Total, c.Verified, c.FixApplied, c.InProgress, c.Open)
}

// linkedFindingsOf lists the findings an issue's status change applies to:
// the findings linked to the issue, and the open primary members of the
// tasks whose issue it is. A task issue's change that is the echo of our own
// push (the status we moved it to, within the echo window) applies to none
// of the task's members.
func (s *SyncService) linkedFindingsOf(ctx context.Context, tenantID shared.ID, payload WebhookPayload, jiraStatus string) ([]shared.ID, error) {
	ids, err := s.linkedFindings(ctx, tenantID, deriveJiraTicketURL(payload.Issue))
	if err != nil {
		return nil, err
	}
	if s.links == nil || s.taskReader == nil {
		return ids, nil
	}
	client, err := s.resolveClient(ctx, tenantID)
	if err != nil {
		return ids, nil //nolint:nilerr // no integration: the findings path reports it
	}
	ii, ok := client.(IssueIdentifier)
	if !ok {
		return ids, nil
	}
	links, err := s.links.FindByIssue(ctx, tenantID, ii.IntegrationID(), strings.ToUpper(payload.Issue.Key))
	if err != nil {
		return nil, fmt.Errorf("lookup the issue's task links: %w", err)
	}
	seen := make(map[shared.ID]bool, len(ids))
	for _, id := range ids {
		seen[id] = true
	}
	now := time.Now()
	for _, l := range links {
		if l.TaskID == nil || l.Role != ticketlink.RoleOwn {
			continue
		}
		if isTaskEcho(l, jiraStatus, now) {
			s.logger.Debug("jira webhook: echo of our own task issue move; ignored", "issue_key", logger.SanitizeValue(payload.Issue.Key))
			continue
		}
		members, err := s.taskReader.OpenMemberIDs(ctx, tenantID, *l.TaskID, maxInboundFindings)
		if err != nil {
			return nil, fmt.Errorf("list the task's findings: %w", err)
		}
		for _, id := range members {
			if !seen[id] && len(ids) < maxInboundFindings {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	return ids, nil
}

// isTaskEcho reports whether a task issue's change is the echo of the move
// the platform made: the status we last pushed, within the echo window.
func isTaskEcho(l *ticketlink.Link, jiraStatus string, now time.Time) bool {
	if l.LastStatus == "" || l.LastSyncedAt == nil || !strings.EqualFold(l.LastStatus, jiraStatus) {
		return false
	}
	return now.Sub(*l.LastSyncedAt) <= ticketmap.EchoWindow
}
