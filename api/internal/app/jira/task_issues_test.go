package jira

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type taskStore struct {
	tasks   map[shared.ID]*remediation.Task
	members map[shared.ID][]shared.ID
	denied  bool // TaskForChange refuses (a member outside the caller's scope)
}

func (s *taskStore) TaskForChange(_ context.Context, _, id shared.ID) (*remediation.Task, error) {
	if s.denied {
		return nil, remediation.ErrTaskHiddenMembers
	}
	return s.GetTask(context.Background(), shared.ID{}, id)
}
func (s *taskStore) GetTask(_ context.Context, _, id shared.ID) (*remediation.Task, error) {
	t, ok := s.tasks[id]
	if !ok {
		return nil, remediation.ErrTaskNotFound
	}
	return t, nil
}
func (s *taskStore) OpenMemberIDs(_ context.Context, _, id shared.ID, _ int) ([]shared.ID, error) {
	return s.members[id], nil
}

type onceGuard struct{ seen map[string]bool }

func (g *onceGuard) FirstDelivery(_ context.Context, key string, _ time.Duration) (bool, error) {
	if g.seen == nil {
		g.seen = map[string]bool{}
	}
	if g.seen[key] {
		return false, nil
	}
	g.seen[key] = true
	return true, nil
}

type noURLLinks struct{}

func (noURLLinks) ListIDsByWorkItemURI(context.Context, shared.ID, string, int) ([]shared.ID, error) {
	return nil, nil
}

func newTask(state remediation.TaskState) *remediation.Task {
	d := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	return &remediation.Task{ID: shared.NewID(), Title: "Upgrade openssl on the edge hosts", ActionTitle: "openssl >= 3.0.15",
		State: state, Deadline: &d, Counts: remediation.TaskCounts{Total: 4, Open: 2, InProgress: 1, FixApplied: 1}}
}

func taskSync(t *testing.T, task *remediation.Task) (*SyncService, *linkClient, *memLinks, *taskStore) {
	t.Helper()
	c := &linkClient{intg: shared.NewID()}
	s := newSync(&stubFindingRepo{finding: buildFinding(t)}, c)
	links := &memLinks{}
	s.SetLinkStore(links)
	configured(s)
	store := &taskStore{tasks: map[shared.ID]*remediation.Task{task.ID: task}, members: map[shared.ID][]shared.ID{}}
	s.SetTaskSources(store, store)
	s.SetRefusalCommentGuard(&onceGuard{})
	s.SetWebBaseURL("https://console.example/")
	return s, c, links, store
}

func TestCreateTaskIssue(t *testing.T) {
	task := newTask(remediation.TaskStateInProgress)
	s, c, links, _ := taskSync(t, task)
	tid, by := shared.NewID(), shared.NewID()

	l, err := s.CreateTaskIssue(context.Background(), CreateTaskIssueInput{TenantID: tid, TaskID: task.ID, By: &by})
	if err != nil {
		t.Fatal(err)
	}
	if c.lastInput.ProjectKey != "SEC" || c.lastInput.Summary != task.Title {
		t.Fatalf("created %+v", c.lastInput)
	}
	desc := c.lastInput.Description
	for _, want := range []string{"openssl >= 3.0.15", "*Findings:* 4", "2026-11-01", "https://console.example/remediation/tasks/" + task.ID.String(), "claims the fix"} {
		if !strings.Contains(desc, want) {
			t.Errorf("description lacks %q:\n%s", want, desc)
		}
	}
	if l.TaskID == nil || *l.TaskID != task.ID || l.FindingID != nil || l.Source != ticketlink.SourcePerson || *l.CreatedBy != by {
		t.Fatalf("link %+v", l)
	}
	if l.LastPushedState != string(remediation.TaskStateInProgress) || len(links.rows) != 1 {
		t.Fatalf("pushed state %q, %d links", l.LastPushedState, len(links.rows))
	}

	// One issue per task.
	if _, err := s.CreateTaskIssue(context.Background(), CreateTaskIssueInput{TenantID: tid, TaskID: task.ID}); !errors.Is(err, ErrTaskHasIssue) {
		t.Fatalf("second issue: %v", err)
	}
	if c.calls != 1 {
		t.Fatalf("tracker called %d times", c.calls)
	}
}

func TestCreateTaskIssue_Refusals(t *testing.T) {
	ctx := context.Background()
	tid := shared.NewID()

	// A member outside the caller's scope: no issue, no tracker call.
	task := newTask(remediation.TaskStateOpen)
	s, c, _, store := taskSync(t, task)
	store.denied = true
	if _, err := s.CreateTaskIssue(ctx, CreateTaskIssueInput{TenantID: tid, TaskID: task.ID}); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("out of scope: %v", err)
	}
	// A project that is not configured for ticketing.
	store.denied = false
	if _, err := s.CreateTaskIssue(ctx, CreateTaskIssueInput{TenantID: tid, TaskID: task.ID, ProjectKey: "hr"}); !errors.Is(err, ErrProjectNotConfigured) {
		t.Fatalf("HR project: %v", err)
	}
	// An unknown task.
	if _, err := s.CreateTaskIssue(ctx, CreateTaskIssueInput{TenantID: tid, TaskID: shared.NewID()}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("unknown task: %v", err)
	}
	// A canceled task.
	task.State = remediation.TaskStateCanceled
	if _, err := s.CreateTaskIssue(ctx, CreateTaskIssueInput{TenantID: tid, TaskID: task.ID}); !errors.Is(err, ErrTaskClosedForIssue) {
		t.Fatalf("canceled: %v", err)
	}
	if c.calls != 0 {
		t.Fatalf("tracker called %d times for refused requests", c.calls)
	}

	// Two clicks at once: the guard lets one through.
	task.State = remediation.TaskStateOpen
	s.SetRefusalCommentGuard(&onceGuard{seen: map[string]bool{"jira-task-create:" + tid.String() + ":" + task.ID.String(): true}})
	if _, err := s.CreateTaskIssue(ctx, CreateTaskIssueInput{TenantID: tid, TaskID: task.ID}); !errors.Is(err, ErrTaskHasIssue) {
		t.Fatalf("concurrent create: %v", err)
	}
}

func linkedTask(t *testing.T, state remediation.TaskState) (*SyncService, *linkClient, *memLinks, *remediation.Task, shared.ID) {
	t.Helper()
	task := newTask(state)
	s, c, links, _ := taskSync(t, task)
	tid := shared.NewID()
	if _, err := s.CreateTaskIssue(context.Background(), CreateTaskIssueInput{TenantID: tid, TaskID: task.ID}); err != nil {
		t.Fatal(err)
	}
	return s, c, links, task, tid
}

func TestSyncTaskIssue_MovesAndComments(t *testing.T) {
	s, c, links, task, tid := linkedTask(t, remediation.TaskStateOpen)

	// Unchanged: nothing is sent.
	if err := s.SyncTaskIssue(context.Background(), tid, task.ID); err != nil || len(c.transitions)+len(c.comments) != 0 {
		t.Fatalf("unchanged: %v %v %v", err, c.transitions, c.comments)
	}

	// In progress: moved, with the progress comment carried on the move.
	task.State = remediation.TaskStateInProgress
	if err := s.SyncTaskIssue(context.Background(), tid, task.ID); err != nil {
		t.Fatal(err)
	}
	if len(c.transitions) != 1 || c.transitions[0] != "In Progress" || links.rows[0].LastPushedState != "in_progress" || links.rows[0].LastStatus != "In Progress" {
		t.Fatalf("moves %v, link %+v", c.transitions, links.rows[0])
	}
	// Pushed once: a second pass sends nothing.
	if err := s.SyncTaskIssue(context.Background(), tid, task.ID); err != nil || len(c.transitions) != 1 {
		t.Fatalf("repeat: %v %v", err, c.transitions)
	}

	// Verifying has no status: a comment alone, with the progress.
	task.State = remediation.TaskStateVerifying
	if err := s.SyncTaskIssue(context.Background(), tid, task.ID); err != nil {
		t.Fatal(err)
	}
	if len(c.transitions) != 1 || len(c.comments) != 1 || !strings.Contains(c.comments[0], "verifying") || !strings.Contains(c.comments[0], "1 fix claimed") {
		t.Fatalf("verifying: moves %v comments %v", c.transitions, c.comments)
	}

	// The workflow has no Done move: the comment still goes, the state counts as pushed.
	task.State = remediation.TaskStateDone
	c.transitionErr = ErrNoMatchingTransition
	if err := s.SyncTaskIssue(context.Background(), tid, task.ID); err != nil {
		t.Fatal(err)
	}
	if len(c.comments) != 2 || links.rows[0].LastPushedState != "done" {
		t.Fatalf("no Done move: comments %v link %+v", c.comments, links.rows[0])
	}
}

func TestSyncTaskIssue_TransientErrorIsRetried(t *testing.T) {
	s, c, links, task, tid := linkedTask(t, remediation.TaskStateOpen)
	task.State = remediation.TaskStateInProgress
	c.transitionErr = errors.New("tracker unavailable")
	if err := s.SyncTaskIssue(context.Background(), tid, task.ID); err == nil {
		t.Fatal("want the transient error")
	}
	if links.rows[0].LastPushedState != "open" {
		t.Fatalf("a failed push was recorded as pushed: %+v", links.rows[0])
	}
}

// A person moving the task's issue to Done claims the fix of the task's open
// findings; the echo of our own move does not.
func TestTaskIssueDone_ClaimsTheMembersFix(t *testing.T) {
	s, c, links, task, tid := linkedTask(t, remediation.TaskStateInProgress)
	m1, m2 := shared.NewID(), shared.NewID()
	store := &taskStore{tasks: map[shared.ID]*remediation.Task{task.ID: task}, members: map[shared.ID][]shared.ID{task.ID: {m1, m2}}}
	s.SetTaskSources(store, store)
	app := &applierStub{}
	s.SetInboundApplier(app)
	// The issue is in a configured project (the stub tracker answered PROJ-999).
	links.rows[0].ExternalKey, links.rows[0].ProjectKey = "SEC-77", "SEC"
	// No finding is linked by URL to this issue.
	s.SetWorkItemFindingLister(noURLLinks{})
	payload := WebhookPayload{
		Issue:     WebhookIssue{Key: links.rows[0].ExternalKey, Self: "https://acme.atlassian.net/rest/api/2/issue/1"},
		Changelog: &Changelog{Items: []ChangeItem{{Field: "status", ToString: "Done"}}},
	}
	if err := s.HandleJiraWebhook(context.Background(), tid, payload); err != nil {
		t.Fatal(err)
	}
	if app.target != vulnerability.FindingStatusFixApplied || len(app.ids) != 2 {
		t.Fatalf("applied %q to %v", app.target, app.ids)
	}

	// Our own push to Done comes back: ignored.
	now := time.Now()
	links.rows[0].LastStatus, links.rows[0].LastSyncedAt = "Done", &now
	app.ids, app.target = nil, ""
	if err := s.HandleJiraWebhook(context.Background(), tid, payload); err != nil {
		t.Fatal(err)
	}
	if len(app.ids) != 0 {
		t.Fatalf("the echo applied to %v", app.ids)
	}
	_ = c
}
