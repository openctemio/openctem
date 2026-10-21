package jira

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketlink"
	"github.com/openctemio/openctem/api/pkg/domain/ticketmap"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// The owner's example: findings as "Security Finding", tasks as
// "Remediation Task", campaigns as "Initiative", all custom types of SEC.
func ownerMapping() MappingConfig {
	m := DefaultMappingConfig()
	m.DefaultProjectKey = "SEC"
	m.IssueTypes = map[string]IssueTypeChoice{
		IssueKindFinding: {ID: "10042", Name: "Security Finding"},
		IssueKindTask:    {ID: "10043", Name: "Remediation Task"},
		IssueKindEpic:    {ID: "10045", Name: "Initiative"},
	}
	return m
}

func TestIssueTypeFor(t *testing.T) {
	m := ownerMapping()
	cases := []struct {
		kind, project string
		want          IssueTypeRef
	}{
		{IssueKindFinding, "SEC", IssueTypeRef{ID: "10042", Name: "Security Finding"}},
		{IssueKindFinding, "sec", IssueTypeRef{ID: "10042", Name: "Security Finding"}}, // keys are case-insensitive
		{IssueKindTask, "SEC", IssueTypeRef{ID: "10043", Name: "Remediation Task"}},
		// Another project (a routing rule): its ids may differ, so by name.
		{IssueKindTask, "PAY", IssueTypeRef{Name: "Remediation Task"}},
		{IssueKindEpic, "SEC", IssueTypeRef{ID: "10045", Name: "Initiative"}},
	}
	for _, tc := range cases {
		if got := m.IssueTypeFor(tc.kind, tc.project); got != tc.want {
			t.Errorf("%s in %s: %+v, want %+v", tc.kind, tc.project, got, tc.want)
		}
	}
	// Nothing chosen: the stock type of each kind.
	d := DefaultMappingConfig()
	for kind, want := range map[string]string{IssueKindFinding: "Bug", IssueKindTask: "Task", IssueKindEpic: "Epic"} {
		if got := d.IssueTypeFor(kind, "SEC"); got != (IssueTypeRef{Name: want}) {
			t.Errorf("default %s: %+v", kind, got)
		}
	}
	// An id with no name, in another project: the stock type, never the id.
	d.DefaultProjectKey = "SEC"
	d.IssueTypes = map[string]IssueTypeChoice{IssueKindTask: {ID: "10043"}}
	if got := d.IssueTypeFor(IssueKindTask, "PAY"); got != (IssueTypeRef{Name: "Task"}) {
		t.Errorf("id without name elsewhere: %+v", got)
	}
}

func TestParseIssueTypes_SkipsMalformedEntries(t *testing.T) {
	m := ParseMappingConfig(map[string]any{"ticketing": map[string]any{"issue_types": map[string]any{
		"finding": map[string]any{"id": "10042", "name": " Security Finding "},
		"task":    map[string]any{"id": "abc", "name": "Remediation Task"}, // id not a number: name only
		"risk":    map[string]any{"id": "1", "name": "Risk"},               // unknown kind
		"epic":    "Epic",                                                  // not an object
	}}})
	if m.IssueTypes[IssueKindFinding] != (IssueTypeChoice{ID: "10042", Name: "Security Finding"}) ||
		m.IssueTypes[IssueKindTask] != (IssueTypeChoice{Name: "Remediation Task"}) || len(m.IssueTypes) != 2 {
		t.Fatalf("parsed %+v", m.IssueTypes)
	}
	// The single issue type of before is gone (migrated): it changes nothing.
	old := ParseMappingConfig(map[string]any{"ticketing": map[string]any{"issue_type": "Story"}})
	if old.IssueTypeFor(IssueKindFinding, "SEC").Name != "Bug" {
		t.Fatal("issue_type must no longer be read")
	}
}

func TestValidateTicketingConfig_IssueTypes(t *testing.T) {
	ok := map[string]any{"ticketing": map[string]any{"issue_types": map[string]any{
		"finding": map[string]any{"id": "10042", "name": "Security Finding"},
		"task":    map[string]any{"name": "Task"},
	}}}
	if err := ValidateTicketingConfig(ok); err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	for name, it := range map[string]any{
		"not an object":    "Bug",
		"unknown kind":     map[string]any{"risk": map[string]any{"name": "Risk"}},
		"entry not object": map[string]any{"task": "Task"},
		"unknown key":      map[string]any{"task": map[string]any{"name": "Task", "fields": "x"}},
		"id not a number":  map[string]any{"task": map[string]any{"id": "10043;drop"}},
		"id not a string":  map[string]any{"task": map[string]any{"id": 10043}},
		"name too long":    map[string]any{"task": map[string]any{"name": strings.Repeat("x", 300)}},
	} {
		err := ValidateTicketingConfig(map[string]any{"ticketing": map[string]any{"issue_types": it}})
		if !errors.Is(err, shared.ErrValidation) {
			t.Errorf("%s: want a validation error, got %v", name, err)
		}
	}
}

func TestIssueTypesChanged(t *testing.T) {
	base := map[string]any{"ticketing": map[string]any{"project_key": "SEC", "issue_types": map[string]any{
		"task": map[string]any{"id": "10043", "name": "Remediation Task"}}, "default_priority": "P3"}}
	same := map[string]any{"ticketing": map[string]any{"project_key": "sec", "issue_types": map[string]any{
		"task": map[string]any{"id": "10043", "name": "Remediation Task"}}, "default_priority": "P1"}}
	if IssueTypesChanged(base, same) {
		t.Fatal("a priority change does not need the issue type check")
	}
	if !IssueTypesChanged(base, map[string]any{"ticketing": map[string]any{"project_key": "PAY", "issue_types": base["ticketing"].(map[string]any)["issue_types"]}}) {
		t.Fatal("a new default project changes what the ids mean")
	}
	if !IssueTypesChanged(base, map[string]any{"ticketing": map[string]any{"project_key": "SEC", "issue_types": map[string]any{
		"task": map[string]any{"id": "10044", "name": "Remediation Task"}}}}) {
		t.Fatal("a new id must be checked")
	}
	if !IssueTypesChanged(nil, base) {
		t.Fatal("a new integration with issue types must be checked")
	}
}

// refusingClient is an integration client whose built-in create refuses (or
// not) with the configured error.
type refusingClient struct {
	linkClient
	err error
}

func (c *refusingClient) CreateIssue(ctx context.Context, in CreateIssueInput) (*CreateIssueResult, error) {
	res, _ := c.linkClient.CreateIssue(ctx, in)
	if c.err != nil {
		return nil, c.err
	}
	return res, nil
}

type healthStub struct {
	kinds    []string
	problems []*IssueTypeProblem
}

func (h *healthStub) RecordIssueTypeProblem(_ context.Context, _, _ shared.ID, kind string, p *IssueTypeProblem) error {
	h.kinds, h.problems = append(h.kinds, kind), append(h.problems, p)
	return nil
}

func TestCreateTicket_SendsTheFindingTypeByIDInTheDefaultProject(t *testing.T) {
	c := &refusingClient{linkClient: linkClient{intg: shared.NewID()}}
	s := newSync(&stubFindingRepo{finding: buildFinding(t)}, c)
	s.SetMappingResolver(stubMappingResolver{mapping: ownerMapping()})
	if _, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{TenantID: shared.NewID().String(), FindingID: shared.NewID().String()}); err != nil {
		t.Fatal(err)
	}
	if c.lastInput.IssueTypeID != "10042" || c.lastInput.IssueType != "Security Finding" || c.lastInput.ProjectKey != "SEC" {
		t.Fatalf("created %+v", c.lastInput)
	}

	// A routed project gets the type by name.
	m := ownerMapping()
	m.Routing = []RoutingRule{{Severity: []string{"high"}, ProjectKey: "PAY"}}
	s.SetMappingResolver(stubMappingResolver{mapping: m})
	if _, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{TenantID: shared.NewID().String(), FindingID: shared.NewID().String()}); err != nil {
		t.Fatal(err)
	}
	if c.lastInput.ProjectKey != "PAY" || c.lastInput.IssueTypeID != "" || c.lastInput.IssueType != "Security Finding" {
		t.Fatalf("routed: %+v", c.lastInput)
	}
}

func TestCreateTicket_ProfileIsLookedUpByTheChosenTypeID(t *testing.T) {
	c := &profileClient{integration: shared.NewID()}
	prof := &stubProfiles{create: &ProfileCreate{ProfileID: shared.NewID(), IssueTypeID: "10042", Fields: map[string]any{"summary": "s", "customfield_10050": "Payments"}}}
	s := newSync(&stubFindingRepo{finding: buildFinding(t)}, c)
	s.SetMappingResolver(stubMappingResolver{mapping: ownerMapping()})
	s.SetProfileSource(prof)
	if _, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{TenantID: shared.NewID().String(), FindingID: shared.NewID().String()}); err != nil {
		t.Fatal(err)
	}
	if prof.gotType != "10042" || c.createdType != "10042" || c.calls != 0 {
		t.Fatalf("profile looked up with %q, created as %q, built-in calls %d", prof.gotType, c.createdType, c.calls)
	}

	// The tracker refuses a field: the profile is marked drifted and the
	// caller gets a validation error naming the field.
	c.createErr = NewFieldRejectedError([]string{"customfield_10050"})
	s = newSync(&stubFindingRepo{finding: buildFinding(t)}, c)
	s.SetMappingResolver(stubMappingResolver{mapping: ownerMapping()})
	s.SetProfileSource(prof)
	_, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{TenantID: shared.NewID().String(), FindingID: shared.NewID().String()})
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), "customfield_10050") {
		t.Fatalf("refusal: %v", err)
	}
	if len(prof.drifted) != 1 || prof.drifted[0] != prof.create.ProfileID {
		t.Fatalf("drifted %v", prof.drifted)
	}

	// A create through the published mapping clears the kind's recorded
	// refusal (the mapping is what fills the refused fields).
	c.createErr = nil
	h := &healthStub{}
	s.SetIssueTypeHealth(h)
	if _, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{TenantID: shared.NewID().String(), FindingID: shared.NewID().String()}); err != nil {
		t.Fatal(err)
	}
	if len(h.problems) != 1 || h.kinds[0] != IssueKindFinding || h.problems[0] != nil {
		t.Fatalf("not cleared by the mapping create: %v %+v", h.kinds, h.problems)
	}
}

func TestCreateTicket_FieldRefusalIsRecordedAndClearedOnSuccess(t *testing.T) {
	c := &refusingClient{linkClient: linkClient{intg: shared.NewID()}, err: NewFieldRejectedError([]string{"issuetype"})}
	s := newSync(&stubFindingRepo{finding: buildFinding(t)}, c)
	s.SetMappingResolver(stubMappingResolver{mapping: ownerMapping()})
	h := &healthStub{}
	s.SetIssueTypeHealth(h)

	in := CreateTicketInput{TenantID: shared.NewID().String(), FindingID: shared.NewID().String()}
	if _, err := s.CreateTicketFromFinding(context.Background(), in); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want the refusal, got %v", err)
	}
	if len(h.problems) != 1 || h.kinds[0] != IssueKindFinding || h.problems[0] == nil ||
		h.problems[0].IssueType != "Security Finding" || h.problems[0].Fields[0] != "issuetype" {
		t.Fatalf("recorded %v %+v", h.kinds, h.problems)
	}

	// Another failure (network, 5xx) is not a mapping problem: nothing recorded.
	c.err = errors.New("connection reset")
	_, _ = s.CreateTicketFromFinding(context.Background(), in)
	if len(h.problems) != 1 {
		t.Fatal("a transport error must not touch the health")
	}

	// The next success clears it.
	c.err = nil
	if _, err := s.CreateTicketFromFinding(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if len(h.problems) != 2 || h.problems[1] != nil {
		t.Fatalf("not cleared: %+v", h.problems)
	}
}

func TestCreateEpic_UsesTheEpicType(t *testing.T) {
	c := &refusingClient{linkClient: linkClient{intg: shared.NewID()}}
	s := newSync(&stubFindingRepo{finding: buildFinding(t)}, c)
	s.SetMappingResolver(stubMappingResolver{mapping: ownerMapping()})
	if _, _, err := s.CreateEpic(context.Background(), shared.NewID(), "SEC", "Q4 TLS", "d", nil); err != nil {
		t.Fatal(err)
	}
	if c.lastInput.IssueTypeID != "10045" || c.lastInput.IssueType != "Initiative" {
		t.Fatalf("epic created as %+v", c.lastInput)
	}
	// Without a choice: Epic.
	s.SetMappingResolver(stubMappingResolver{mapping: DefaultMappingConfig()})
	if _, _, err := s.CreateEpic(context.Background(), shared.NewID(), "SEC", "Q4 TLS", "d", nil); err != nil || c.lastInput.IssueType != "Epic" || c.lastInput.IssueTypeID != "" {
		t.Fatalf("default epic: %+v %v", c.lastInput, err)
	}
}

// taskProfileClient is a tracker client with profiles and issue identity.
type taskProfileClient struct {
	*profileClient
}

func (c taskProfileClient) IssueIdentity(_ context.Context, key string) (string, string, error) {
	return "10001", key, nil
}

func taskProfileSync(t *testing.T, task *remediation.Task, prof *stubProfiles) (*SyncService, *profileClient, *memLinks) {
	t.Helper()
	pc := &profileClient{integration: shared.NewID(), status: "1"}
	s := newSync(&stubFindingRepo{finding: buildFinding(t)}, taskProfileClient{pc})
	links := &memLinks{}
	s.SetLinkStore(links)
	s.SetMappingResolver(fixedMapping(ownerMapping()))
	s.SetProfileSource(prof)
	store := &taskStore{tasks: map[shared.ID]*remediation.Task{task.ID: task}, members: map[shared.ID][]shared.ID{}}
	s.SetTaskSources(store, store)
	s.SetRefusalCommentGuard(&onceGuard{})
	return s, pc, links
}

func TestCreateTaskIssue_UsesTheTaskTypeAndItsProfile(t *testing.T) {
	task := newTask(remediation.TaskStateOpen)

	// Without a task profile: the built-in fields, sent as Remediation Task by id.
	s, pc, _ := taskProfileSync(t, task, &stubProfiles{})
	if _, err := s.CreateTaskIssue(context.Background(), CreateTaskIssueInput{TenantID: shared.NewID(), TaskID: task.ID}); err != nil {
		t.Fatal(err)
	}
	if pc.lastInput.IssueTypeID != "10043" || pc.lastInput.IssueType != "Remediation Task" || pc.createdWith != nil {
		t.Fatalf("built-in task create: %+v", pc.lastInput)
	}

	// With a published task profile for that type: its fields (required
	// custom fields included), never the built-in create.
	task2 := newTask(remediation.TaskStateOpen)
	prof := &stubProfiles{taskCreate: &ProfileCreate{ProfileID: shared.NewID(), IssueTypeID: "10043", Fields: map[string]any{"summary": "t", "customfield_10050": "Payments", "duedate": "2026-11-01"}}}
	s, pc, links := taskProfileSync(t, task2, prof)
	if _, err := s.CreateTaskIssue(context.Background(), CreateTaskIssueInput{TenantID: shared.NewID(), TaskID: task2.ID}); err != nil {
		t.Fatal(err)
	}
	if prof.gotType != "10043" || pc.createdType != "10043" || pc.createdWith["customfield_10050"] != "Payments" || pc.calls != 0 {
		t.Fatalf("profile create: looked up %q, type %q, fields %v, built-in calls %d", prof.gotType, pc.createdType, pc.createdWith, pc.calls)
	}
	if len(links.rows) != 1 || links.rows[0].TaskID == nil || *links.rows[0].TaskID != task2.ID {
		t.Fatalf("link %+v", links.rows)
	}

	// The tracker refuses a field of the task profile: drifted, validation error.
	task3 := newTask(remediation.TaskStateOpen)
	prof3 := &stubProfiles{taskCreate: &ProfileCreate{ProfileID: shared.NewID(), IssueTypeID: "10043", Fields: map[string]any{"summary": "t"}}}
	s, pc, links = taskProfileSync(t, task3, prof3)
	pc.createErr = NewFieldRejectedError([]string{"customfield_10099"})
	if _, err := s.CreateTaskIssue(context.Background(), CreateTaskIssueInput{TenantID: shared.NewID(), TaskID: task3.ID}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("refusal: %v", err)
	}
	if len(prof3.drifted) != 1 || len(links.rows) != 0 {
		t.Fatalf("drifted %v links %d", prof3.drifted, len(links.rows))
	}
}

func TestSyncTaskIssue_FollowsTheTaskProfileWorkflow(t *testing.T) {
	task := newTask(remediation.TaskStateOpen)
	prof := &stubProfiles{}
	s, pc, links := taskProfileSync(t, task, prof)
	tid := shared.NewID()
	if _, err := s.CreateTaskIssue(context.Background(), CreateTaskIssueInput{TenantID: tid, TaskID: task.ID}); err != nil {
		t.Fatal(err)
	}
	pc.issueType = "10043"
	target := ticketmap.StatusTarget{StatusID: "4", Comment: true}
	statuses := append([]ticketmap.WorkflowStatus{}, wfStatuses...)
	statuses[2].Name = "Ready for retest"
	prof.taskStatus = &ProfileStatus{State: "verifying", Target: &target, Workflow: ticketmap.Workflow{Statuses: statuses, Transitions: wfTransitions}}

	task.State = remediation.TaskStateVerifying
	if err := s.SyncTaskIssue(context.Background(), tid, task.ID); err != nil {
		t.Fatal(err)
	}
	if prof.gotType != "10043" {
		t.Fatalf("task profile looked up for type %q, want the issue's own type", prof.gotType)
	}
	if len(pc.steps) != 2 || pc.steps[1] != "21" || len(pc.transitions) != 0 {
		t.Fatalf("path %v, built-in moves %v", pc.steps, pc.transitions)
	}
	if !strings.Contains(pc.stepComments[1], "Progress:") || pc.stepComments[0] != "" {
		t.Fatalf("comments %q", pc.stepComments)
	}
	if links.rows[0].LastPushedState != string(remediation.TaskStateVerifying) || links.rows[0].LastStatus != "Ready for retest" {
		t.Fatalf("link %+v", links.rows[0])
	}

	// A state the profile does not move: the progress comment alone.
	prof.taskStatus = &ProfileStatus{State: "blocked"}
	task.State = remediation.TaskStateOnHold
	if err := s.SyncTaskIssue(context.Background(), tid, task.ID); err != nil {
		t.Fatal(err)
	}
	if len(pc.steps) != 2 || len(pc.comments) != 1 || !strings.Contains(pc.comments[0], "on hold") {
		t.Fatalf("no target: steps %v comments %v", pc.steps, pc.comments)
	}
}

func TestStatusSync_FindingProfileIsLookedUpByTheIssuesType(t *testing.T) {
	c := &profileClient{integration: shared.NewID(), status: "1", issueType: "10042"}
	prof := &stubProfiles{}
	s := newSync(&stubFindingRepo{finding: buildFinding(t, "https://x.atlassian.net/browse/SEC-7")}, c)
	s.SetProfileSource(prof)
	if err := s.SyncFindingStatusToTicket(context.Background(), shared.NewID(), shared.NewID(), enabledMapping()); err != nil {
		t.Fatal(err)
	}
	if prof.gotType != "10042" {
		t.Fatalf("looked up type %q", prof.gotType)
	}
}

func withIssueType(p WebhookPayload, id string) WebhookPayload {
	p.Issue.Fields["issuetype"] = map[string]any{"id": id, "name": "x"}
	p.Issue.ID = "10001"
	return p
}

func TestInbound_ProfileByIssueTypeAndKind(t *testing.T) {
	taskMap := &ticketmap.StatusMap{Inbound: []ticketmap.InboundRule{{StatusID: "20", Intent: ticketmap.IntentFixClaim}}}
	findingMap := &ticketmap.StatusMap{Inbound: []ticketmap.InboundRule{{StatusID: "20", Intent: ticketmap.IntentInProgress}}}

	setup := func(t *testing.T, byKey map[string]*ticketmap.StatusMap, taskIssue bool) (*SyncService, *applierStub, *stubProfiles, shared.ID, shared.ID) {
		t.Helper()
		s, app, c, repo := intentSync(t, nil)
		prof := &stubProfiles{inboundBy: byKey, projects: []string{"SEC"}}
		s.SetProfileSource(prof)
		tenant := shared.NewID()
		if taskIssue {
			links := &memLinks{}
			task := newTask(remediation.TaskStateOpen)
			l, err := ticketlink.New(tenant, c.integration, ticketlink.ForTask(task.ID), "SEC-1", "10001",
				"https://x.atlassian.net", ticketlink.BrowseURL("https://x.atlassian.net", "SEC-1"), ticketlink.RoleOwn, ticketlink.SourcePerson, nil)
			if err != nil {
				t.Fatal(err)
			}
			_ = links.Create(context.Background(), l)
			s.SetLinkStore(links)
			store := &taskStore{tasks: map[shared.ID]*remediation.Task{task.ID: task}, members: map[shared.ID][]shared.ID{task.ID: {repo.finding.ID()}}}
			s.SetTaskSources(store, store)
		}
		return s, app, prof, tenant, c.integration
	}

	t.Run("a task issue uses the task profile of its type", func(t *testing.T) {
		s, app, prof, tenant, intg := setup(t, map[string]*ticketmap.StatusMap{"task/10043": taskMap, "finding/10043": findingMap}, true)
		if err := s.HandleJiraWebhook(context.Background(), tenant, intg, withIssueType(moved("20", "indeterminate", ""), "10043")); err != nil {
			t.Fatal(err)
		}
		if app.target != vulnerability.FindingStatusFixApplied || prof.gotKinds[0] != ticketmap.ObjectTask || prof.gotType != "10043" {
			t.Fatalf("applied %q kinds %v type %q", app.target, prof.gotKinds, prof.gotType)
		}
	})
	t.Run("a task issue without a task profile uses the finding profile of the same type", func(t *testing.T) {
		s, app, prof, tenant, intg := setup(t, map[string]*ticketmap.StatusMap{"finding/10043": findingMap}, true)
		if err := s.HandleJiraWebhook(context.Background(), tenant, intg, withIssueType(moved("20", "indeterminate", ""), "10043")); err != nil {
			t.Fatal(err)
		}
		if app.target != vulnerability.FindingStatusInProgress || len(prof.gotKinds) != 2 {
			t.Fatalf("applied %q kinds %v", app.target, prof.gotKinds)
		}
	})
	t.Run("a finding issue never uses a task profile", func(t *testing.T) {
		s, app, prof, tenant, intg := setup(t, map[string]*ticketmap.StatusMap{"task/10042": taskMap, "finding/10042": findingMap}, false)
		if err := s.HandleJiraWebhook(context.Background(), tenant, intg, withIssueType(moved("20", "indeterminate", ""), "10042")); err != nil {
			t.Fatal(err)
		}
		if app.target != vulnerability.FindingStatusInProgress || len(prof.gotKinds) != 1 || prof.gotKinds[0] != ticketmap.ObjectFinding {
			t.Fatalf("applied %q kinds %v", app.target, prof.gotKinds)
		}
	})
	t.Run("another type's workflow is never applied", func(t *testing.T) {
		// Only Security Finding (10042) has a profile; the issue is a Bug (10004):
		// the built-in name map decides ("Whatever" is unmapped: nothing).
		s, app, prof, tenant, intg := setup(t, map[string]*ticketmap.StatusMap{"finding/10042": findingMap}, false)
		if err := s.HandleJiraWebhook(context.Background(), tenant, intg, withIssueType(moved("20", "indeterminate", ""), "10004")); err != nil {
			t.Fatal(err)
		}
		if app.target != "" || prof.gotType != "10004" {
			t.Fatalf("applied %q for type %q", app.target, prof.gotType)
		}
	})
}

func TestPayloadIssueTypeID(t *testing.T) {
	for raw, want := range map[any]string{"10043": "10043", "10043 OR 1=1": "", "": ""} {
		p := WebhookPayload{Issue: WebhookIssue{Fields: map[string]any{"issuetype": map[string]any{"id": raw}}}}
		if got := payloadIssueTypeID(p); got != want {
			t.Errorf("%v: %q", raw, got)
		}
	}
	if payloadIssueTypeID(WebhookPayload{}) != "" {
		t.Error("no fields")
	}
}

func TestNewFieldRejectedError(t *testing.T) {
	if NewFieldRejectedError([]string{"<b>", "a b"}) != nil {
		t.Fatal("no well-formed id: nil")
	}
	e := NewFieldRejectedError([]string{"summary", "customfield_10050", "x\ny"})
	if strings.Join(e.Fields, ",") != "customfield_10050,summary" || !e.Permanent() || !errors.Is(e, shared.ErrValidation) {
		t.Fatalf("%+v", e)
	}
}
