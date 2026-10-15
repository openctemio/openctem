package jira

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketmap"
)

// profileClient is a tracker with a small workflow: To Do(1) → In Progress(3)
// → In Review(4) → Done(10, resolution required); Done → To Do.
type profileClient struct {
	recordingClient
	integration  shared.ID
	status       string
	createdWith  map[string]any
	createdType  string
	steps        []string
	stepFields   []map[string]string
	stepComments []string
	transErr     error
}

var wfTransitions = []ticketmap.WorkflowTransition{
	{ID: "11", Name: "Start", From: []string{"1"}, To: "3"},
	{ID: "21", Name: "Review", From: []string{"3"}, To: "4"},
	{ID: "31", Name: "Close", From: []string{"4"}, To: "10", Fields: []ticketmap.TransitionField{{ID: "resolution", Name: "Resolution", Required: true}}},
	{ID: "41", Name: "Reopen", From: []string{"10"}, To: "1"},
}

var wfStatuses = []ticketmap.WorkflowStatus{{ID: "1", Category: "new"}, {ID: "3", Category: "indeterminate"}, {ID: "4", Category: "indeterminate"}, {ID: "10", Category: "done"}}

func (c *profileClient) IntegrationID() shared.ID { return c.integration }
func (c *profileClient) CreateIssueFields(_ context.Context, _ string, typeID string, f map[string]any) (*CreateIssueResult, error) {
	c.createdWith, c.createdType = f, typeID
	return &CreateIssueResult{Key: "SEC-7", BrowseURL: "https://x.atlassian.net/browse/SEC-7"}, nil
}
func (c *profileClient) CurrentStatus(context.Context, string) (ticketmap.WorkflowStatus, error) {
	return ticketmap.WorkflowStatus{ID: c.status, Name: "s" + c.status}, nil
}
func (c *profileClient) AvailableTransitions(context.Context, string) ([]ticketmap.WorkflowTransition, error) {
	var out []ticketmap.WorkflowTransition
	for _, t := range wfTransitions {
		for _, f := range t.From {
			if f == c.status {
				out = append(out, t)
			}
		}
	}
	return out, nil
}
func (c *profileClient) Transition(_ context.Context, _, id string, fields map[string]string, comment string) error {
	if c.transErr != nil {
		return c.transErr
	}
	for _, t := range wfTransitions {
		if t.ID == id {
			c.status = t.To
		}
	}
	c.steps = append(c.steps, id)
	c.stepFields = append(c.stepFields, fields)
	c.stepComments = append(c.stepComments, comment)
	return nil
}

type stubProfiles struct {
	create *ProfileCreate
	status *ProfileStatus
	gotInt shared.ID
}

func (p *stubProfiles) RenderFindingCreate(_ context.Context, _, integrationID shared.ID, _, _ string, _ shared.ID) (*ProfileCreate, error) {
	p.gotInt = integrationID
	return p.create, nil
}
func (p *stubProfiles) FindingStatusTarget(_ context.Context, _, integrationID shared.ID, _ string, _ shared.ID) (*ProfileStatus, error) {
	p.gotInt = integrationID
	return p.status, nil
}

func TestCreateTicket_UsesThePublishedProfile(t *testing.T) {
	intg := shared.NewID()
	c := &profileClient{integration: intg}
	prof := &stubProfiles{create: &ProfileCreate{IssueTypeID: "10001", Fields: map[string]any{"summary": "[HIGH] x", "customfield_10050": map[string]string{"id": "70"}}}}
	s := newSync(&stubFindingRepo{finding: buildFinding(t)}, c)
	s.SetProfileSource(prof)

	info, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{
		TenantID: shared.NewID().String(), FindingID: shared.NewID().String(), ProjectKey: "SEC", ParentKey: "SEC-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.TicketKey != "SEC-7" || c.calls != 0 {
		t.Fatalf("want the profile create only; key=%s legacy calls=%d", info.TicketKey, c.calls)
	}
	if c.createdType != "10001" || c.createdWith["customfield_10050"] == nil || c.createdWith["parent"] == nil {
		t.Fatalf("fields: %v type %s", c.createdWith, c.createdType)
	}
	if prof.gotInt != intg {
		t.Fatal("the profile must be looked up for the client's own integration")
	}
	if _, leaked := prof.create.Fields["parent"]; leaked {
		t.Fatal("the rendered fields must not be mutated")
	}
}

func TestCreateTicket_DryRunAndNoProfileUseTheBuiltInFields(t *testing.T) {
	for name, pr := range map[string]*ProfileCreate{
		"dry run":    {IssueTypeID: "1", Fields: map[string]any{"summary": "x"}, DryRun: true},
		"no profile": nil,
	} {
		c := &profileClient{integration: shared.NewID()}
		s := newSync(&stubFindingRepo{finding: buildFinding(t)}, c)
		s.SetProfileSource(&stubProfiles{create: pr})
		if _, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{
			TenantID: shared.NewID().String(), FindingID: shared.NewID().String(), ProjectKey: "SEC",
		}); err != nil {
			t.Fatal(err)
		}
		if c.calls != 1 || c.createdWith != nil {
			t.Fatalf("%s: want the built-in create", name)
		}
	}
}

func TestStatusSync_ProfileWalksTheWorkflowAndFillsTheResolution(t *testing.T) {
	c := &profileClient{integration: shared.NewID(), status: "1"}
	target := ticketmap.StatusTarget{StatusID: "10", Resolution: "Done", Comment: true}
	prof := &stubProfiles{status: &ProfileStatus{State: "verified", Target: &target, Workflow: ticketmap.Workflow{Statuses: wfStatuses, Transitions: wfTransitions}}}
	s := newSync(&stubFindingRepo{finding: buildFinding(t, "https://x.atlassian.net/browse/SEC-7")}, c)
	s.SetProfileSource(prof)

	// The integration-level opt-in is off: a published profile is its own opt-in.
	if err := s.SyncFindingStatusToTicket(context.Background(), shared.NewID(), shared.NewID(), DefaultMappingConfig()); err != nil {
		t.Fatal(err)
	}
	if len(c.steps) != 3 || c.steps[0] != "11" || c.steps[2] != "31" {
		t.Fatalf("path: %v", c.steps)
	}
	if c.stepFields[2]["resolution"] != "Done" || c.stepComments[2] == "" || c.stepComments[0] != "" {
		t.Fatalf("final step fields/comment: %v %v", c.stepFields, c.stepComments)
	}
	if len(c.transitions) != 0 {
		t.Fatal("the built-in status sync must not run as well")
	}
	// Already there: nothing moves (idempotent replay).
	c.steps = nil
	if err := s.SyncFindingStatusToTicket(context.Background(), shared.NewID(), shared.NewID(), DefaultMappingConfig()); err != nil || len(c.steps) != 0 {
		t.Fatalf("replay moved the issue: %v %v", err, c.steps)
	}
}

func TestStatusSync_NeverGuessesAndFailsPermanently(t *testing.T) {
	// Unknown workflow graph and no direct transition: refuse.
	c := &profileClient{integration: shared.NewID(), status: "1"}
	target := ticketmap.StatusTarget{StatusID: "10", Resolution: "Done"}
	s := newSync(&stubFindingRepo{finding: buildFinding(t, "https://x.atlassian.net/browse/SEC-7")}, c)
	s.SetProfileSource(&stubProfiles{status: &ProfileStatus{State: "verified", Target: &target}})
	err := s.SyncFindingStatusToTicket(context.Background(), shared.NewID(), shared.NewID(), DefaultMappingConfig())
	var perm interface{ Permanent() bool }
	if !errors.Is(err, ErrNoPath) || !errors.As(err, &perm) || len(c.steps) != 0 {
		t.Fatalf("want a permanent ErrNoPath and no move; got %v steps %v", err, c.steps)
	}

	// A required screen field the mapping does not fill: refuse before moving.
	c = &profileClient{integration: shared.NewID(), status: "4"}
	noRes := ticketmap.StatusTarget{StatusID: "10"}
	s = newSync(&stubFindingRepo{finding: buildFinding(t, "https://x.atlassian.net/browse/SEC-7")}, c)
	s.SetProfileSource(&stubProfiles{status: &ProfileStatus{State: "verified", Target: &noRes, Workflow: ticketmap.Workflow{Statuses: wfStatuses, Transitions: wfTransitions}}})
	if err := s.SyncFindingStatusToTicket(context.Background(), shared.NewID(), shared.NewID(), DefaultMappingConfig()); !errors.Is(err, ErrNoPath) || len(c.steps) != 0 {
		t.Fatalf("missing resolution: %v %v", err, c.steps)
	}
}

func TestStatusSync_DryRunAndUnmappedStateDoNothing(t *testing.T) {
	c := &profileClient{integration: shared.NewID(), status: "1"}
	target := ticketmap.StatusTarget{StatusID: "3"}
	s := newSync(&stubFindingRepo{finding: buildFinding(t, "https://x.atlassian.net/browse/SEC-7")}, c)
	for _, ps := range []*ProfileStatus{
		{State: "in_progress", Target: &target, DryRun: true},
		{State: "new"}, // the state does not move the issue
	} {
		s.SetProfileSource(&stubProfiles{status: ps})
		if err := s.SyncFindingStatusToTicket(context.Background(), shared.NewID(), shared.NewID(), enabledMapping()); err != nil || len(c.steps) != 0 || len(c.transitions) != 0 {
			t.Fatalf("%+v: err=%v steps=%v builtin=%v", ps, err, c.steps, c.transitions)
		}
	}
}
