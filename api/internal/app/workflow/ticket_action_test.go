package workflow

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

type fakeJiraTicket struct {
	created     bool
	synced      bool
	gotProject  string
	gotFinding  string
	gotIssue    string
	syncFinding shared.ID
	err         error
}

func (f *fakeJiraTicket) CreateTicketFromFinding(_ context.Context, _, findingID, projectKey, issueType string) (TicketRef, error) {
	if f.err != nil {
		return TicketRef{}, f.err
	}
	f.created = true
	f.gotFinding = findingID
	f.gotProject = projectKey
	f.gotIssue = issueType
	return TicketRef{Key: "SEC-42", URL: "https://jira/browse/SEC-42"}, nil
}

func (f *fakeJiraTicket) SyncFindingStatus(_ context.Context, _, findingID shared.ID) error {
	if f.err != nil {
		return f.err
	}
	f.synced = true
	f.syncFinding = findingID
	return nil
}

type fakeGitHubTicket struct {
	created   bool
	gotOwner  string
	gotRepo   string
	gotFinder string
}

func (f *fakeGitHubTicket) CreateTicketFromFinding(_ context.Context, _, findingID, owner, repo string) (TicketRef, error) {
	f.created = true
	f.gotFinder = findingID
	f.gotOwner = owner
	f.gotRepo = repo
	return TicketRef{Key: "#7", URL: "https://github.com/o/r/issues/7"}, nil
}

func TestCreateTicket_Jira_Default(t *testing.T) {
	jira := &fakeJiraTicket{}
	h := NewTicketActionHandler(nil, jira, nil, logger.NewNop())

	res, err := h.createTicket(context.Background(), &ActionInput{
		TenantID: shared.NewID(),
		ActionConfig: map[string]any{
			"finding_id": "f-1", "project_key": "SEC", "issue_type": "Bug",
		},
	})
	if err != nil {
		t.Fatalf("createTicket: %v", err)
	}
	if !jira.created || jira.gotProject != "SEC" || jira.gotIssue != "Bug" || jira.gotFinding != "f-1" {
		t.Fatalf("jira not called correctly: %+v", jira)
	}
	if res["provider"] != "jira" || res["ticket_key"] != "SEC-42" || res["created"] != true {
		t.Fatalf("unexpected result: %v", res)
	}
}

func TestCreateTicket_GitHub_Provider(t *testing.T) {
	gh := &fakeGitHubTicket{}
	h := NewTicketActionHandler(nil, nil, gh, logger.NewNop())

	res, err := h.createTicket(context.Background(), &ActionInput{
		TenantID: shared.NewID(),
		ActionConfig: map[string]any{
			"finding_id": "f-2", "provider": "github", "owner": "acme", "repo": "app",
		},
	})
	if err != nil {
		t.Fatalf("createTicket: %v", err)
	}
	if !gh.created || gh.gotOwner != "acme" || gh.gotRepo != "app" {
		t.Fatalf("github not called correctly: %+v", gh)
	}
	if res["provider"] != "github" || res["ticket_url"] != "https://github.com/o/r/issues/7" {
		t.Fatalf("unexpected result: %v", res)
	}
}

func TestCreateTicket_FromTriggerData(t *testing.T) {
	jira := &fakeJiraTicket{}
	h := NewTicketActionHandler(nil, jira, nil, logger.NewNop())

	// finding id arrives via the workflow trigger, not action config.
	_, err := h.createTicket(context.Background(), &ActionInput{
		TenantID:     shared.NewID(),
		ActionConfig: map[string]any{"project_key": "SEC"},
		TriggerData:  map[string]any{"finding": map[string]any{"id": "f-trigger"}},
	})
	if err != nil {
		t.Fatalf("createTicket: %v", err)
	}
	if jira.gotFinding != "f-trigger" {
		t.Fatalf("expected finding id from trigger data, got %q", jira.gotFinding)
	}
}

func TestUpdateTicket_SyncsFindingStatus(t *testing.T) {
	jira := &fakeJiraTicket{}
	h := NewTicketActionHandler(nil, jira, nil, logger.NewNop())
	fid := shared.NewID()

	res, err := h.updateTicket(context.Background(), &ActionInput{
		TenantID:     shared.NewID(),
		ActionConfig: map[string]any{"finding_id": fid.String()},
	})
	if err != nil {
		t.Fatalf("updateTicket: %v", err)
	}
	if !jira.synced || jira.syncFinding != fid {
		t.Fatalf("expected SyncFindingStatus for %s, got synced=%v id=%s", fid, jira.synced, jira.syncFinding)
	}
	if res["synced"] != true {
		t.Fatalf("unexpected result: %v", res)
	}
}

func TestCreateTicket_ProviderError_Propagates(t *testing.T) {
	jira := &fakeJiraTicket{err: errors.New("jira 500")}
	h := NewTicketActionHandler(nil, jira, nil, logger.NewNop())
	_, err := h.createTicket(context.Background(), &ActionInput{
		TenantID:     shared.NewID(),
		ActionConfig: map[string]any{"finding_id": "f-1", "project_key": "SEC"},
	})
	if err == nil {
		t.Fatal("expected provider error to propagate")
	}
}
