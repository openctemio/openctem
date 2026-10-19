package exposure

import (
	"context"
	"errors"
	"strings"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type fakeTicketRepo struct {
	remediation.CampaignTicketRepository
	existing *remediation.CampaignTicket
	created  *remediation.CampaignTicket
}

func (r *fakeTicketRepo) GetByCampaignAndProvider(_ context.Context, _, _ shared.ID, _ string) (*remediation.CampaignTicket, error) {
	if r.existing != nil {
		return r.existing, nil
	}
	return nil, remediation.ErrCampaignTicketNotFound
}

func (r *fakeTicketRepo) Create(_ context.Context, t *remediation.CampaignTicket) error {
	r.created = t
	return nil
}

func (r *fakeTicketRepo) GetByIssueKey(_ context.Context, _ shared.ID, _, _ string) (*remediation.CampaignTicket, error) {
	if r.existing != nil {
		return r.existing, nil
	}
	return nil, remediation.ErrCampaignTicketNotFound
}

func (r *fakeTicketRepo) ListByCampaignIDs(_ context.Context, _ shared.ID, _ []shared.ID) (map[string]*remediation.CampaignTicket, error) {
	out := map[string]*remediation.CampaignTicket{}
	if r.existing != nil {
		out[r.existing.CampaignID().String()] = r.existing
	}
	return out, nil
}

type fakeEpicCreator struct {
	key, url        string
	calls           int
	err             error
	transitionCalls int
	lastTransition  string
}

func (f *fakeEpicCreator) CreateEpic(_ context.Context, _ shared.ID, _, _, _ string, _ []string) (string, string, error) {
	f.calls++
	if f.err != nil {
		return "", "", f.err
	}
	return f.key, f.url, nil
}

func (f *fakeEpicCreator) TransitionEpic(_ context.Context, _ shared.ID, _, targetStatus, _ string) error {
	f.transitionCalls++
	f.lastTransition = targetStatus
	return nil
}

func TestCreateTicket_CreatesEpicAndLink(t *testing.T) {
	c := newCampaign(t)
	tr := &fakeTicketRepo{}
	epic := &fakeEpicCreator{key: "SEC-42", url: "https://x.atlassian.net/browse/SEC-42"}
	svc := newTicketSvc(c, tr, epic)

	info, err := svc.CreateTicket(context.Background(), c.TenantID().String(), c.ID().String(), "SEC")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if info.AlreadyExisted {
		t.Error("should not report already-existed on first create")
	}
	if info.IssueKey != "SEC-42" || info.IssueURL != epic.url {
		t.Errorf("unexpected ticket info: %+v", info)
	}
	if epic.calls != 1 {
		t.Errorf("epic should be created once, got %d", epic.calls)
	}
	if tr.created == nil || tr.created.IssueKey() != "SEC-42" {
		t.Error("link was not persisted")
	}
}

func TestCreateTicket_IdempotentWhenLinkExists(t *testing.T) {
	c := newCampaign(t)
	existing, _ := remediation.NewCampaignTicket(shared.NewID(), c.ID(), "jira", "SEC-1", "https://x/browse/SEC-1")
	tr := &fakeTicketRepo{existing: existing}
	epic := &fakeEpicCreator{key: "SEC-99", url: "https://x/browse/SEC-99"}
	svc := newTicketSvc(c, tr, epic)

	info, err := svc.CreateTicket(context.Background(), c.TenantID().String(), c.ID().String(), "SEC")
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if !info.AlreadyExisted || info.IssueKey != "SEC-1" {
		t.Errorf("expected existing SEC-1, got %+v", info)
	}
	if epic.calls != 0 {
		t.Errorf("must NOT create a second epic when one exists, got %d calls", epic.calls)
	}
}

func TestCreateTicket_NotConfigured(t *testing.T) {
	c := newCampaign(t)
	svc := newTicketSvc(c, nil, nil) // ticketing not wired
	_, err := svc.CreateTicket(context.Background(), c.TenantID().String(), c.ID().String(), "SEC")
	if !errors.Is(err, ErrTicketingNotConfigured) {
		t.Fatalf("expected ErrTicketingNotConfigured, got %v", err)
	}
}

func TestCreateTicket_RequiresProjectKey(t *testing.T) {
	c := newCampaign(t)
	svc := newTicketSvc(c, &fakeTicketRepo{}, &fakeEpicCreator{})
	_, err := svc.CreateTicket(context.Background(), c.TenantID().String(), c.ID().String(), "")
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected validation error, got %v", err)
	}
}

func TestUpdateCampaignStatus_CompletionTransitionsEpic(t *testing.T) {
	c := newCampaign(t)
	if err := c.Activate(); err != nil { // draft -> active so it can complete
		t.Fatalf("activate: %v", err)
	}
	link, _ := remediation.NewCampaignTicket(c.TenantID(), c.ID(), "jira", "SEC-7", "https://x/browse/SEC-7")
	tr := &fakeTicketRepo{existing: link}
	epic := &fakeEpicCreator{}
	svc := newTicketSvc(c, tr, epic)

	svc.repo.(*fakeCampaignRepo).whole = remediation.CampaignSummary{Tasks: 1, DoneTasks: 1}
	if _, err := svc.UpdateCampaignStatus(context.Background(), c.TenantID().String(), c.ID().String(),
		string(remediation.CampaignStatusCompleted), nil, auditapp.AuditContext{}); err != nil {
		t.Fatalf("UpdateCampaignStatus: %v", err)
	}
	if epic.transitionCalls != 1 || epic.lastTransition != "Done" {
		t.Fatalf("expected one transition to Done, got calls=%d last=%q", epic.transitionCalls, epic.lastTransition)
	}
}

func TestUpdateCampaignStatus_NoEpicLink_NoTransition(t *testing.T) {
	c := newCampaign(t)
	if err := c.Activate(); err != nil {
		t.Fatalf("activate: %v", err)
	}
	epic := &fakeEpicCreator{}
	svc := newTicketSvc(c, &fakeTicketRepo{}, epic) // no existing link

	svc.repo.(*fakeCampaignRepo).whole = remediation.CampaignSummary{Tasks: 1, DoneTasks: 1}
	if _, err := svc.UpdateCampaignStatus(context.Background(), c.TenantID().String(), c.ID().String(),
		string(remediation.CampaignStatusCompleted), nil, auditapp.AuditContext{}); err != nil {
		t.Fatalf("UpdateCampaignStatus: %v", err)
	}
	if epic.transitionCalls != 0 {
		t.Fatalf("no epic link → must not transition, got %d", epic.transitionCalls)
	}
}

func TestCampaignTicketFor_PresentAndAbsent(t *testing.T) {
	c := newCampaign(t)
	link, _ := remediation.NewCampaignTicket(c.TenantID(), c.ID(), "jira", "SEC-5", "https://x/browse/SEC-5")

	// Present
	svc := newTicketSvc(c, &fakeTicketRepo{existing: link}, &fakeEpicCreator{})
	got, err := svc.CampaignTicketFor(context.Background(), c.TenantID(), c.ID())
	if err != nil {
		t.Fatalf("CampaignTicketFor: %v", err)
	}
	if got == nil || got.IssueKey != "SEC-5" || got.Provider != "jira" {
		t.Fatalf("expected SEC-5 link, got %+v", got)
	}

	// Absent → nil, nil
	svc2 := newTicketSvc(c, &fakeTicketRepo{}, &fakeEpicCreator{})
	got2, err := svc2.CampaignTicketFor(context.Background(), c.TenantID(), c.ID())
	if err != nil || got2 != nil {
		t.Fatalf("expected (nil,nil) when no link, got (%+v,%v)", got2, err)
	}
}

func TestCampaignTicketsFor_Batch(t *testing.T) {
	c := newCampaign(t)
	link, _ := remediation.NewCampaignTicket(c.TenantID(), c.ID(), "jira", "SEC-9", "https://x/browse/SEC-9")
	svc := newTicketSvc(c, &fakeTicketRepo{existing: link}, &fakeEpicCreator{})

	m, err := svc.CampaignTicketsFor(context.Background(), c.TenantID(), []shared.ID{c.ID()})
	if err != nil {
		t.Fatalf("CampaignTicketsFor: %v", err)
	}
	if got := m[c.ID().String()]; got == nil || got.IssueKey != "SEC-9" {
		t.Fatalf("expected SEC-9 in batch map, got %+v", m)
	}
}

// Jira Done on a campaign's epic is a fix claim for the campaign's findings
// (marked fixed through the campaign resolve, the integration as the actor);
// it never completes the campaign. A non-epic issue is not handled.
func TestHandleEpicStatusChange_DoneClaimsTasksFixedNeverCompletes(t *testing.T) {
	c := newCampaign(t)
	if err := c.Activate(); err != nil {
		t.Fatal(err)
	}
	link, err := remediation.NewCampaignTicket(c.TenantID(), c.ID(), "jira", "SEC-7", "https://x.atlassian.net/browse/SEC-7")
	if err != nil {
		t.Fatal(err)
	}
	svc := newTicketSvc(c, &fakeTicketRepo{existing: link}, nil)
	tasks := svc.tasks.(*fakeTasks)
	t1, t2 := shared.NewID(), shared.NewID()
	tasks.live = []shared.ID{t1, t2}
	tasks.refusals = map[shared.ID][]string{t2: {"f-1: not your finding"}}

	refusals, handled, err := svc.HandleEpicStatusChange(context.Background(), c.TenantID(), "SEC-7", "Done", "acct-1")
	if err != nil || !handled || len(refusals) != 1 || refusals[0] != "f-1: not your finding" {
		t.Fatalf("Done: refusals=%v handled=%v err=%v", refusals, handled, err)
	}
	if len(tasks.claimed) != 2 || !strings.Contains(tasks.lastNote, "SEC-7") {
		t.Fatalf("claimed %v note %q, want both live tasks claimed fixed", tasks.claimed, tasks.lastNote)
	}
	if c.Status() != remediation.CampaignStatusActive {
		t.Fatalf("campaign status = %s, want still active", c.Status())
	}
	tasks.claimed = nil
	if _, handled, _ := svc.HandleEpicStatusChange(context.Background(), c.TenantID(), "SEC-7", "In Progress", ""); !handled || len(tasks.claimed) != 0 {
		t.Fatalf("In Progress on the epic: handled=%v claimed=%v", handled, tasks.claimed)
	}
	other := newTicketSvc(c, &fakeTicketRepo{}, nil)
	if _, handled, _ := other.HandleEpicStatusChange(context.Background(), c.TenantID(), "SEC-8", "Done", ""); handled {
		t.Fatal("an issue that is no campaign's epic was handled")
	}
}

// The epic comment never carries internal error text.
func TestHandleEpicStatusChange_FailureCommentIsFixed(t *testing.T) {
	c := newCampaign(t)
	link, err := remediation.NewCampaignTicket(c.TenantID(), c.ID(), "jira", "SEC-9", "https://x.atlassian.net/browse/SEC-9")
	if err != nil {
		t.Fatal(err)
	}
	svc := newTicketSvc(c, &fakeTicketRepo{existing: link}, nil)
	tasks := svc.tasks.(*fakeTasks)
	tk := shared.NewID()
	tasks.live = []shared.ID{tk}
	tasks.claimErr = errors.New("pq: relation internal_secret_table does not exist")
	refusals, handled, err := svc.HandleEpicStatusChange(context.Background(), c.TenantID(), "SEC-9", "Done", "")
	if !handled || err != nil || len(refusals) != 1 || refusals[0] != tk.String()+": "+campaignEpicClaimFailed {
		t.Fatalf("refusals=%q handled=%v err=%v, want the fixed message", refusals, handled, err)
	}
}
