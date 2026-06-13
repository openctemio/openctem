package exposure

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/remediation"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// ticketCampaignRepo embeds the interface (merge-safe vs. future methods) and
// overrides only GetByID.
type ticketCampaignRepo struct {
	remediation.CampaignRepository
	c *remediation.Campaign
}

func (r *ticketCampaignRepo) GetByID(_ context.Context, _ shared.ID, _ shared.ID) (*remediation.Campaign, error) {
	if r.c == nil {
		return nil, remediation.ErrCampaignNotFound
	}
	return r.c, nil
}

func (r *ticketCampaignRepo) Update(_ context.Context, _ *remediation.Campaign) error { return nil }

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

func newCampaign(t *testing.T) *remediation.Campaign {
	t.Helper()
	c, err := remediation.NewCampaign(shared.NewID(), "Fix Log4j", remediation.CampaignPriorityHigh)
	if err != nil {
		t.Fatalf("NewCampaign: %v", err)
	}
	return c
}

func newTicketSvc(c *remediation.Campaign, tr remediation.CampaignTicketRepository, epic CampaignEpicCreator) *RemediationCampaignService {
	s := NewRemediationCampaignService(&ticketCampaignRepo{c: c}, logger.NewNop())
	if tr != nil || epic != nil {
		s.SetTicketing(tr, epic)
	}
	return s
}

func TestCreateTicket_CreatesEpicAndLink(t *testing.T) {
	c := newCampaign(t)
	tr := &fakeTicketRepo{}
	epic := &fakeEpicCreator{key: "SEC-42", url: "https://x.atlassian.net/browse/SEC-42"}
	svc := newTicketSvc(c, tr, epic)

	info, err := svc.CreateTicket(context.Background(), shared.NewID().String(), c.ID().String(), "SEC")
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

	info, err := svc.CreateTicket(context.Background(), shared.NewID().String(), c.ID().String(), "SEC")
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
	_, err := svc.CreateTicket(context.Background(), shared.NewID().String(), c.ID().String(), "SEC")
	if !errors.Is(err, ErrTicketingNotConfigured) {
		t.Fatalf("expected ErrTicketingNotConfigured, got %v", err)
	}
}

func TestCreateTicket_RequiresProjectKey(t *testing.T) {
	c := newCampaign(t)
	svc := newTicketSvc(c, &fakeTicketRepo{}, &fakeEpicCreator{})
	_, err := svc.CreateTicket(context.Background(), shared.NewID().String(), c.ID().String(), "")
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

	if _, err := svc.UpdateCampaignStatus(context.Background(), c.TenantID().String(), c.ID().String(),
		string(remediation.CampaignStatusCompleted)); err != nil {
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

	if _, err := svc.UpdateCampaignStatus(context.Background(), c.TenantID().String(), c.ID().String(),
		string(remediation.CampaignStatusCompleted)); err != nil {
		t.Fatalf("UpdateCampaignStatus: %v", err)
	}
	if epic.transitionCalls != 0 {
		t.Fatalf("no epic link → must not transition, got %d", epic.transitionCalls)
	}
}
