package jira

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/ticketing"
	"github.com/openctemio/openctem/api/pkg/domain/pentest"
	"github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type egressCampaigns map[shared.ID]*pentest.Campaign

func (c egressCampaigns) GetByID(_ context.Context, _, id shared.ID) (*pentest.Campaign, error) {
	if v, ok := c[id]; ok {
		return v, nil
	}
	return nil, shared.ErrNotFound
}

// egressRepo serves one finding by id and in batches.
type egressRepo struct {
	stubFindingRepo
	byID map[shared.ID]*vulnerability.Finding
}

func (r *egressRepo) GetByIDs(_ context.Context, _ shared.ID, ids []shared.ID) ([]*vulnerability.Finding, error) {
	out := make([]*vulnerability.Finding, 0, len(ids))
	for _, id := range ids {
		if f, ok := r.byID[id]; ok {
			out = append(out, f)
		}
	}
	return out, nil
}

// pentestSetup is a SyncService with the gate wired and one pentest finding
// of a campaign at tlp.
func pentestSetup(t *testing.T, tlp pentest.TLP, client Client) (*SyncService, *vulnerability.Finding, *egressRepo) {
	t.Helper()
	c, err := pentest.NewCampaign(shared.NewID(), "engagement")
	if err != nil {
		t.Fatal(err)
	}
	c.SetProfile(nil, "", "", tlp)
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourcePentest, "manual", vulnerability.SeverityHigh, "SQL injection")
	if err != nil {
		t.Fatal(err)
	}
	cid := c.ID()
	f.SetPentestCampaignID(&cid)
	repo := &egressRepo{stubFindingRepo: stubFindingRepo{finding: f}, byID: map[shared.ID]*vulnerability.Finding{f.ID(): f}}
	s := newSync(repo, client)
	s.SetEgressGate(ticketing.NewEgressGate(nil, egressCampaigns{cid: c}))
	return s, f, repo
}

func wantRefusal(t *testing.T, err error, reason ticketing.EgressReason) {
	t.Helper()
	var r *ticketing.EgressRefusedError
	if !errors.As(err, &r) || r.Reason != reason {
		t.Fatalf("want refusal %q, got %v", reason, err)
	}
}

func TestCreateTicket_PentestRefusedOutsideCampaignRoute(t *testing.T) {
	ctx := context.Background()
	for _, route := range []ticketing.Route{ticketing.RouteFinding, ticketing.RouteAutomation} {
		client := &stubCreateClient{}
		s, f, _ := pentestSetup(t, pentest.TLPGreen, client)
		_, err := s.CreateTicketFromFinding(ctx, CreateTicketInput{TenantID: shared.NewID().String(), FindingID: f.ID().String(), ProjectKey: "SEC", Route: route})
		wantRefusal(t, err, ticketing.ReasonPentestCampaignOnly)
		if client.calls != 0 {
			t.Fatalf("route %q: tracker called for a refused pentest finding", route)
		}
	}
}

func TestCreateTicket_CampaignRoute(t *testing.T) {
	ctx := context.Background()

	// Within the default limit: created.
	client := &stubCreateClient{}
	s, f, _ := pentestSetup(t, pentest.TLPAmber, client)
	if _, err := s.CreateTicketFromFinding(ctx, CreateTicketInput{TenantID: shared.NewID().String(), FindingID: f.ID().String(), ProjectKey: "SEC", Route: ticketing.RouteCampaign}); err != nil {
		t.Fatalf("amber campaign via the campaign route: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("tracker calls %d", client.calls)
	}

	// TLP:RED never, even through the campaign route.
	client = &stubCreateClient{}
	s, f, _ = pentestSetup(t, pentest.TLPRed, client)
	_, err := s.CreateTicketFromFinding(ctx, CreateTicketInput{TenantID: shared.NewID().String(), FindingID: f.ID().String(), ProjectKey: "SEC", Route: ticketing.RouteCampaign})
	wantRefusal(t, err, ticketing.ReasonTLPRed)
	if client.calls != 0 {
		t.Fatal("tracker called for a TLP:RED finding")
	}
}

// Without a gate wired, pentest content is refused (fail closed).
func TestCreateTicket_NoGateRefusesPentest(t *testing.T) {
	client := &stubCreateClient{}
	s, f, _ := pentestSetup(t, pentest.TLPClear, client)
	s.SetEgressGate(nil)
	_, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{TenantID: shared.NewID().String(), FindingID: f.ID().String(), ProjectKey: "SEC", Route: ticketing.RouteCampaign})
	wantRefusal(t, err, ticketing.ReasonPentestNoCampaign)
}

func TestCheckFindingEgress_Automation(t *testing.T) {
	s, f, _ := pentestSetup(t, pentest.TLPGreen, &stubCreateClient{})
	wantRefusal(t, s.CheckFindingEgress(context.Background(), shared.NewID(), f.ID(), ticketing.RouteAutomation), ticketing.ReasonPentestCampaignOnly)
}

// A status push stops when the campaign is above the limit (raised after the
// issue was created); within the limit it goes on.
func TestStatusPush_Gated(t *testing.T) {
	ctx := context.Background()
	c := &recordingClient{curStatus: "To Do"}
	s, f, _ := pentestSetup(t, pentest.TLPRed, c)
	f.AddWorkItemURI("https://x.atlassian.net/browse/SEC-1")
	if err := f.TransitionStatus(vulnerability.FindingStatusConfirmed, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.TransitionStatus(vulnerability.FindingStatusInProgress, "", nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncFindingStatusToTicket(ctx, shared.NewID(), f.ID(), enabledMapping()); err != nil {
		t.Fatalf("a refused push is skipped, not an error: %v", err)
	}
	if len(c.transitions) != 0 || len(c.comments) != 0 {
		t.Fatalf("TLP:RED push sent: %v %v", c.transitions, c.comments)
	}

	c2 := &recordingClient{curStatus: "To Do"}
	s2, f2, _ := pentestSetup(t, pentest.TLPGreen, c2)
	f2.AddWorkItemURI("https://x.atlassian.net/browse/SEC-2")
	_ = f2.TransitionStatus(vulnerability.FindingStatusConfirmed, "", nil)
	_ = f2.TransitionStatus(vulnerability.FindingStatusInProgress, "", nil)
	if err := s2.SyncFindingStatusToTicket(ctx, shared.NewID(), f2.ID(), enabledMapping()); err != nil {
		t.Fatal(err)
	}
	if len(c2.transitions) != 1 {
		t.Fatalf("green campaign push not sent: %v", c2.transitions)
	}
}

// A task whose findings include a pentest finding gets no issue.
func TestCreateTaskIssue_PentestMemberRefused(t *testing.T) {
	task := newTask(remediation.TaskStateOpen)
	s, c, _, store := taskSync(t, task)
	_, f, repo := pentestSetup(t, pentest.TLPGreen, c)
	s.findingRepo = repo
	s.SetEgressGate(ticketing.NewEgressGate(nil, nil))
	store.members[task.ID] = []shared.ID{f.ID()}
	_, err := s.CreateTaskIssue(context.Background(), CreateTaskIssueInput{TenantID: shared.NewID(), TaskID: task.ID})
	wantRefusal(t, err, ticketing.ReasonPentestCampaignOnly)
	if c.calls != 0 {
		t.Fatal("tracker called for a task with a pentest finding")
	}
}

// Secret findings send no preview, snippet or fingerprint; findings that
// expose data send no free text.
func TestTicketDescription_ContentRules(t *testing.T) {
	sec, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceSecret, "betterleaks", vulnerability.SeverityHigh, "AWS key")
	if err != nil {
		t.Fatal(err)
	}
	sec.SetTitle("AWS key in config.yaml")
	sec.SetSecretMaskedValue("AKIA****MPLE")
	sec.SetSnippet("aws_key = AKIAIOSFODNN7EXAMPLE")
	sec.SetFingerprint("fp-0123456789abcdef")
	desc := ticketDescription(sec)
	for _, leak := range []string{"AKIA****MPLE", "AKIAIOSFODNN7EXAMPLE", "fp-0123456789abcdef", "aws_key"} {
		if strings.Contains(desc, leak) {
			t.Fatalf("secret ticket carries %q:\n%s", leak, desc)
		}
	}

	pii, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceDAST, "zap", vulnerability.SeverityMedium, "records")
	if err != nil {
		t.Fatal(err)
	}
	pii.SetTitle("Customer list exposes jane@example.com")
	pii.SetDescription("rows: jane@example.com, bob@example.com")
	pii.SetLocation("exports/customers.csv", 1, 1, 0, 0)
	if err := pii.SetDataExposureRisk(vulnerability.DataExposureRiskCritical); err != nil {
		t.Fatal(err)
	}
	desc = ticketDescription(pii)
	if strings.Contains(desc, "@example.com") || strings.Contains(ticketSummary(pii), "@example.com") {
		t.Fatalf("data exposure ticket carries free text:\n%s\n%s", ticketSummary(pii), desc)
	}
	if !strings.Contains(desc, "customers.csv") {
		t.Fatalf("data exposure ticket should keep the location:\n%s", desc)
	}
}
