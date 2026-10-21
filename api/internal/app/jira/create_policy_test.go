package jira

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/ticketing"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/ticketpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// memPolicyRepo is an in-memory ticketpolicy.Repository.
type memPolicyRepo struct {
	policy   *ticketpolicy.Policy
	holds    map[shared.ID]ticketpolicy.Hold
	reserved int
	due      []ticketpolicy.Candidate
}

func newMemPolicyRepo(p *ticketpolicy.Policy) *memPolicyRepo {
	return &memPolicyRepo{policy: p, holds: map[shared.ID]ticketpolicy.Hold{}}
}

func (m *memPolicyRepo) Get(context.Context, shared.ID, shared.ID) (ticketpolicy.Policy, error) {
	if m.policy == nil {
		return ticketpolicy.Default(), nil
	}
	return *m.policy, nil
}
func (m *memPolicyRepo) Save(_ context.Context, _, _ shared.ID, p ticketpolicy.Policy) (ticketpolicy.Policy, error) {
	p.UpdatedAt = time.Now()
	m.policy = &p
	return p, nil
}
func (m *memPolicyRepo) Stats(context.Context, shared.ID, shared.ID) (ticketpolicy.Stats, error) {
	return ticketpolicy.Stats{}, nil
}
func (m *memPolicyRepo) Preview(context.Context, shared.ID, shared.ID, ticketpolicy.Policy) (ticketpolicy.Preview, error) {
	return ticketpolicy.Preview{}, nil
}
func (m *memPolicyRepo) PutHold(_ context.Context, h ticketpolicy.Hold) error {
	m.holds[h.FindingID] = h
	return nil
}
func (m *memPolicyRepo) DeleteHold(_ context.Context, _, _, f shared.ID) error {
	delete(m.holds, f)
	return nil
}
func (m *memPolicyRepo) DeleteFindingHolds(_ context.Context, _, f shared.ID) error {
	delete(m.holds, f)
	return nil
}
func (m *memPolicyRepo) ListFindingHolds(context.Context, shared.ID, shared.ID) ([]ticketpolicy.Hold, error) {
	return nil, nil
}
func (m *memPolicyRepo) DueHolds(context.Context, int, time.Duration) ([]ticketpolicy.Candidate, error) {
	return m.due, nil
}
func (m *memPolicyRepo) Reserve(_ context.Context, _, _ shared.ID, dailyCap int) (bool, error) {
	if dailyCap > 0 && m.reserved >= dailyCap {
		return false, nil
	}
	m.reserved++
	return true, nil
}
func (m *memPolicyRepo) Release(context.Context, shared.ID, shared.ID) error {
	m.reserved--
	return nil
}
func (m *memPolicyRepo) PurgeDaily(context.Context, time.Duration) (int64, error) { return 0, nil }

func policyFixture(t *testing.T, sev vulnerability.Severity, p *ticketpolicy.Policy) (*PolicyGate, *siteClient, *memPolicyRepo, *vulnerability.Finding) {
	t.Helper()
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceDAST, "nuclei", sev, "finding")
	if err != nil {
		t.Fatal(err)
	}
	client := &siteClient{intg: shared.NewID(), site: "https://a.atlassian.net"}
	s := newSync(&stubFindingRepo{finding: f}, client)
	m := DefaultMappingConfig()
	m.DefaultProjectKey = "SEC"
	s.SetMappingResolver(stubMappingResolver{mapping: m})
	repo := newMemPolicyRepo(p)
	return NewPolicyGate(s, repo, nil, logger.NewNop()), client, repo, f
}

func autoInput(f *vulnerability.Finding) CreateTicketInput {
	return CreateTicketInput{TenantID: f.TenantID().String(), FindingID: f.ID().String()}
}

// The defaults hold an info finding: nothing reaches Jira, a hold is kept.
func TestAutoCreate_BelowThresholdIsHeld(t *testing.T) {
	g, client, repo, f := policyFixture(t, vulnerability.SeverityInfo, nil)
	info, held, err := g.AutoCreate(context.Background(), autoInput(f))
	if err != nil || info != nil || held == nil || held.Reason != ticketpolicy.ReasonBelowThreshold {
		t.Fatalf("got info=%v held=%+v err=%v", info, held, err)
	}
	if client.calls != 0 {
		t.Fatalf("tracker calls %d, want 0", client.calls)
	}
	if _, ok := repo.holds[f.ID()]; !ok || repo.reserved != 0 {
		t.Fatalf("hold %v reserved %d", repo.holds, repo.reserved)
	}
}

// A high finding passes, takes a slot and is created.
func TestAutoCreate_PassCreates(t *testing.T) {
	g, client, repo, f := policyFixture(t, vulnerability.SeverityHigh, nil)
	repo.holds[f.ID()] = ticketpolicy.Hold{FindingID: f.ID(), Reason: ticketpolicy.ReasonBelowThreshold}
	info, held, err := g.AutoCreate(context.Background(), autoInput(f))
	if err != nil || held != nil || info == nil {
		t.Fatalf("got info=%v held=%+v err=%v", info, held, err)
	}
	if client.calls != 1 || repo.reserved != 1 || len(repo.holds) != 0 {
		t.Fatalf("calls %d reserved %d holds %d", client.calls, repo.reserved, len(repo.holds))
	}
}

// KEV lifts a low finding over the default policy.
func TestAutoCreate_KEVAlways(t *testing.T) {
	g, client, _, f := policyFixture(t, vulnerability.SeverityLow, nil)
	f.SetIsInKEV(true)
	if _, held, err := g.AutoCreate(context.Background(), autoInput(f)); err != nil || held != nil {
		t.Fatalf("held=%+v err=%v", held, err)
	}
	if client.calls != 1 {
		t.Fatalf("tracker calls %d, want 1", client.calls)
	}
}

// Over today's cap the finding is held with reason daily_cap.
func TestAutoCreate_DailyCap(t *testing.T) {
	p := ticketpolicy.Default()
	p.DailyCap = 1
	g, client, repo, f := policyFixture(t, vulnerability.SeverityCritical, &p)
	repo.reserved = 1
	_, held, err := g.AutoCreate(context.Background(), autoInput(f))
	if err != nil || held == nil || held.Reason != ticketpolicy.ReasonDailyCap {
		t.Fatalf("held=%+v err=%v", held, err)
	}
	if client.calls != 0 {
		t.Fatalf("tracker calls %d, want 0", client.calls)
	}
}

// A person's create below the threshold needs the confirmation.
func TestManualCreate_BelowThresholdNeedsConfirm(t *testing.T) {
	g, client, _, f := policyFixture(t, vulnerability.SeverityLow, nil)
	info, below, err := g.ManualCreate(context.Background(), autoInput(f), false)
	if err != nil || info != nil || below == nil {
		t.Fatalf("got info=%v below=%v err=%v", info, below, err)
	}
	if client.calls != 0 {
		t.Fatalf("tracker calls %d, want 0", client.calls)
	}
	info, below, err = g.ManualCreate(context.Background(), autoInput(f), true)
	if err != nil || info == nil || below == nil {
		t.Fatalf("confirmed: info=%v below=%v err=%v", info, below, err)
	}
	if client.calls != 1 {
		t.Fatalf("tracker calls %d, want 1", client.calls)
	}
}

// People are not counted against the cap; above the threshold no
// confirmation is asked.
func TestManualCreate_AboveThreshold(t *testing.T) {
	p := ticketpolicy.Default()
	p.DailyCap = 1
	g, client, repo, f := policyFixture(t, vulnerability.SeverityHigh, &p)
	repo.reserved = 1
	info, below, err := g.ManualCreate(context.Background(), autoInput(f), false)
	if err != nil || info == nil || below != nil || client.calls != 1 {
		t.Fatalf("info=%v below=%v err=%v calls=%d", info, below, err, client.calls)
	}
}

// The release job: a closed finding drops its hold, one still below stays,
// one that now passes is created through the automatic route.
func TestReleaseDue(t *testing.T) {
	g, client, repo, f := policyFixture(t, vulnerability.SeverityHigh, nil)
	closed, below, pass := shared.NewID(), shared.NewID(), f.ID()
	mk := func(id shared.ID, s ticketpolicy.Signals) ticketpolicy.Candidate {
		repo.holds[id] = ticketpolicy.Hold{FindingID: id, Reason: ticketpolicy.ReasonBelowThreshold}
		return ticketpolicy.Candidate{Hold: repo.holds[id], Signals: s, Policy: ticketpolicy.Default()}
	}
	repo.due = []ticketpolicy.Candidate{
		mk(closed, ticketpolicy.Signals{Severity: "critical", Open: false}),
		mk(below, ticketpolicy.Signals{Severity: "low", PriorityClass: "P3", Open: true}),
		mk(pass, ticketpolicy.Signals{Severity: "high", Open: true}),
	}
	for i := range repo.due {
		repo.due[i].TenantID, repo.due[i].IntegrationID = f.TenantID(), client.intg
	}
	n, err := g.ReleaseDue(context.Background(), 10)
	if err != nil || n != 1 {
		t.Fatalf("created %d err %v", n, err)
	}
	if _, ok := repo.holds[closed]; ok {
		t.Fatal("closed finding kept its hold")
	}
	if _, ok := repo.holds[below]; !ok {
		t.Fatal("below-threshold hold removed")
	}
	if _, ok := repo.holds[pass]; ok || client.calls != 1 {
		t.Fatalf("passing hold kept=%v calls=%d", ok, client.calls)
	}
}

// A refused create is kept as create_failed with a platform-worded code and
// its slot is given back.
func TestReleaseDue_EgressRefusalKeepsHold(t *testing.T) {
	g, client, repo, f := policyFixture(t, vulnerability.SeverityHigh, nil)
	g.sync.SetEgressGate(ticketing.NewEgressGate(nil, nil))
	cid := shared.NewID()
	f.SetPentestCampaignID(&cid)
	repo.holds[f.ID()] = ticketpolicy.Hold{FindingID: f.ID()}
	repo.due = []ticketpolicy.Candidate{{
		Hold:    ticketpolicy.Hold{TenantID: f.TenantID(), IntegrationID: client.intg, FindingID: f.ID()},
		Signals: ticketpolicy.Signals{Severity: "high", Open: true}, Policy: ticketpolicy.Default(),
	}}
	if n, _ := g.ReleaseDue(context.Background(), 10); n != 0 {
		t.Fatalf("created %d", n)
	}
	h := repo.holds[f.ID()]
	if h.Reason != ticketpolicy.ReasonCreateFailed || h.Detail == "" || repo.reserved != 0 || client.calls != 0 {
		t.Fatalf("hold %+v reserved %d calls %d", h, repo.reserved, client.calls)
	}
}
