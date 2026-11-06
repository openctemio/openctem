package unit

// Analyst severity override: the service rules (reason, upgrade applies,
// downgrade under the organization's approval policy, approval, restore).
// The database behavior (priority/SLA recompute persisted, re-sightings
// keep the override, the review trigger, data scope) is covered by
// internal/infra/postgres/finding_severity_override_db_test.go.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/pkg/domain/approvalpolicy"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// memSeverityRequests is an in-memory SeverityRequestRepository.
type memSeverityRequests struct {
	reqs     map[shared.ID]*vulnerability.SeverityRequest
	signoffs map[shared.ID][]approvalpolicy.Signoff
	writer   vulnerability.SeverityWriter
}

func newMemSeverityRequests(w vulnerability.SeverityWriter) *memSeverityRequests {
	return &memSeverityRequests{reqs: map[shared.ID]*vulnerability.SeverityRequest{}, signoffs: map[shared.ID][]approvalpolicy.Signoff{}, writer: w}
}

func (m *memSeverityRequests) Create(_ context.Context, r *vulnerability.SeverityRequest) error {
	for _, o := range m.reqs {
		if o.TenantID == r.TenantID && o.FindingID == r.FindingID && o.Status == vulnerability.ApprovalStatusPending {
			return vulnerability.ErrPendingRequestExists
		}
	}
	c := *r
	m.reqs[r.ID] = &c
	return nil
}

func (m *memSeverityRequests) Get(_ context.Context, tenantID, id shared.ID) (*vulnerability.SeverityRequest, error) {
	r, ok := m.reqs[id]
	if !ok || r.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	c := *r
	c.ApprovalsCollected = len(m.signoffs[id])
	return &c, nil
}

func (m *memSeverityRequests) Pending(_ context.Context, tenantID, findingID shared.ID) (*vulnerability.SeverityRequest, error) {
	for _, r := range m.reqs {
		if r.TenantID == tenantID && r.FindingID == findingID && r.Status == vulnerability.ApprovalStatusPending {
			c := *r
			return &c, nil
		}
	}
	return nil, nil //nolint:nilnil // none
}

func (m *memSeverityRequests) Signoffs(_ context.Context, _, id shared.ID) ([]approvalpolicy.Signoff, error) {
	return m.signoffs[id], nil
}

func (m *memSeverityRequests) SignOff(ctx context.Context, tenantID, id shared.ID, s vulnerability.SeveritySignoff,
	decide func(prior []approvalpolicy.Signoff) (bool, error),
	apply func(ctx context.Context, w vulnerability.SeverityWriter) error,
) (bool, error) {
	r, ok := m.reqs[id]
	if !ok || r.TenantID != tenantID {
		return false, shared.ErrNotFound
	}
	complete, err := decide(m.signoffs[id])
	if err != nil {
		return false, err
	}
	m.signoffs[id] = append(m.signoffs[id], approvalpolicy.Signoff{UserID: s.UserID, InSecurityPool: s.SecurityPool})
	if !complete {
		return false, nil
	}
	if err := apply(ctx, m.writer); err != nil {
		return false, err
	}
	r.Status = vulnerability.ApprovalStatusApproved
	by := s.UserID
	r.DecidedBy = &by
	return true, nil
}

func (m *memSeverityRequests) Close(_ context.Context, tenantID, id shared.ID, status vulnerability.ApprovalStatus,
	actor shared.ID, note string, requester *shared.ID,
) error {
	r, ok := m.reqs[id]
	if !ok || r.TenantID != tenantID || r.Status != vulnerability.ApprovalStatusPending {
		return shared.ErrNotFound
	}
	if requester != nil && (r.RequestedBy == nil || *r.RequestedBy != *requester) {
		return shared.ErrNotFound
	}
	r.Status = status
	r.DecidedBy = &actor
	r.DecisionNote = note
	return nil
}

// fpLevel is an organization's approval settings with one false-positive
// level.
type fpLevel string

func (l fpLevel) GetFindingApprovalSettings(_ context.Context, _ string) (*tenantdom.FindingApprovalSettings, error) {
	return &tenantdom.FindingApprovalSettings{FPApproval: string(l)}, nil
}

const longReason = "scanner over-rates this; the service is behind the VPN only"

func severitySvc(t *testing.T, level string) (*finding.VulnerabilityService, *mockFindingRepo, *memSeverityRequests) {
	t.Helper()
	svc, _, repo := newVulnTestService()
	reqs := newMemSeverityRequests(repo)
	svc.SetSeverityRequestRepository(reqs)
	if level != "" {
		svc.SetSoloApproval(nil, nil, fpLevel(level))
	}
	return svc, repo, reqs
}

func change(svc *finding.VulnerabilityService, f *vulnerability.Finding, actor shared.ID, sev, reason string, canApprove bool) (*finding.SeverityChangeResult, error) {
	return svc.ChangeFindingSeverity(context.Background(), finding.ChangeSeverityInput{
		TenantID: f.TenantID().String(), FindingID: f.ID().String(), ActorID: actor.String(),
		Severity: sev, Reason: reason, CanApprove: canApprove,
	})
}

func TestSeverityOverride_UpgradeAppliesWithReason(t *testing.T) {
	svc, repo, _ := severitySvc(t, "")
	tenant := shared.NewID()
	f := createTestFindingWithSeverity(t, svc, tenant.String(), "high")
	actor := shared.NewID()

	res, err := change(svc, f, actor, "critical", "exploited in the wild against our edge", false)
	if err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	if !res.Applied || res.Request != nil {
		t.Fatalf("an upgrade applies at once, got applied=%v request=%v", res.Applied, res.Request)
	}
	got := repo.findings[f.ID().String()]
	if got.Severity() != vulnerability.SeverityCritical || got.SourceSeverity() != vulnerability.SeverityHigh {
		t.Errorf("severity=%s source=%s, want critical over source high", got.Severity(), got.SourceSeverity())
	}
	o := got.SeverityOverride()
	if o == nil || o.By == nil || *o.By != actor || o.Reason != "exploited in the wild against our edge" {
		t.Errorf("override not recorded with author and reason: %+v", o)
	}
}

func TestSeverityOverride_ReasonRequired(t *testing.T) {
	svc, _, _ := severitySvc(t, "")
	f := createTestFindingWithSeverity(t, svc, shared.NewID().String(), "high")
	for _, reason := range []string{"", "   "} {
		if _, err := change(svc, f, shared.NewID(), "critical", reason, false); !errors.Is(err, shared.ErrValidation) {
			t.Errorf("reason %q: want validation error, got %v", reason, err)
		}
	}
	if _, err := change(svc, f, shared.NewID(), "extreme", longReason, false); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("invalid severity: want validation error, got %v", err)
	}
}

func TestSeverityOverride_DowngradeNeedsApprovalUnderLevelAll(t *testing.T) {
	svc, repo, reqs := severitySvc(t, tenantdom.FPApprovalAll)
	f := createTestFindingWithSeverity(t, svc, shared.NewID().String(), "high")
	requester := shared.NewID()

	res, err := change(svc, f, requester, "low", longReason, true)
	if err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	if res.Applied || res.Request == nil || res.Request.Status != vulnerability.ApprovalStatusPending {
		t.Fatalf("a downgrade under level all waits for approval, got applied=%v request=%+v", res.Applied, res.Request)
	}
	if got := repo.findings[f.ID().String()]; got.Severity() != vulnerability.SeverityHigh || got.HasSeverityOverride() {
		t.Errorf("the finding changed before approval: severity=%s", got.Severity())
	}
	// One pending request per finding: another change waits for it.
	if _, err := change(svc, f, requester, "critical", longReason, true); !errors.Is(err, vulnerability.ErrPendingRequestExists) {
		t.Errorf("second change while pending: want ErrPendingRequestExists, got %v", err)
	}

	in := finding.DecideSeverityRequestInput{TenantID: f.TenantID().String(), FindingID: f.ID().String(), RequestID: res.Request.ID.String()}
	// The requester never approves their own request.
	in.ActorID = requester.String()
	if _, err := svc.ApproveSeverityRequest(context.Background(), in); !errors.Is(err, vulnerability.ErrSelfApproval) {
		t.Errorf("self approval: want ErrSelfApproval, got %v", err)
	}
	// Nor rejects it (they withdraw it).
	in.Note = "no"
	if _, err := svc.RejectSeverityRequest(context.Background(), in); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("requester rejecting: want forbidden, got %v", err)
	}
	// Another person approves: the downgrade applies.
	in.ActorID, in.Note = shared.NewID().String(), ""
	out, err := svc.ApproveSeverityRequest(context.Background(), in)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if !out.Applied || out.Finding.Severity() != vulnerability.SeverityLow || out.Finding.SourceSeverity() != vulnerability.SeverityHigh {
		t.Errorf("approved downgrade: applied=%v severity=%s source=%s", out.Applied, out.Finding.Severity(), out.Finding.SourceSeverity())
	}
	if o := out.Finding.SeverityOverride(); o == nil || o.By == nil || *o.By != requester {
		t.Errorf("the override's author is the requester, got %+v", o)
	}
	if r, _ := reqs.Get(context.Background(), f.TenantID(), res.Request.ID); r.Status != vulnerability.ApprovalStatusApproved {
		t.Errorf("request status = %s, want approved", r.Status)
	}
}

func TestSeverityOverride_DowngradeSinglePersonUnderLevelOff(t *testing.T) {
	svc, repo, _ := severitySvc(t, tenantdom.FPApprovalOff)
	f := createTestFindingWithSeverity(t, svc, shared.NewID().String(), "high")

	// Level off lets a holder of findings:approve decide alone.
	res, err := change(svc, f, shared.NewID(), "medium", longReason, true)
	if err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	if !res.Applied || repo.findings[f.ID().String()].Severity() != vulnerability.SeverityMedium {
		t.Fatalf("level off + approver: the downgrade applies at once, got applied=%v", res.Applied)
	}

	// Without findings:approve it is still a request.
	g := createTestFindingWithSeverity(t, svc, shared.NewID().String(), "high")
	res, err = change(svc, g, shared.NewID(), "medium", longReason, false)
	if err != nil {
		t.Fatalf("downgrade without approve: %v", err)
	}
	if res.Applied || res.Request == nil {
		t.Errorf("no approve permission: want a pending request, got applied=%v", res.Applied)
	}
}

func TestSeverityOverride_HighAndAboveMaterialNeedsApproval(t *testing.T) {
	svc, _, _ := severitySvc(t, tenantdom.FPApprovalHighAndAbove)
	// A high finding is material: a downgrade needs a second person.
	f := createTestFindingWithSeverity(t, svc, shared.NewID().String(), "high")
	res, err := change(svc, f, shared.NewID(), "low", longReason, true)
	if err != nil {
		t.Fatalf("downgrade: %v", err)
	}
	if res.Applied {
		t.Error("high_and_above: a downgrade of a high finding must wait for approval")
	}
	// A medium finding is not: the approver decides alone.
	g := createTestFindingWithSeverity(t, svc, shared.NewID().String(), "medium")
	res, err = change(svc, g, shared.NewID(), "low", longReason, true)
	if err != nil {
		t.Fatalf("downgrade medium: %v", err)
	}
	if !res.Applied {
		t.Error("high_and_above: a downgrade of a medium finding applies at once for an approver")
	}
}

func TestSeverityOverride_RestoreSource(t *testing.T) {
	svc, repo, _ := severitySvc(t, tenantdom.FPApprovalAll)
	f := createTestFindingWithSeverity(t, svc, shared.NewID().String(), "medium")
	actor := shared.NewID()

	restore := func(canApprove bool) (*finding.SeverityChangeResult, error) {
		return svc.ChangeFindingSeverity(context.Background(), finding.ChangeSeverityInput{
			TenantID: f.TenantID().String(), FindingID: f.ID().String(), ActorID: actor.String(),
			Restore: true, Reason: longReason, CanApprove: canApprove,
		})
	}
	if _, err := restore(true); !errors.Is(err, shared.ErrValidation) {
		t.Errorf("restore without an override: want validation error, got %v", err)
	}
	// Upgrade (no approval), then restore: back to medium is a downgrade of
	// the effective severity, so under level all it waits for approval.
	if _, err := change(svc, f, actor, "high", longReason, true); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	res, err := restore(true)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if res.Applied || res.Request == nil || !res.Request.Restore {
		t.Fatalf("restore lowering the severity: want a pending restore request, got applied=%v request=%+v", res.Applied, res.Request)
	}
	out, err := svc.ApproveSeverityRequest(context.Background(), finding.DecideSeverityRequestInput{
		TenantID: f.TenantID().String(), FindingID: f.ID().String(), RequestID: res.Request.ID.String(), ActorID: shared.NewID().String(),
	})
	if err != nil {
		t.Fatalf("approve restore: %v", err)
	}
	got := repo.findings[f.ID().String()]
	if !out.Applied || got.Severity() != vulnerability.SeverityMedium || got.HasSeverityOverride() {
		t.Errorf("restored: severity=%s override=%v, want medium and no override", got.Severity(), got.HasSeverityOverride())
	}
}

func TestSeverityOverride_ApproveStaleAndCancel(t *testing.T) {
	svc, repo, _ := severitySvc(t, tenantdom.FPApprovalAll)
	f := createTestFindingWithSeverity(t, svc, shared.NewID().String(), "high")
	requester := shared.NewID()
	res, err := change(svc, f, requester, "low", longReason, false)
	if err != nil || res.Request == nil {
		t.Fatalf("downgrade request: %v", err)
	}
	in := finding.DecideSeverityRequestInput{TenantID: f.TenantID().String(), FindingID: f.ID().String(), RequestID: res.Request.ID.String()}

	// Someone else cannot withdraw it.
	in.ActorID = shared.NewID().String()
	if _, err := svc.CancelSeverityRequest(context.Background(), in); !errors.Is(err, shared.ErrForbidden) {
		t.Errorf("cancel by another person: want forbidden, got %v", err)
	}
	// The severity moved since the request: approving it is refused.
	_ = repo.findings[f.ID().String()].UpdateSeverity(vulnerability.SeverityCritical)
	if _, err := svc.ApproveSeverityRequest(context.Background(), in); !errors.Is(err, vulnerability.ErrSeverityRequestStale) {
		t.Errorf("stale approval: want ErrSeverityRequestStale, got %v", err)
	}
	// The requester withdraws it.
	in.ActorID = requester.String()
	if _, err := svc.CancelSeverityRequest(context.Background(), in); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := svc.ApproveSeverityRequest(context.Background(), in); err == nil {
		t.Error("a withdrawn request cannot be approved")
	}
}

func TestSeverityOverride_RequestOfAnotherFindingNotFound(t *testing.T) {
	svc, _, _ := severitySvc(t, tenantdom.FPApprovalAll)
	tenant := shared.NewID().String()
	f := createTestFindingWithSeverity(t, svc, tenant, "high")
	g := createTestFindingWithSeverity(t, svc, tenant, "high")
	res, err := change(svc, f, shared.NewID(), "low", longReason, false)
	if err != nil || res.Request == nil {
		t.Fatalf("downgrade request: %v", err)
	}
	// The request id under another finding of the same tenant is not found.
	_, err = svc.ApproveSeverityRequest(context.Background(), finding.DecideSeverityRequestInput{
		TenantID: tenant, FindingID: g.ID().String(), RequestID: res.Request.ID.String(), ActorID: shared.NewID().String(),
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("request under another finding: want not found, got %v", err)
	}
	// And under another tenant.
	_, err = svc.ApproveSeverityRequest(context.Background(), finding.DecideSeverityRequestInput{
		TenantID: shared.NewID().String(), FindingID: f.ID().String(), RequestID: res.Request.ID.String(), ActorID: shared.NewID().String(),
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Errorf("request under another tenant: want not found, got %v", err)
	}
}

func TestSeverityOverride_DowngradeWithoutRequestStoreIsRefused(t *testing.T) {
	svc, _, _ := newVulnTestService()
	f := createTestFindingWithSeverity(t, svc, shared.NewID().String(), "high")
	if _, err := change(svc, f, shared.NewID(), "low", longReason, false); !errors.Is(err, shared.ErrNotImplemented) {
		t.Errorf("no request store: want not implemented (fail closed), got %v", err)
	}
}

func TestSeverityOverride_RepoErrorSurfaces(t *testing.T) {
	svc, repo, _ := severitySvc(t, "")
	f := createTestFindingWithSeverity(t, svc, shared.NewID().String(), "high")
	repo.updateErr = errors.New("db error")
	if _, err := change(svc, f, shared.NewID(), "critical", longReason, false); err == nil {
		t.Error("a failed write must surface")
	}
}

func TestSeverityOverride_DomainRules(t *testing.T) {
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityMedium, "m")
	if err != nil {
		t.Fatal(err)
	}
	by := shared.NewID()
	if _, err := f.SetSeverityOverride(vulnerability.SeverityLow, longReason, by, time.Now()); err != nil {
		t.Fatal(err)
	}
	// A re-sighting reporting high moves the source only.
	other, _ := vulnerability.NewFinding(f.TenantID(), f.AssetID(), vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh, "m")
	f.EnrichFrom(other)
	if f.Severity() != vulnerability.SeverityLow || f.SourceSeverity() != vulnerability.SeverityHigh {
		t.Errorf("after re-sighting: severity=%s source=%s, want low over source high", f.Severity(), f.SourceSeverity())
	}
	// Setting the source severity itself ends the override.
	if _, err := f.SetSeverityOverride(vulnerability.SeverityHigh, longReason, by, time.Now()); err != nil {
		t.Fatal(err)
	}
	if f.HasSeverityOverride() || f.Severity() != vulnerability.SeverityHigh {
		t.Errorf("override to the source severity is a restore: override=%v severity=%s", f.HasSeverityOverride(), f.Severity())
	}
	// Without an override a re-sighting keeps the highest severity.
	crit, _ := vulnerability.NewFinding(f.TenantID(), f.AssetID(), vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityCritical, "m")
	f.EnrichFrom(crit)
	if f.Severity() != vulnerability.SeverityCritical || f.HasSeverityOverride() {
		t.Errorf("no override: severity=%s, want critical", f.Severity())
	}
}
