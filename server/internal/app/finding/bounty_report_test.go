package finding

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type bountyStubRepo struct {
	vulnerability.FindingRepository
	byID    map[shared.ID]*vulnerability.Finding
	updates int
}

func (r *bountyStubRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error) {
	f, ok := r.byID[id]
	if !ok || f.TenantID() != tenantID {
		return nil, vulnerability.FindingNotFoundError(id)
	}
	return f, nil
}

func (r *bountyStubRepo) Update(context.Context, *vulnerability.Finding) error {
	r.updates++
	return nil
}

type captureAudit struct{ events []audit.AuditEvent }

func (c *captureAudit) LogEvent(_ context.Context, _ audit.AuditContext, e audit.AuditEvent) error {
	c.events = append(c.events, e)
	return nil
}

func bountyRig(t *testing.T, src vulnerability.FindingSource) (*VulnerabilityService, *bountyStubRepo, *captureAudit, *vulnerability.Finding) {
	t.Helper()
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), src, "bounty-intake", vulnerability.SeverityHigh, "Stored XSS in profile")
	if err != nil {
		t.Fatal(err)
	}
	repo := &bountyStubRepo{byID: map[shared.ID]*vulnerability.Finding{f.ID(): f}}
	svc := NewVulnerabilityService(nil, repo, logger.NewNop())
	aud := &captureAudit{}
	svc.SetAuditService(aud)
	return svc, repo, aud, f
}

func bountyInput(f *vulnerability.Finding, r vulnerability.BountyReport, canTriage bool) UpdateBountyReportInput {
	return UpdateBountyReportInput{TenantID: f.TenantID().String(), FindingID: f.ID().String(), Report: r,
		CanTriage: canTriage, ActorID: shared.NewID().String()}
}

func TestUpdateBountyReport_WriterSetsPlainFields(t *testing.T) {
	svc, repo, aud, f := bountyRig(t, vulnerability.FindingSourceBugBounty)
	got, err := svc.UpdateBountyReport(context.Background(), bountyInput(f,
		vulnerability.BountyReport{Intake: "vdp", Ref: "R-7", State: "triaged", Researcher: "night_owl"}, false))
	if err != nil {
		t.Fatalf("writer setting plain fields: %v", err)
	}
	if r := got.BountyReport(); r == nil || r.State != "triaged" {
		t.Fatalf("stored = %+v", r)
	}
	if repo.updates != 1 || len(aud.events) != 1 {
		t.Fatalf("updates=%d audit=%d, want 1 and 1", repo.updates, len(aud.events))
	}
	e := aud.events[0]
	if e.Action != auditdom.ActionFindingBountyReportChanged || e.ResourceID != f.ID().String() {
		t.Fatalf("audit = %+v", e)
	}
	changes, _ := e.Metadata["changes"].(map[string]bountyFieldChange)
	if c, ok := changes["state"]; !ok || c.Old != nil || c.New != "triaged" {
		t.Fatalf("audit changes = %+v", changes)
	}
}

func TestUpdateBountyReport_RewardAndDisclosureNeedTriage(t *testing.T) {
	ctx := context.Background()
	svc, repo, aud, f := bountyRig(t, vulnerability.FindingSourceBugBounty)
	base := vulnerability.BountyReport{Intake: "vdp", Ref: "R-7"}
	if _, err := svc.UpdateBountyReport(ctx, bountyInput(f, base, false)); err != nil {
		t.Fatal(err)
	}
	updatesBefore, eventsBefore := repo.updates, len(aud.events)

	withReward := base
	withReward.Reward = &vulnerability.BountyReward{Amount: "500", Currency: "USD", Status: "pending"}
	withDisclosure := base
	withDisclosure.Disclosure = &vulnerability.BountyDisclosure{State: "coordinated", AgreedDate: "2026-12-01"}
	for name, r := range map[string]vulnerability.BountyReport{"reward": withReward, "disclosure": withDisclosure} {
		_, err := svc.UpdateBountyReport(ctx, bountyInput(f, r, false))
		var de *shared.DomainError
		if !errors.Is(err, shared.ErrForbidden) || !errors.As(err, &de) || de.Code != "TRIAGE_PERMISSION_REQUIRED" {
			t.Fatalf("%s without triage: want 403 TRIAGE_PERMISSION_REQUIRED, got %v", name, err)
		}
	}
	if repo.updates != updatesBefore || len(aud.events) != eventsBefore || f.BountyReport().Reward != nil {
		t.Fatal("a refused reward change must write nothing")
	}

	// With triage: written and audited with the old and new reward.
	if _, err := svc.UpdateBountyReport(ctx, bountyInput(f, withReward, true)); err != nil {
		t.Fatalf("triager setting reward: %v", err)
	}
	last := aud.events[len(aud.events)-1]
	changes, _ := last.Metadata["changes"].(map[string]bountyFieldChange)
	c, ok := changes["reward"]
	if !ok || c.Old != nil || c.New == nil || last.Severity != auditdom.SeverityMedium {
		t.Fatalf("reward audit = %+v (severity %s)", changes, last.Severity)
	}

	// Clearing a reward is a reward change too.
	if _, err := svc.UpdateBountyReport(ctx, bountyInput(f, base, false)); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("writer clearing the reward: want forbidden, got %v", err)
	}
	// A writer may still change other fields while keeping the reward.
	keep := withReward
	keep.State = "resolved"
	if _, err := svc.UpdateBountyReport(ctx, bountyInput(f, keep, false)); err != nil {
		t.Fatalf("writer changing state with the same reward: %v", err)
	}
}

func TestUpdateBountyReport_Refusals(t *testing.T) {
	ctx := context.Background()

	svc, _, _, manual := bountyRig(t, vulnerability.FindingSourceManual)
	if _, err := svc.UpdateBountyReport(ctx, bountyInput(manual, vulnerability.BountyReport{Intake: "vdp", Ref: "1"}, true)); !errors.Is(err, vulnerability.ErrBountyReportSource) {
		t.Fatalf("manual finding: want ErrBountyReportSource, got %v", err)
	}

	svc, _, _, f := bountyRig(t, vulnerability.FindingSourceBugBounty)
	// Another tenant's id is not found.
	in := bountyInput(f, vulnerability.BountyReport{Intake: "vdp", Ref: "1"}, true)
	in.TenantID = shared.NewID().String()
	if _, err := svc.UpdateBountyReport(ctx, in); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other tenant: want not found, got %v", err)
	}
	if _, err := svc.UpdateBountyReport(ctx, bountyInput(f, vulnerability.BountyReport{Intake: "vdp", Ref: "1", URL: "http://169.254.169.254/"}, true)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("http url: want validation, got %v", err)
	}
	if _, err := svc.UpdateBountyReport(ctx, bountyInput(f, vulnerability.BountyReport{Intake: "vdp", Ref: "1"}, true)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateBountyReport(ctx, bountyInput(f, vulnerability.BountyReport{Intake: "vdp", Ref: "2"}, true)); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("changing ref: want validation, got %v", err)
	}
}

func TestUpdateBountyReport_NoChangeWritesNothing(t *testing.T) {
	ctx := context.Background()
	svc, repo, aud, f := bountyRig(t, vulnerability.FindingSourceBugBounty)
	r := vulnerability.BountyReport{Intake: "vdp", Ref: "1", State: "new"}
	if _, err := svc.UpdateBountyReport(ctx, bountyInput(f, r, false)); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.UpdateBountyReport(ctx, bountyInput(f, r, false)); err != nil {
		t.Fatal(err)
	}
	if repo.updates != 1 || len(aud.events) != 1 {
		t.Fatalf("same report twice: updates=%d audit=%d, want 1 and 1", repo.updates, len(aud.events))
	}
}

func TestApplyBountyReportOnCreate(t *testing.T) {
	newF := func(src vulnerability.FindingSource) *vulnerability.Finding {
		f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), src, "t", vulnerability.SeverityLow, "m")
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	r := &vulnerability.BountyReport{Intake: "vdp", Ref: "1"}
	if err := applyBountyReportOnCreate(newF(vulnerability.FindingSourceDAST), r, true); !errors.Is(err, vulnerability.ErrBountyReportSource) {
		t.Fatalf("dast with a report: %v", err)
	}
	paid := &vulnerability.BountyReport{Intake: "vdp", Ref: "1", Reward: &vulnerability.BountyReward{Status: "paid"}}
	if err := applyBountyReportOnCreate(newF(vulnerability.FindingSourceBugBounty), paid, false); !errors.Is(err, shared.ErrForbidden) {
		t.Fatalf("reward without triage on create: %v", err)
	}
	f := newF(vulnerability.FindingSourceBugBounty)
	if err := applyBountyReportOnCreate(f, paid, true); err != nil || f.BountyReport() == nil {
		t.Fatalf("triager create: %v", err)
	}
	if err := applyBountyReportOnCreate(newF(vulnerability.FindingSourceBugBounty), nil, false); err != nil {
		t.Fatalf("no report: %v", err)
	}
}

// A bug-bounty report is never sent to AI triage automatically.
func TestAutoTriageAllowed_NotForBugBounty(t *testing.T) {
	for src, want := range map[vulnerability.FindingSource]bool{
		vulnerability.FindingSourceBugBounty: false,
		vulnerability.FindingSourceDAST:      true,
		vulnerability.FindingSourceManual:    true,
	} {
		f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(), src, "t", vulnerability.SeverityCritical, "m")
		if err != nil {
			t.Fatal(err)
		}
		if got := autoTriageAllowed(f); got != want {
			t.Errorf("%s: autoTriageAllowed = %v, want %v", src, got, want)
		}
	}
}
