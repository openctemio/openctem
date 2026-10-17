package ioc

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

type fakeReopenRepo struct {
	f       *vulnerability.Finding
	updates int
	reviews []string
	// changed: the finding moved on after it was read (the guarded UPDATE
	// matches nothing).
	changed bool
}

func (r *fakeReopenRepo) ReopenResolved(_ context.Context, _, _ shared.ID) (bool, error) {
	if r.changed || r.f.Status() != vulnerability.FindingStatusResolved {
		return false, nil
	}
	r.updates++
	return true, r.f.TransitionStatus(vulnerability.FindingStatusConfirmed, "", nil)
}

func (r *fakeReopenRepo) GetByID(_ context.Context, _, _ shared.ID) (*vulnerability.Finding, error) {
	return r.f, nil
}
func (r *fakeReopenRepo) Update(_ context.Context, _ *vulnerability.Finding) error {
	r.updates++
	return nil
}

func (r *fakeReopenRepo) RaiseDecisionReview(_ context.Context, _, _ shared.ID, reason string, _ map[string]any) (bool, error) {
	r.reviews = append(r.reviews, reason)
	return true, nil
}

type capturingAuditor struct{ last audit.AuditEvent }

func (a *capturingAuditor) LogEvent(_ context.Context, _ audit.AuditContext, e audit.AuditEvent) error {
	a.last = e
	return nil
}

// The IOC reopen transitions a closed finding to `confirmed`, but the audit
// event recorded new_status = in_progress — the trail said the finding went
// somewhere it did not. This pins the audited status to the actual transition
// target so they cannot drift apart again.
func TestReopenForIOCMatch_AuditsTheActualNewStatus(t *testing.T) {
	tenantID := shared.NewID()
	assetID := shared.NewID()

	f, err := vulnerability.NewFinding(tenantID, assetID,
		vulnerability.FindingSourceVA, "tool", vulnerability.SeverityHigh, "msg")
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	// Drive it to a closed state so IsClosed() is true and reopen proceeds.
	if err := f.TransitionStatus(vulnerability.FindingStatusConfirmed, "triage", nil); err != nil {
		t.Fatalf("to confirmed: %v", err)
	}
	if err := f.TransitionStatus(vulnerability.FindingStatusResolved, "fixed", nil); err != nil {
		t.Fatalf("to resolved: %v", err)
	}
	if !f.Status().IsClosed() {
		t.Fatalf("precondition: finding not closed (%s)", f.Status())
	}

	auditor := &capturingAuditor{}
	rp := NewFindingReopener(&fakeReopenRepo{f: f}, auditor)

	reopened, err := rp.ReopenForIOCMatch(context.Background(), tenantID, f.ID(), "ioc hit")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !reopened {
		t.Fatal("expected the closed finding to be reopened")
	}

	// The finding actually went to confirmed; the audit must say so.
	if f.Status() != vulnerability.FindingStatusConfirmed {
		t.Fatalf("finding status = %s, want confirmed", f.Status())
	}
	got, _ := auditor.last.Metadata["new_status"].(string)
	if got != string(vulnerability.FindingStatusConfirmed) {
		t.Errorf("audit new_status = %q, want %q — the audit trail must match the "+
			"actual transition, not a different status", got, vulnerability.FindingStatusConfirmed)
	}
}

// A decision a person made (false positive, accepted risk, duplicate) is
// never reversed by an IOC match: the finding keeps its status, nothing is
// written to it, and a review flag is raised instead.
func TestReopenForIOCMatch_DecisionsAreFlaggedNotReopened(t *testing.T) {
	tenantID := shared.NewID()
	for _, decided := range []vulnerability.FindingStatus{
		vulnerability.FindingStatusFalsePositive, vulnerability.FindingStatusAccepted, vulnerability.FindingStatusDuplicate,
	} {
		f := vulnerability.ReconstituteFinding(vulnerability.FindingData{
			ID: shared.NewID(), TenantID: tenantID, AssetID: shared.NewID(), Source: vulnerability.FindingSourceVA,
			ToolName: "tool", Severity: vulnerability.SeverityHigh, Message: "msg", Status: decided,
		})
		repo := &fakeReopenRepo{f: f}
		reopened, err := NewFindingReopener(repo, &capturingAuditor{}).ReopenForIOCMatch(context.Background(), tenantID, f.ID(), "ioc hit")
		if err != nil {
			t.Fatalf("%s: %v", decided, err)
		}
		if reopened || f.Status() != decided || repo.updates != 0 {
			t.Errorf("%s: reopened=%v status=%s updates=%d, want the decision untouched", decided, reopened, f.Status(), repo.updates)
		}
		if len(repo.reviews) != 1 || repo.reviews[0] != "ioc_match" {
			t.Errorf("%s: reviews = %v, want one ioc_match flag", decided, repo.reviews)
		}
	}
}

// A finding someone changed after the correlator read it is never
// overwritten: the guarded reopen matches nothing and nothing is audited.
func TestReopenForIOCMatch_LostUpdateGuard(t *testing.T) {
	tenantID := shared.NewID()
	f := vulnerability.ReconstituteFinding(vulnerability.FindingData{
		ID: shared.NewID(), TenantID: tenantID, AssetID: shared.NewID(), Source: vulnerability.FindingSourceVA,
		ToolName: "tool", Severity: vulnerability.SeverityHigh, Message: "msg", Status: vulnerability.FindingStatusResolved,
	})
	auditor := &capturingAuditor{}
	repo := &fakeReopenRepo{f: f, changed: true}
	reopened, err := NewFindingReopener(repo, auditor).ReopenForIOCMatch(context.Background(), tenantID, f.ID(), "ioc hit")
	if err != nil || reopened || repo.updates != 0 || auditor.last.Action != "" {
		t.Errorf("reopened=%v err=%v updates=%d audit=%q, want nothing", reopened, err, repo.updates, auditor.last.Action)
	}
}
