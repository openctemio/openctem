package ioc

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

type fakeReopenRepo struct{ f *vulnerability.Finding }

func (r *fakeReopenRepo) GetByID(_ context.Context, _, _ shared.ID) (*vulnerability.Finding, error) {
	return r.f, nil
}
func (r *fakeReopenRepo) Update(_ context.Context, _ *vulnerability.Finding) error { return nil }

type capturingAuditor struct{ last app.AuditEvent }

func (a *capturingAuditor) LogEvent(_ context.Context, _ app.AuditContext, e app.AuditEvent) error {
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
