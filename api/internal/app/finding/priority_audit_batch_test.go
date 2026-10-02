package finding

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

type fakePriorityAuditRepo struct{ entries []PriorityAuditEntry }

func (r *fakePriorityAuditRepo) LogChange(_ context.Context, e PriorityAuditEntry) error {
	r.entries = append(r.entries, e)
	return nil
}

func newAuditService(repo PriorityAuditRepository) *PriorityClassificationService {
	return &PriorityClassificationService{auditRepo: repo, logger: logger.NewNop()}
}

func mkAuditFinding(t *testing.T) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceVA, "tool", vulnerability.SeverityHigh, "msg")
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	return f
}

// The batch classify path — the MAIN path (ingest + the 12h reclassify sweep) —
// logged nothing to priority_class_audit_log, so "why/when did this become P0"
// had no answer despite classified findings. auditClassChange records it, gated
// on an actual class change.
func TestAuditClassChange_LogsOnChange(t *testing.T) {
	repo := &fakePriorityAuditRepo{}
	s := newAuditService(repo)

	// nil previous (a first classification) is a change: nil -> P1.
	s.auditClassChange(context.Background(), shared.NewID(), mkAuditFinding(t), nil,
		vulnerability.PriorityClassification{Class: vulnerability.PriorityP1, Reason: "r", Source: "auto"})

	if len(repo.entries) != 1 {
		t.Fatalf("logged %d entries, want 1 for a first classification", len(repo.entries))
	}
	if repo.entries[0].NewClass != vulnerability.PriorityP1 {
		t.Errorf("NewClass = %q, want P1", repo.entries[0].NewClass)
	}

	// A real transition P1 -> P0 is logged.
	prev := vulnerability.PriorityP1
	s.auditClassChange(context.Background(), shared.NewID(), mkAuditFinding(t), &prev,
		vulnerability.PriorityClassification{Class: vulnerability.PriorityP0, Reason: "kev", Source: "auto"})
	if len(repo.entries) != 2 {
		t.Fatalf("a P1->P0 transition was not logged (entries=%d)", len(repo.entries))
	}
}

// A re-confirming sweep (same class) must NOT log — otherwise the 12h sweep
// floods the audit log with no-op rows.
func TestAuditClassChange_SkipsWhenUnchanged(t *testing.T) {
	repo := &fakePriorityAuditRepo{}
	s := newAuditService(repo)

	prev := vulnerability.PriorityP2
	s.auditClassChange(context.Background(), shared.NewID(), mkAuditFinding(t), &prev,
		vulnerability.PriorityClassification{Class: vulnerability.PriorityP2, Reason: "same", Source: "auto"})

	if len(repo.entries) != 0 {
		t.Fatalf("logged %d entries for an unchanged class — the sweep would flood "+
			"the audit log with re-confirmations", len(repo.entries))
	}
}

// No audit repo wired must not panic.
func TestAuditClassChange_NilRepoIsSafe(t *testing.T) {
	s := newAuditService(nil)
	s.auditClassChange(context.Background(), shared.NewID(), mkAuditFinding(t), nil,
		vulnerability.PriorityClassification{Class: vulnerability.PriorityP0})
}
