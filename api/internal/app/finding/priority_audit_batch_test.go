package finding

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
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

type fakeBatchAuditRepo struct {
	fakePriorityAuditRepo
	batches [][]PriorityAuditEntry
}

func (r *fakeBatchAuditRepo) LogChanges(_ context.Context, es []PriorityAuditEntry) error {
	r.batches = append(r.batches, append([]PriorityAuditEntry(nil), es...))
	return nil
}

// The batch path writes its audit entries in chunks through LogChanges when
// the repository supports it: one round trip per chunk, not per finding.
func TestLogClassChanges_UsesBatchInChunks(t *testing.T) {
	repo := &fakeBatchAuditRepo{}
	s := newAuditService(repo)
	n := priorityAuditChunk*2 + 7
	entries := make([]PriorityAuditEntry, n)
	for i := range entries {
		entries[i] = PriorityAuditEntry{TenantID: shared.NewID(), FindingID: shared.NewID(), NewClass: vulnerability.PriorityP1}
	}
	s.logClassChanges(context.Background(), entries)
	if len(repo.entries) != 0 {
		t.Fatalf("LogChange called %d times; want the batch path only", len(repo.entries))
	}
	if len(repo.batches) != 3 {
		t.Fatalf("batches = %d, want 3", len(repo.batches))
	}
	total := 0
	for _, b := range repo.batches {
		if len(b) > priorityAuditChunk {
			t.Fatalf("chunk of %d exceeds %d", len(b), priorityAuditChunk)
		}
		total += len(b)
	}
	if total != n {
		t.Fatalf("wrote %d entries, want %d", total, n)
	}
}

// A repository without LogChanges still gets every entry, one by one.
func TestLogClassChanges_FallsBackToSingleWrites(t *testing.T) {
	repo := &fakePriorityAuditRepo{}
	s := newAuditService(repo)
	entries := []PriorityAuditEntry{
		{TenantID: shared.NewID(), FindingID: shared.NewID(), NewClass: vulnerability.PriorityP0},
		{TenantID: shared.NewID(), FindingID: shared.NewID(), NewClass: vulnerability.PriorityP2},
	}
	s.logClassChanges(context.Background(), entries)
	if len(repo.entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(repo.entries))
	}
}

// classChangeEntry records nothing for an unchanged class.
func TestClassChangeEntry_SkipsUnchanged(t *testing.T) {
	s := newAuditService(&fakePriorityAuditRepo{})
	prev := vulnerability.PriorityP1
	if _, ok := s.classChangeEntry(shared.NewID(), mkAuditFinding(t), &prev,
		vulnerability.PriorityClassification{Class: vulnerability.PriorityP1}); ok {
		t.Fatal("unchanged class produced an audit entry")
	}
	if _, ok := s.classChangeEntry(shared.NewID(), mkAuditFinding(t), &prev,
		vulnerability.PriorityClassification{Class: vulnerability.PriorityP0}); !ok {
		t.Fatal("changed class produced no audit entry")
	}
}
