package validation

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

func newIngestSvc(repo *fakeFindingRepo, evRepo *memEvidenceRepo) (*EvidenceIngestService, *captureNotifier) {
	notif := &captureNotifier{}
	store := NewEvidenceStore(evRepo)
	return NewEvidenceIngestService(store, repo, notif, logger.NewNop()), notif
}

func TestIngest_NotDetected_RecordsAndResolves(t *testing.T) {
	repo := &fakeFindingRepo{current: atFixApplied(t)}
	evRepo := &memEvidenceRepo{}
	svc, notif := newIngestSvc(repo, evRepo)

	tenantID, findingID := shared.NewID(), shared.NewID()
	res, err := svc.Ingest(context.Background(), tenantID, findingID, nil, Evidence{
		ExecutorKind: "safe-check",
		Outcome:      OutcomeNotDetected,
		Summary:      "exposure gone",
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if !res.StatusChanged {
		t.Fatal("status should have changed (resolved)")
	}
	if repo.current.Status() != vulnerability.FindingStatusResolved {
		t.Fatalf("status = %s, want resolved", repo.current.Status())
	}
	if len(evRepo.rows) != 1 {
		t.Fatalf("evidence rows = %d, want 1", len(evRepo.rows))
	}
	if notif.calls != 0 {
		t.Fatal("notifier must not fire when fix stood")
	}
}

func TestIngest_Detected_RevertsAndNotifies(t *testing.T) {
	repo := &fakeFindingRepo{current: atFixApplied(t)}
	evRepo := &memEvidenceRepo{}
	svc, notif := newIngestSvc(repo, evRepo)

	res, err := svc.Ingest(context.Background(), shared.NewID(), shared.NewID(), nil, Evidence{
		ExecutorKind: "nuclei",
		Outcome:      OutcomeDetected,
		Summary:      "still exploitable",
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res.StatusChanged {
		t.Fatal("status must not be 'resolved' for a detected outcome")
	}
	if repo.current.Status() != vulnerability.FindingStatusInProgress {
		t.Fatalf("status = %s, want in_progress", repo.current.Status())
	}
	if notif.calls != 1 || notif.last != "still exploitable" {
		t.Fatalf("notifier calls=%d last=%q", notif.calls, notif.last)
	}
	if len(evRepo.rows) != 1 {
		t.Fatalf("evidence rows = %d, want 1", len(evRepo.rows))
	}
}

func TestIngest_InvalidOutcome_Rejected(t *testing.T) {
	repo := &fakeFindingRepo{current: atFixApplied(t)}
	evRepo := &memEvidenceRepo{}
	svc, _ := newIngestSvc(repo, evRepo)

	_, err := svc.Ingest(context.Background(), shared.NewID(), shared.NewID(), nil, Evidence{
		ExecutorKind: "safe-check",
		Outcome:      Outcome("bogus"),
	})
	if !errors.Is(err, ErrInvalidOutcome) || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrInvalidOutcome/ErrValidation, got %v", err)
	}
	if len(evRepo.rows) != 0 {
		t.Fatal("no evidence should be recorded for an invalid outcome")
	}
}

func TestIngest_FindingNotFound_NotRecorded(t *testing.T) {
	repo := &fakeFindingRepo{getErr: shared.ErrNotFound}
	evRepo := &memEvidenceRepo{}
	svc, _ := newIngestSvc(repo, evRepo)

	_, err := svc.Ingest(context.Background(), shared.NewID(), shared.NewID(), nil, Evidence{
		ExecutorKind: "safe-check",
		Outcome:      OutcomeNotDetected,
	})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
	if len(evRepo.rows) != 0 {
		t.Fatal("no cross-tenant / unknown-finding evidence may be recorded")
	}
}

func TestIngest_TransitionNotAllowed_StillRecords(t *testing.T) {
	// A finding already resolved cannot transition again on a detected outcome;
	// the evidence must still be persisted (non-fatal), StatusChanged=false.
	f := atFixApplied(t)
	if err := f.TransitionStatus(vulnerability.FindingStatusResolved, "", nil); err != nil {
		t.Fatalf("seed resolved: %v", err)
	}
	repo := &fakeFindingRepo{current: f}
	evRepo := &memEvidenceRepo{}
	svc, _ := newIngestSvc(repo, evRepo)

	res, err := svc.Ingest(context.Background(), shared.NewID(), shared.NewID(), nil, Evidence{
		ExecutorKind: "safe-check",
		Outcome:      OutcomeDetected,
		Summary:      "regression",
	})
	if err != nil {
		t.Fatalf("ingest should not hard-fail on a blocked transition: %v", err)
	}
	if res.StatusChanged {
		t.Fatal("status should not have changed")
	}
	if len(evRepo.rows) != 1 {
		t.Fatalf("evidence rows = %d, want 1 (recorded despite blocked transition)", len(evRepo.rows))
	}
}

func TestIngest_ZeroIDs_Rejected(t *testing.T) {
	repo := &fakeFindingRepo{current: atFixApplied(t)}
	svc, _ := newIngestSvc(repo, &memEvidenceRepo{})
	_, err := svc.Ingest(context.Background(), shared.ID{}, shared.NewID(), nil, Evidence{Outcome: OutcomeNotDetected})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation for zero tenant id, got %v", err)
	}
}

func TestIngest_ListForFinding(t *testing.T) {
	repo := &fakeFindingRepo{current: atFixApplied(t)}
	evRepo := &memEvidenceRepo{}
	svc, _ := newIngestSvc(repo, evRepo)

	tenantID, findingID := shared.NewID(), shared.NewID()
	if _, err := svc.Ingest(context.Background(), tenantID, findingID, nil, Evidence{
		ExecutorKind: "safe-check",
		Outcome:      OutcomeInconclusive,
	}); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	list, err := svc.ListForFinding(context.Background(), tenantID, findingID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("list len = %d, want 1", len(list))
	}
}
