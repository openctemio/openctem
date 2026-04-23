package validation

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// post-refactor: Retest dispatches a job to an agent via the
// ValidationDispatcher interface. The fake dispatcher returns canned
// Evidence so we can pin the finding-status reconciliation.

type fakeDispatcher struct {
	ev          Evidence
	err         error
	recordedJob ValidationJob
}

func (f *fakeDispatcher) Submit(_ context.Context, job ValidationJob) (Evidence, error) {
	f.recordedJob = job
	if f.err != nil {
		return f.ev, f.err
	}
	return f.ev, nil
}

type staticCapability struct {
	kinds []ExecutorKind
	err   error
}

func (s staticCapability) AvailableExecutorKinds(_ context.Context, _ shared.ID) ([]ExecutorKind, error) {
	return s.kinds, s.err
}

type captureNotifier struct {
	mu    sync.Mutex
	calls int
	last  string
}

func (c *captureNotifier) NotifyFixRejected(_ context.Context, _, _ shared.ID, reason string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.last = reason
	return nil
}

type fakeFindingRepo struct {
	current *vulnerability.Finding
	updErr  error
	updates int
}

func (f *fakeFindingRepo) Get(_ context.Context, _, _ shared.ID) (*vulnerability.Finding, error) {
	return f.current, nil
}

func (f *fakeFindingRepo) Update(_ context.Context, fnd *vulnerability.Finding) error {
	if f.updErr != nil {
		return f.updErr
	}
	f.updates++
	f.current = fnd
	return nil
}

func atFixApplied(t *testing.T) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(
		shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceManual, "T-1",
		vulnerability.SeverityHigh, "test",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	for _, st := range []vulnerability.FindingStatus{
		vulnerability.FindingStatusConfirmed,
		vulnerability.FindingStatusInProgress,
		vulnerability.FindingStatusFixApplied,
	} {
		if err := f.TransitionStatus(st, "", nil); err != nil {
			t.Fatalf("transition %s: %v", st, err)
		}
	}
	return f
}

func newProofSvc(disp ValidationDispatcher, cap AgentCapability) (*ProofOfFixService, *fakeFindingRepo, *captureNotifier) {
	repo := &fakeFindingRepo{}
	notif := &captureNotifier{}
	evStore := NewEvidenceStore(&memEvidenceRepo{})
	return NewProofOfFixService(disp, cap, evStore, repo, notif), repo, notif
}

func TestRetest_NotDetected_Resolves(t *testing.T) {
	disp := &fakeDispatcher{ev: Evidence{Outcome: OutcomeNotDetected, ExecutorKind: "safe-check"}}
	cap := staticCapability{kinds: []ExecutorKind{KindSafeCheck}}
	svc, repo, notif := newProofSvc(disp, cap)
	repo.current = atFixApplied(t)

	_, stood, err := svc.Retest(context.Background(), shared.NewID(), shared.NewID(), "T1046", Target{}, "", nil)
	if err != nil {
		t.Fatalf("retest: %v", err)
	}
	if !stood {
		t.Fatal("fix should have stood")
	}
	if repo.current.Status() != vulnerability.FindingStatusResolved {
		t.Fatalf("status = %s, want resolved", repo.current.Status())
	}
	if notif.calls != 0 {
		t.Fatal("notifier must not fire when fix stood")
	}
	if disp.recordedJob.ExecutorKind != KindSafeCheck {
		t.Fatalf("dispatched kind = %q, want safe-check", disp.recordedJob.ExecutorKind)
	}
}

func TestRetest_Detected_RevertsAndNotifies(t *testing.T) {
	disp := &fakeDispatcher{ev: Evidence{Outcome: OutcomeDetected, Summary: "still exploitable"}}
	cap := staticCapability{kinds: []ExecutorKind{KindSafeCheck}}
	svc, repo, notif := newProofSvc(disp, cap)
	repo.current = atFixApplied(t)

	_, stood, err := svc.Retest(context.Background(), shared.NewID(), shared.NewID(), "T1046", Target{}, "", nil)
	if err != nil {
		t.Fatalf("retest: %v", err)
	}
	if stood {
		t.Fatal("fix must NOT have stood")
	}
	if repo.current.Status() != vulnerability.FindingStatusInProgress {
		t.Fatalf("status = %s", repo.current.Status())
	}
	if notif.calls != 1 {
		t.Fatalf("notifier calls = %d, want 1", notif.calls)
	}
	if notif.last != "still exploitable" {
		t.Fatalf("notifier reason = %q", notif.last)
	}
}

func TestRetest_Inconclusive_NoTransition(t *testing.T) {
	disp := &fakeDispatcher{ev: Evidence{Outcome: OutcomeInconclusive}}
	cap := staticCapability{kinds: []ExecutorKind{KindSafeCheck}}
	svc, repo, notif := newProofSvc(disp, cap)
	repo.current = atFixApplied(t)
	start := repo.current.Status()

	_, _, err := svc.Retest(context.Background(), shared.NewID(), shared.NewID(), "T1046", Target{}, "", nil)
	if err != nil {
		t.Fatalf("retest: %v", err)
	}
	if repo.current.Status() != start {
		t.Fatalf("inconclusive must keep status, got %s", repo.current.Status())
	}
	if notif.calls != 0 {
		t.Fatal("inconclusive must not notify")
	}
}

func TestRetest_DispatcherError_PersistsEvidence(t *testing.T) {
	boom := errors.New("agent queue down")
	disp := &fakeDispatcher{ev: Evidence{Outcome: OutcomeError}, err: boom}
	cap := staticCapability{kinds: []ExecutorKind{KindSafeCheck}}
	svc, repo, _ := newProofSvc(disp, cap)
	repo.current = atFixApplied(t)

	_, _, err := svc.Retest(context.Background(), shared.NewID(), shared.NewID(), "T1046", Target{}, "", nil)
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	if repo.current.Status() != vulnerability.FindingStatusFixApplied {
		t.Fatalf("status must be unchanged on dispatch fail, got %s", repo.current.Status())
	}
}

func TestRetest_PriorKindHonoured(t *testing.T) {
	disp := &fakeDispatcher{ev: Evidence{Outcome: OutcomeNotDetected}}
	cap := staticCapability{kinds: []ExecutorKind{KindSafeCheck, KindNuclei}}
	svc, repo, _ := newProofSvc(disp, cap)
	repo.current = atFixApplied(t)

	_, _, err := svc.Retest(context.Background(), shared.NewID(), shared.NewID(), "T1046", Target{}, KindNuclei, nil)
	if err != nil {
		t.Fatal(err)
	}
	if disp.recordedJob.ExecutorKind != KindNuclei {
		t.Fatalf("prior kind not honoured, got %q", disp.recordedJob.ExecutorKind)
	}
}

func TestRetest_PriorKindUnavailable_Reselects(t *testing.T) {
	disp := &fakeDispatcher{ev: Evidence{Outcome: OutcomeNotDetected}}
	cap := staticCapability{kinds: []ExecutorKind{KindSafeCheck}}
	svc, repo, _ := newProofSvc(disp, cap)
	repo.current = atFixApplied(t)

	_, _, err := svc.Retest(context.Background(), shared.NewID(), shared.NewID(), "T1046", Target{}, KindCaldera, nil)
	if err != nil {
		t.Fatal(err)
	}
	if disp.recordedJob.ExecutorKind != KindSafeCheck {
		t.Fatalf("fallback selection failed, got %q", disp.recordedJob.ExecutorKind)
	}
}

func TestRetest_NoAvailableExecutor_Errors(t *testing.T) {
	disp := &fakeDispatcher{}
	cap := staticCapability{kinds: nil}
	svc, repo, _ := newProofSvc(disp, cap)
	repo.current = atFixApplied(t)

	_, _, err := svc.Retest(context.Background(), shared.NewID(), shared.NewID(), "T1046", Target{}, "", nil)
	if !errors.Is(err, ErrNoExecutor) {
		t.Fatalf("want ErrNoExecutor, got %v", err)
	}
}

func TestRetest_EmptyTechnique_Errors(t *testing.T) {
	svc, _, _ := newProofSvc(&fakeDispatcher{}, staticCapability{})
	_, _, err := svc.Retest(context.Background(), shared.NewID(), shared.NewID(), "", Target{}, "", nil)
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want ErrValidation, got %v", err)
	}
}

func TestRetest_CapabilityLookupError(t *testing.T) {
	boom := errors.New("registry down")
	disp := &fakeDispatcher{}
	cap := staticCapability{err: boom}
	svc, _, _ := newProofSvc(disp, cap)

	_, _, err := svc.Retest(context.Background(), shared.NewID(), shared.NewID(), "T1046", Target{}, "", nil)
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
}
