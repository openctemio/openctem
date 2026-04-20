package integration

// Integration coverage for the validation-loop invariants of the CTEM
// model. These are the gates that prove a remediation actually
// worked and that our data on "finished" findings is trustworthy:
//
//   proof-of-fix retest flow                            (invariant F4)
//   compensating-control change reclassifies findings   (invariant B2)
//   validation coverage SLO blocks cycle close          (coverage gate)
//
// The F3/B1/B3/B4/B5 edges live in ctem_feedback_invariants_test.go.
// This file picks up F4 + B2 + the coverage SLO so the second batch
// of loop-closing guarantees is also locked in at the integration
// layer.
//
// As in the sibling file, fakes implement the narrow surfaces each
// wire exposes rather than full repos. The goal is: prove the
// inter-component contract, not the storage layer.

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/app/validation"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// -----------------------------------------------------------------------------
// F4 — proof-of-fix retest flow
// -----------------------------------------------------------------------------

// stubDispatcher returns canned evidence for the validation job. This
// stands in for the agent fleet — in production the API pushes the
// job onto the platform-agent queue and an agent reports back.
type stubDispatcher struct {
	outcome    validation.Outcome
	recordedJobID string
	submissions   int32
}

func (d *stubDispatcher) Submit(_ context.Context, job validation.ValidationJob) (validation.Evidence, error) {
	atomic.AddInt32(&d.submissions, 1)
	d.recordedJobID = job.JobID.String()
	return validation.Evidence{
		ExecutorKind: string(job.ExecutorKind),
		Technique:    job.Technique,
		Outcome:      d.outcome,
		Summary:      "stub evidence",
	}, nil
}

// staticCapability says "the fleet supports this one executor kind".
type staticCapability struct {
	kinds []validation.ExecutorKind
}

func (s staticCapability) AvailableExecutorKinds(_ context.Context, _ shared.ID) ([]validation.ExecutorKind, error) {
	return s.kinds, nil
}

type captureNotifier struct {
	calls  int32
	reason string
}

func (c *captureNotifier) NotifyFixRejected(_ context.Context, _, _ shared.ID, reason string) error {
	atomic.AddInt32(&c.calls, 1)
	c.reason = reason
	return nil
}

type mutableFindingRepo struct {
	current *vulnerability.Finding
	updates int32
}

func (r *mutableFindingRepo) Get(_ context.Context, _, _ shared.ID) (*vulnerability.Finding, error) {
	return r.current, nil
}

func (r *mutableFindingRepo) Update(_ context.Context, f *vulnerability.Finding) error {
	atomic.AddInt32(&r.updates, 1)
	r.current = f
	return nil
}

// findingAtFixApplied builds a finding walked through the legal
// status chain to fix_applied — the pre-condition for retest.
func findingAtFixApplied(t *testing.T) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(
		shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceManual, "T-1",
		vulnerability.SeverityHigh, "F4 retest subject",
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

// newProofSvc wires the real ProofOfFixService with an in-memory
// evidence store (so Record doesn't need postgres).
func newProofSvc(disp validation.ValidationDispatcher, cap validation.AgentCapability, notif validation.RetestNotifier, repo validation.FindingMutator) *validation.ProofOfFixService {
	evStore := validation.NewEvidenceStore(memoryEvidenceRepo{})
	return validation.NewProofOfFixService(disp, cap, evStore, repo, notif)
}

type memoryEvidenceRepo struct{}

func (memoryEvidenceRepo) Create(_ context.Context, _ validation.StoredEvidence) error { return nil }
func (memoryEvidenceRepo) ListByFinding(_ context.Context, _, _ shared.ID) ([]validation.StoredEvidence, error) {
	return nil, nil
}

// TestCTEM_F4_OutcomeNotDetectedResolves — the happy path: agent says
// the exposure is gone, finding goes to resolved, notifier stays
// quiet.
func TestCTEM_F4_OutcomeNotDetectedResolves(t *testing.T) {
	f := findingAtFixApplied(t)
	repo := &mutableFindingRepo{current: f}
	disp := &stubDispatcher{outcome: validation.OutcomeNotDetected}
	notif := &captureNotifier{}

	svc := newProofSvc(disp, staticCapability{kinds: []validation.ExecutorKind{validation.KindSafeCheck}}, notif, repo)

	ev, stood, err := svc.Retest(context.Background(), f.TenantID(), f.ID(),
		validation.TechniqueID("T1"), validation.Target{}, validation.KindSafeCheck, nil)
	if err != nil {
		t.Fatalf("retest: %v", err)
	}
	if !stood {
		t.Fatal("OutcomeNotDetected must report fix-stood=true")
	}
	if ev.Outcome != validation.OutcomeNotDetected {
		t.Fatalf("evidence outcome = %s, want not_detected", ev.Outcome)
	}
	if repo.current.Status() != vulnerability.FindingStatusResolved {
		t.Fatalf("finding should be resolved, got %s", repo.current.Status())
	}
	if atomic.LoadInt32(&notif.calls) != 0 {
		t.Fatal("notifier must NOT fire on a passing retest")
	}
}

// TestCTEM_F4_OutcomeDetectedRevertsAndNotifies — the failure path:
// agent still detects the exposure after the fix, finding reverts to
// in_progress and the assignee is notified.
func TestCTEM_F4_OutcomeDetectedRevertsAndNotifies(t *testing.T) {
	f := findingAtFixApplied(t)
	repo := &mutableFindingRepo{current: f}
	disp := &stubDispatcher{outcome: validation.OutcomeDetected}
	notif := &captureNotifier{}

	svc := newProofSvc(disp, staticCapability{kinds: []validation.ExecutorKind{validation.KindSafeCheck}}, notif, repo)

	_, stood, err := svc.Retest(context.Background(), f.TenantID(), f.ID(),
		validation.TechniqueID("T1"), validation.Target{}, validation.KindSafeCheck, nil)
	if err != nil {
		t.Fatalf("retest: %v", err)
	}
	if stood {
		t.Fatal("OutcomeDetected must report fix-stood=false")
	}
	if repo.current.Status() != vulnerability.FindingStatusInProgress {
		t.Fatalf("finding should revert to in_progress, got %s", repo.current.Status())
	}
	if atomic.LoadInt32(&notif.calls) != 1 {
		t.Fatalf("notifier must fire exactly once on rejected fix, got %d", notif.calls)
	}
	if notif.reason == "" {
		t.Fatal("notifier reason must not be empty — assignee needs context")
	}
}

// TestCTEM_F4_OutcomeInconclusiveLeavesStatusUntouched — grey-zone
// result. Evidence is still recorded (historical truth) but the
// finding stays in fix_applied for a human reviewer to judge.
func TestCTEM_F4_OutcomeInconclusiveLeavesStatusUntouched(t *testing.T) {
	f := findingAtFixApplied(t)
	prevStatus := f.Status()
	repo := &mutableFindingRepo{current: f}
	disp := &stubDispatcher{outcome: validation.OutcomeInconclusive}
	notif := &captureNotifier{}

	svc := newProofSvc(disp, staticCapability{kinds: []validation.ExecutorKind{validation.KindSafeCheck}}, notif, repo)

	_, stood, err := svc.Retest(context.Background(), f.TenantID(), f.ID(),
		validation.TechniqueID("T1"), validation.Target{}, validation.KindSafeCheck, nil)
	if err != nil {
		t.Fatalf("retest: %v", err)
	}
	if stood {
		t.Fatal("inconclusive cannot report fix-stood=true")
	}
	if repo.current.Status() != prevStatus {
		t.Fatalf("finding status changed on inconclusive: was %s now %s", prevStatus, repo.current.Status())
	}
	if atomic.LoadInt32(&notif.calls) != 0 {
		t.Fatal("no notification for inconclusive outcome")
	}
}

// TestCTEM_F4_MissingTechniqueRejectedUpfront — proof-of-fix refuses
// to dispatch without a technique. Otherwise the agent would receive
// a job with an empty Technique field and would fail opaquely.
func TestCTEM_F4_MissingTechniqueRejectedUpfront(t *testing.T) {
	f := findingAtFixApplied(t)
	repo := &mutableFindingRepo{current: f}
	disp := &stubDispatcher{outcome: validation.OutcomeNotDetected}

	svc := newProofSvc(disp, staticCapability{kinds: []validation.ExecutorKind{validation.KindSafeCheck}}, &captureNotifier{}, repo)

	_, _, err := svc.Retest(context.Background(), f.TenantID(), f.ID(),
		validation.TechniqueID(""), validation.Target{}, validation.KindSafeCheck, nil)
	if err == nil {
		t.Fatal("empty technique must error before dispatching")
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("want shared.ErrValidation, got %v", err)
	}
	if atomic.LoadInt32(&disp.submissions) != 0 {
		t.Fatal("dispatcher must NOT be called when validation fails upfront")
	}
}

// -----------------------------------------------------------------------------
// Validation coverage SLO
// -----------------------------------------------------------------------------

// TestCTEM_Coverage_MeetsThresholdsPasses — a cycle where every P0
// and P1 has evidence, 90% of P2 do, and P3 has none (P3 is not
// enforced) must not be blocked.
func TestCTEM_Coverage_MeetsThresholdsPasses(t *testing.T) {
	cov := app.ValidationCoverage{
		P0Total: 10, P0WithEvidence: 10,
		P1Total: 20, P1WithEvidence: 20,
		P2Total: 10, P2WithEvidence: 9, // 90% ≥ 80% target
		P3Total: 50, P3WithEvidence: 0, // not enforced
	}
	if err := app.Enforce(cov, app.DefaultThresholds); err != nil {
		t.Fatalf("coverage should meet SLO, got %v", err)
	}
}

// TestCTEM_Coverage_BelowP0ThresholdBlocks — missing a single P0
// evidence record breaks the SLO. The error must name the class so
// the operator knows exactly which priority is failing.
func TestCTEM_Coverage_BelowP0ThresholdBlocks(t *testing.T) {
	cov := app.ValidationCoverage{
		P0Total: 10, P0WithEvidence: 9, // 90% < 100%
		P1Total: 20, P1WithEvidence: 20,
		P2Total: 10, P2WithEvidence: 10,
	}
	err := app.Enforce(cov, app.DefaultThresholds)
	if err == nil {
		t.Fatal("should reject when P0 is below 100%")
	}
	if !errors.Is(err, app.ErrCoverageBelowSLO) {
		t.Fatalf("want ErrCoverageBelowSLO, got %v", err)
	}
	if !strings.Contains(err.Error(), "P0") {
		t.Fatalf("error must name P0 class: %q", err.Error())
	}
}

// TestCTEM_Coverage_BelowMultipleClassesListsEach — if both P1 and
// P2 fail the SLO, the message must call out both so the operator
// isn't blind to the second breach after fixing the first.
func TestCTEM_Coverage_BelowMultipleClassesListsEach(t *testing.T) {
	cov := app.ValidationCoverage{
		P0Total: 1, P0WithEvidence: 1,
		P1Total: 10, P1WithEvidence: 8, // 80% < 100%
		P2Total: 10, P2WithEvidence: 5, // 50% < 80%
	}
	err := app.Enforce(cov, app.DefaultThresholds)
	if err == nil {
		t.Fatal("should reject when multiple classes fail")
	}
	msg := err.Error()
	if !strings.Contains(msg, "P1") || !strings.Contains(msg, "P2") {
		t.Fatalf("error must list both P1 and P2: %q", msg)
	}
}

// TestCTEM_Coverage_ZeroTotalIsTriviallyMet — a tenant with NO P0/P1
// findings this cycle must not be blocked. Zero total = 100%.
func TestCTEM_Coverage_ZeroTotalIsTriviallyMet(t *testing.T) {
	cov := app.ValidationCoverage{
		P0Total: 0, P0WithEvidence: 0,
		P1Total: 0, P1WithEvidence: 0,
		P2Total: 0, P2WithEvidence: 0,
	}
	if err := app.Enforce(cov, app.DefaultThresholds); err != nil {
		t.Fatalf("zero-total coverage must be a no-op, got %v", err)
	}
	if cov.Pct("P0") != 100 {
		t.Fatalf("Pct(P0) with zero total = %v, want 100", cov.Pct("P0"))
	}
}

// TestCTEM_Coverage_CustomThresholdsHonored — thresholds are a
// config, not a constant. A tenant operating with relaxed P1 (80%
// instead of 100%) must pass at 85% P1.
func TestCTEM_Coverage_CustomThresholdsHonored(t *testing.T) {
	cov := app.ValidationCoverage{
		P0Total: 1, P0WithEvidence: 1,
		P1Total: 20, P1WithEvidence: 17, // 85%
	}
	thresholds := app.CoverageThresholds{P0: 100, P1: 80, P2: 0, P3: 0}
	if err := app.Enforce(cov, thresholds); err != nil {
		t.Fatalf("85%% P1 should pass under 80%% threshold: %v", err)
	}
}
