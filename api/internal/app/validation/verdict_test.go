package validation

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// atStatus builds a finding walked to the requested open status via the FSM.
func atStatus(t *testing.T, target vulnerability.FindingStatus) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(
		shared.NewID(), shared.NewID(),
		vulnerability.FindingSourceManual, "T-1",
		vulnerability.SeverityHigh, "test",
	)
	if err != nil {
		t.Fatalf("new finding: %v", err)
	}
	path := map[vulnerability.FindingStatus][]vulnerability.FindingStatus{
		vulnerability.FindingStatusNew:        {},
		vulnerability.FindingStatusConfirmed:  {vulnerability.FindingStatusConfirmed},
		vulnerability.FindingStatusInProgress: {vulnerability.FindingStatusConfirmed, vulnerability.FindingStatusInProgress},
		vulnerability.FindingStatusFixApplied: {vulnerability.FindingStatusConfirmed, vulnerability.FindingStatusInProgress, vulnerability.FindingStatusFixApplied},
	}
	steps, ok := path[target]
	if !ok {
		t.Fatalf("atStatus: unsupported target %s", target)
	}
	for _, st := range steps {
		if err := f.TransitionStatus(st, "", nil); err != nil {
			t.Fatalf("transition %s: %v", st, err)
		}
	}
	return f
}

// ingestFor wires an ingest service with a capture recorder we can assert on.
func ingestFor(f *vulnerability.Finding) (*EvidenceIngestService, *fakeFindingRepo, *captureRecorder) {
	repo := &fakeFindingRepo{current: f}
	rec := &captureRecorder{}
	store := NewEvidenceStore(&memEvidenceRepo{})
	svc := NewEvidenceIngestService(store, repo, nil, rec, logger.NewNop())
	return svc, repo, rec
}

// --- verdict table (RFC-011.2 §3) -------------------------------------------

// not_reproducible on an OPEN finding (new/confirmed/in_progress) → downgrade to
// validated_fixed + stamp not_reproducible + set downgraded_at (feeds metric).
func TestVerdict_NotReproducible_OpenDowngrades(t *testing.T) {
	for _, start := range []vulnerability.FindingStatus{
		vulnerability.FindingStatusNew,
		vulnerability.FindingStatusConfirmed,
		vulnerability.FindingStatusInProgress,
	} {
		t.Run(string(start), func(t *testing.T) {
			svc, repo, rec := ingestFor(atStatus(t, start))
			res, err := svc.Ingest(context.Background(), shared.NewID(), shared.NewID(), nil, Evidence{
				ExecutorKind: "safe-check", Outcome: OutcomeNotDetected,
			})
			if err != nil {
				t.Fatalf("ingest: %v", err)
			}
			if !res.Downgraded {
				t.Fatal("expected Downgraded=true")
			}
			if res.StatusChanged {
				t.Fatal("a downgrade is not a proof-of-fix resolve; StatusChanged must be false")
			}
			if repo.current.Status() != vulnerability.FindingStatusValidatedFixed {
				t.Fatalf("status = %s, want validated_fixed", repo.current.Status())
			}
			if rec.lastVerdict != VerdictNotReproducible {
				t.Fatalf("verdict = %s, want not_reproducible", rec.lastVerdict)
			}
			if rec.downgradedAt == nil {
				t.Fatal("downgraded_at must be stamped on a downgrade")
			}
		})
	}
}

// not_reproducible on a fix_applied finding → resolved (verified proof-of-fix),
// NOT a downgrade (downgraded_at stays nil so it is not counted in the metric).
func TestVerdict_NotReproducible_FixAppliedResolves(t *testing.T) {
	svc, repo, rec := ingestFor(atStatus(t, vulnerability.FindingStatusFixApplied))
	res, err := svc.Ingest(context.Background(), shared.NewID(), shared.NewID(), nil, Evidence{
		ExecutorKind: "safe-check", Outcome: OutcomeNotDetected,
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if !res.StatusChanged {
		t.Fatal("fix_applied + not_reproducible should resolve (StatusChanged=true)")
	}
	if res.Downgraded {
		t.Fatal("a verified proof-of-fix is not a downgrade")
	}
	if repo.current.Status() != vulnerability.FindingStatusResolved {
		t.Fatalf("status = %s, want resolved", repo.current.Status())
	}
	if rec.downgradedAt != nil {
		t.Fatal("downgraded_at must NOT be set for a verified proof-of-fix")
	}
	if rec.lastVerdict != VerdictNotReproducible {
		t.Fatalf("verdict = %s, want not_reproducible", rec.lastVerdict)
	}
}

// reproducible on an OPEN finding → hold state; stamp "reproducible" (still
// exploitable). No transition, no downgrade.
func TestVerdict_Reproducible_OpenHolds(t *testing.T) {
	svc, repo, rec := ingestFor(atStatus(t, vulnerability.FindingStatusConfirmed))
	res, err := svc.Ingest(context.Background(), shared.NewID(), shared.NewID(), nil, Evidence{
		ExecutorKind: "nuclei", Outcome: OutcomeDetected, Summary: "still exploitable",
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res.StatusChanged || res.Downgraded {
		t.Fatal("reproducible on an open finding must hold state")
	}
	if repo.current.Status() != vulnerability.FindingStatusConfirmed {
		t.Fatalf("status = %s, want confirmed (held)", repo.current.Status())
	}
	if rec.lastVerdict != VerdictReproducible {
		t.Fatalf("verdict = %s, want reproducible", rec.lastVerdict)
	}
	if rec.downgradedAt != nil {
		t.Fatal("reproducible must not stamp downgraded_at")
	}
}

// reproducible on a fix_applied finding → re-open (fix did not hold).
func TestVerdict_Reproducible_FixAppliedReopens(t *testing.T) {
	svc, repo, rec := ingestFor(atStatus(t, vulnerability.FindingStatusFixApplied))
	if _, err := svc.Ingest(context.Background(), shared.NewID(), shared.NewID(), nil, Evidence{
		ExecutorKind: "nuclei", Outcome: OutcomeDetected, Summary: "regression",
	}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if repo.current.Status() != vulnerability.FindingStatusInProgress {
		t.Fatalf("status = %s, want in_progress (re-opened)", repo.current.Status())
	}
	if rec.lastVerdict != VerdictReproducible {
		t.Fatalf("verdict = %s, want reproducible", rec.lastVerdict)
	}
}

// reproducible after a prior downgrade (validated_fixed) → re-open to confirmed.
func TestVerdict_Reproducible_AfterDowngradeReopens(t *testing.T) {
	f := atStatus(t, vulnerability.FindingStatusConfirmed)
	svc, repo, _ := ingestFor(f)
	// First: downgrade it.
	if _, err := svc.Ingest(context.Background(), shared.NewID(), shared.NewID(), nil, Evidence{
		ExecutorKind: "safe-check", Outcome: OutcomeNotDetected,
	}); err != nil {
		t.Fatalf("ingest downgrade: %v", err)
	}
	if repo.current.Status() != vulnerability.FindingStatusValidatedFixed {
		t.Fatalf("precondition: want validated_fixed, got %s", repo.current.Status())
	}
	// Then: it reproduces again.
	if _, err := svc.Ingest(context.Background(), shared.NewID(), shared.NewID(), nil, Evidence{
		ExecutorKind: "nuclei", Outcome: OutcomeDetected, Summary: "came back",
	}); err != nil {
		t.Fatalf("ingest reproduce: %v", err)
	}
	if repo.current.Status() != vulnerability.FindingStatusConfirmed {
		t.Fatalf("status = %s, want confirmed (re-opened after refuted downgrade)", repo.current.Status())
	}
}

// inconclusive / error / skipped carry no verdict: no transition, no stamp.
func TestVerdict_NoSignal_NoOp(t *testing.T) {
	for _, oc := range []Outcome{OutcomeInconclusive, OutcomeError, OutcomeSkipped} {
		t.Run(string(oc), func(t *testing.T) {
			svc, repo, rec := ingestFor(atStatus(t, vulnerability.FindingStatusConfirmed))
			if _, err := svc.Ingest(context.Background(), shared.NewID(), shared.NewID(), nil, Evidence{
				ExecutorKind: "safe-check", Outcome: oc,
			}); err != nil {
				t.Fatalf("ingest: %v", err)
			}
			if repo.current.Status() != vulnerability.FindingStatusConfirmed {
				t.Fatalf("status changed on %s: %s", oc, repo.current.Status())
			}
			if rec.calls != 0 {
				t.Fatalf("%s must not stamp a verdict", oc)
			}
		})
	}
}

// back-compat: a finding never validated has no verdict recorded; the recorder
// is never called for a no-signal outcome and the finding is untouched.
func TestVerdict_BackCompat_NilRecorderTolerated(t *testing.T) {
	repo := &fakeFindingRepo{current: atStatus(t, vulnerability.FindingStatusConfirmed)}
	store := NewEvidenceStore(&memEvidenceRepo{})
	// nil recorder must not panic; the downgrade transition still happens.
	svc := NewEvidenceIngestService(store, repo, nil, nil, logger.NewNop())
	res, err := svc.Ingest(context.Background(), shared.NewID(), shared.NewID(), nil, Evidence{
		ExecutorKind: "safe-check", Outcome: OutcomeNotDetected,
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if !res.Downgraded {
		t.Fatal("downgrade transition must still happen without a recorder")
	}
	if repo.current.Status() != vulnerability.FindingStatusValidatedFixed {
		t.Fatalf("status = %s, want validated_fixed", repo.current.Status())
	}
}

// --- downgrade % metric ------------------------------------------------------

func TestDowngradePct(t *testing.T) {
	cases := []struct {
		name                  string
		downgraded, validated int
		want                  float64
	}{
		{"nothing validated", 0, 0, 0},
		{"none downgraded", 0, 10, 0},
		{"a third", 3, 9, float64(3) / float64(9) * 100},
		{"benchmark band", 35, 100, 35},
		{"all downgraded", 5, 5, 100},
		{"clamp on bad input", 12, 10, 100},
		{"negative guarded", -1, 10, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := DowngradePct(c.downgraded, c.validated)
			if diff := got - c.want; diff > 1e-9 || diff < -1e-9 {
				t.Fatalf("DowngradePct(%d,%d) = %v, want %v", c.downgraded, c.validated, got, c.want)
			}
		})
	}
}
