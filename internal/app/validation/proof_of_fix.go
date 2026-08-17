package validation

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// (invariant F4): proof-of-fix retest, agent-dispatch model.
//
// When a finding transitions to `fix_applied`, the API queues a
// validation job for the agent that most recently produced its
// original validation evidence. Outcomes:
//
//   - OutcomeNotDetected → exposure gone → transition finding to
//     resolved.
//   - OutcomeDetected    → fix did not hold → revert to in_progress
//     AND notify the assignee.
//   - Otherwise → no state change; evidence stays visible for
//     manual review.
//
// The API does NOT execute the technique in-process. It calls the
// ValidationDispatcher which queues the job for an agent that
// declares support for the required ExecutorKind.

// ProofOfFixService orchestrates the retest.
type ProofOfFixService struct {
	dispatcher ValidationDispatcher
	selector   Selector
	evidence   *EvidenceStore
	finding    FindingMutator
	notifier   RetestNotifier
	// recorder durably stamps the confirm-or-downgrade verdict; nil is OK
	// (state transitions still happen, the downgrade % metric is just not fed).
	recorder VerdictRecorder
	// capability is how the API learns which ExecutorKinds the
	// current agent fleet advertises. Injected so integration
	// testing can stub it.
	capability AgentCapability
}

// AgentCapability lets the service ask "which ExecutorKinds are
// currently available for this tenant?" before selecting. A real
// implementation looks at agent registrations; the test stub returns
// a static slice.
type AgentCapability interface {
	AvailableExecutorKinds(ctx context.Context, tenantID shared.ID) ([]ExecutorKind, error)
}

// FindingMutator is the narrow contract for loading + saving a
// finding during the transition.
type FindingMutator interface {
	Get(ctx context.Context, tenantID, findingID shared.ID) (*vulnerability.Finding, error)
	Update(ctx context.Context, f *vulnerability.Finding) error
}

// RetestNotifier posts a message to the assignee when the retest
// refutes the fix. Nil notifier is acceptable — the status revert
// still happens.
type RetestNotifier interface {
	NotifyFixRejected(ctx context.Context, tenantID, findingID shared.ID, reason string) error
}

// NewProofOfFixService wires dependencies.
func NewProofOfFixService(
	dispatcher ValidationDispatcher,
	capability AgentCapability,
	evStore *EvidenceStore,
	findingRepo FindingMutator,
	notifier RetestNotifier,
) *ProofOfFixService {
	return &ProofOfFixService{
		dispatcher: dispatcher,
		selector:   DefaultSelector{},
		evidence:   evStore,
		finding:    findingRepo,
		notifier:   notifier,
		capability: capability,
	}
}

// Retest dispatches a validation job and reconciles the finding.
// Returns the Evidence the agent produced, a boolean indicating
// whether the fix stood (true = finding moved to resolved), and
// any error.
//
// Passing priorKind routes to the same executor that produced the
// original validation when that kind is still available in the
// fleet. Falling back to Selector.Select when it is not.
func (s *ProofOfFixService) Retest(
	ctx context.Context,
	tenantID, findingID shared.ID,
	tid TechniqueID,
	target Target,
	priorKind ExecutorKind,
	profile *AttackerProfile,
) (Evidence, bool, error) {
	if tid == "" {
		return Evidence{}, false, fmt.Errorf("%w: technique is required", shared.ErrValidation)
	}

	available, err := s.capability.AvailableExecutorKinds(ctx, tenantID)
	if err != nil {
		return Evidence{}, false, fmt.Errorf("capability lookup: %w", err)
	}

	kind := priorKind
	if kind == "" || !contains(available, kind) {
		k, err := s.selector.Select(tid, profile, available)
		if err != nil {
			return Evidence{}, false, fmt.Errorf("proof-of-fix: %w", err)
		}
		kind = k
	}

	job := ValidationJob{
		JobID:          shared.NewID(),
		TenantID:       tenantID,
		FindingID:      findingID,
		ExecutorKind:   kind,
		Technique:      tid,
		Target:         target,
		TimeoutSeconds: 120,
	}
	if profile != nil {
		job.ProfileID = profile.ID
	}

	ev, dispErr := s.dispatcher.Submit(ctx, job)
	// Persist evidence regardless — a failed attempt is still
	// historical truth the reviewer can see.
	if _, err := s.evidence.Record(ctx, tenantID, findingID, nil, ev); err != nil {
		// Swallow (logged by EvidenceStore) — classification below
		// is the important side effect.
		_ = err
	}
	if dispErr != nil {
		return ev, false, fmt.Errorf("dispatch: %w", dispErr)
	}

	res, err := applyOutcomeToFinding(ctx, s.finding, s.notifier, s.recorder, tenantID, findingID, ev)
	if err != nil {
		return ev, false, err
	}
	return ev, res.Stood, nil
}

// SetVerdictRecorder wires the durable verdict recorder (validation_outcome /
// downgraded_at). Optional — without it the state transitions still apply.
func (s *ProofOfFixService) SetVerdictRecorder(r VerdictRecorder) { s.recorder = r }

// reconcileResult reports what the confirm-or-downgrade verdict did to a
// finding, so callers can surface it and feed the outcome metric.
type reconcileResult struct {
	// Stood is true when a fix_applied finding was verified and moved to
	// resolved (the proof-of-fix stood).
	Stood bool
	// Downgraded is true when a still-open finding was downgraded to
	// validated_fixed after a not_reproducible verdict (feeds downgrade %).
	Downgraded bool
}

// applyOutcomeToFinding translates an Evidence outcome into the RFC-011.2
// confirm-or-downgrade verdict + finding-state transition. Shared by the
// proof-of-fix retest path and the evidence-ingest path so the mapping has a
// single source of truth. The verdict table (RFC-011.2 §3):
//
//	outcome not_detected  (== VerdictNotReproducible, "exposure gone"):
//	    - fix_applied            → resolved (verified proof-of-fix)   Stood=true
//	    - new/confirmed/in_prog. → validated_fixed (DOWNGRADE)        Downgraded=true
//	    - already validated_fixed→ hold (re-stamp verdict only)
//	outcome detected      (== VerdictReproducible, "still exploitable"):
//	    - fix_applied            → in_progress (fix did not hold, re-open) + notify
//	    - validated_fixed        → confirmed (downgrade refuted — re-open)
//	    - other open states      → hold (stamp "still exploitable")
//	inconclusive/error/skipped   → no verdict, no state change.
//
// The downgrade default is conservative — validated_fixed is NOT a closed state,
// so a human still closes it (validated_fixed→resolved requires findings:verify).
// A non-intrusive re-check is not proof enough to silently close a live finding
// and bypass that gate. Closed / pentest-workflow states are never auto-moved;
// their verdict is still stamped for the record.
//
// recorder (may be nil) durably stamps validation_outcome / downgraded_at so the
// downgrade % metric is measurable; a nil recorder still performs the transition.
func applyOutcomeToFinding(
	ctx context.Context,
	finding FindingMutator,
	notifier RetestNotifier,
	recorder VerdictRecorder,
	tenantID, findingID shared.ID,
	ev Evidence,
) (reconcileResult, error) {
	verdict, hasVerdict := verdictFor(ev.Outcome)
	if !hasVerdict {
		// inconclusive / error / skipped carry no confirm/downgrade signal.
		return reconcileResult{}, nil
	}

	f, err := finding.Get(ctx, tenantID, findingID)
	if err != nil {
		return reconcileResult{}, fmt.Errorf("reload finding: %w", err)
	}

	res := reconcileResult{}
	var downgradedAt *time.Time

	switch verdict {
	case VerdictNotReproducible:
		switch f.Status() {
		case vulnerability.FindingStatusFixApplied:
			// Proof-of-fix confirmed — verified close, NOT a downgrade.
			if err := f.TransitionStatus(vulnerability.FindingStatusResolved, "proof-of-fix: exposure no longer detected", nil); err != nil {
				return reconcileResult{}, fmt.Errorf("transition to resolved: %w", err)
			}
			if err := finding.Update(ctx, f); err != nil {
				return reconcileResult{}, err
			}
			res.Stood = true
		case vulnerability.FindingStatusNew,
			vulnerability.FindingStatusConfirmed,
			vulnerability.FindingStatusInProgress:
			// Downgrade a still-open finding: exposure no longer observable.
			if err := f.TransitionStatus(vulnerability.FindingStatusValidatedFixed, "validation: exposure condition no longer observable", nil); err != nil {
				return reconcileResult{}, fmt.Errorf("transition to validated_fixed: %w", err)
			}
			if err := finding.Update(ctx, f); err != nil {
				return reconcileResult{}, err
			}
			now := time.Now().UTC()
			downgradedAt = &now
			res.Downgraded = true
		default:
			// validated_fixed (re-confirm) / closed / pentest states: hold, stamp only.
		}

	case VerdictReproducible:
		switch f.Status() {
		case vulnerability.FindingStatusFixApplied:
			// Fix did not hold — re-open and notify the assignee.
			if err := f.TransitionStatus(vulnerability.FindingStatusInProgress, "proof-of-fix: fix did not hold", nil); err != nil {
				return reconcileResult{}, fmt.Errorf("transition to in_progress: %w", err)
			}
			if err := finding.Update(ctx, f); err != nil {
				return reconcileResult{}, err
			}
			if notifier != nil {
				_ = notifier.NotifyFixRejected(ctx, tenantID, findingID, ev.Summary)
			}
		case vulnerability.FindingStatusValidatedFixed:
			// A prior downgrade is now refuted — re-open (downgraded_at is left
			// intact so the historical downgrade still counts toward the metric).
			if err := f.TransitionStatus(vulnerability.FindingStatusConfirmed, "validation: exposure reproduced after downgrade", nil); err != nil {
				return reconcileResult{}, fmt.Errorf("reopen validated_fixed: %w", err)
			}
			if err := finding.Update(ctx, f); err != nil {
				return reconcileResult{}, err
			}
		default:
			// open states / closed / pentest: hold state; stamp "still exploitable".
		}
	}

	// Durably stamp the verdict (and downgrade timestamp, when set). Best-effort:
	// a stamp failure must not undo an already-committed state transition, so it
	// is logged by the recorder and swallowed here.
	if recorder != nil {
		if err := recorder.RecordVerdict(ctx, tenantID, findingID, verdict, downgradedAt); err != nil {
			return res, fmt.Errorf("record verdict: %w", err)
		}
	}
	return res, nil
}

func contains(s []ExecutorKind, k ExecutorKind) bool {
	for _, x := range s {
		if x == k {
			return true
		}
	}
	return false
}
