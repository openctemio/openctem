package validation

import (
	"context"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// Q2/WS-D (invariant F4): proof-of-fix retest, agent-dispatch model.
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
	dispatcher    ValidationDispatcher
	selector      Selector
	evidence      *EvidenceStore
	finding       FindingMutator
	notifier      RetestNotifier
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

	stood, err := s.applyOutcome(ctx, tenantID, findingID, ev)
	if err != nil {
		return ev, false, err
	}
	return ev, stood, nil
}

// applyOutcome translates an Evidence outcome into a finding
// status transition.
func (s *ProofOfFixService) applyOutcome(
	ctx context.Context,
	tenantID, findingID shared.ID,
	ev Evidence,
) (bool, error) {
	f, err := s.finding.Get(ctx, tenantID, findingID)
	if err != nil {
		return false, fmt.Errorf("reload finding: %w", err)
	}

	switch ev.Outcome {
	case OutcomeNotDetected:
		if err := f.TransitionStatus(vulnerability.FindingStatusResolved, "proof-of-fix: exposure no longer detected", nil); err != nil {
			return false, fmt.Errorf("transition to resolved: %w", err)
		}
		if err := s.finding.Update(ctx, f); err != nil {
			return false, err
		}
		return true, nil

	case OutcomeDetected:
		if err := f.TransitionStatus(vulnerability.FindingStatusInProgress, "proof-of-fix: fix did not hold", nil); err != nil {
			return false, fmt.Errorf("transition to in_progress: %w", err)
		}
		if err := s.finding.Update(ctx, f); err != nil {
			return false, err
		}
		if s.notifier != nil {
			_ = s.notifier.NotifyFixRejected(ctx, tenantID, findingID, ev.Summary)
		}
		return false, nil

	default:
		return false, nil
	}
}

func contains(s []ExecutorKind, k ExecutorKind) bool {
	for _, x := range s {
		if x == k {
			return true
		}
	}
	return false
}
