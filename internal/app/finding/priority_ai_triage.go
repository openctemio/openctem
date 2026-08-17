package finding

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
)

// AITriageFPThreshold is the false-positive-likelihood at or above which a
// COMPLETED AI triage verdict is treated as a high-confidence "likely false
// positive" and is allowed to DE-ESCALATE a finding's priority by one bounded
// level. Below it, the AI signal has no effect (fail-safe). It is derived from
// the real aitriage.TriageResult.FalsePositiveLikelihood field (0-1) — the only
// confidence signal the triage entity persists.
const AITriageFPThreshold = 0.8

// AIFalsePositiveVerdict is the minimal, SAFE AI-triage signal the priority
// classifier consumes. Likely is true only for a high-confidence false-positive
// verdict (FalsePositiveLikelihood >= AITriageFPThreshold on a completed triage);
// Likelihood carries the raw 0-1 value for the audit reason. The zero value
// (Likely == false) means "no verdict / low confidence" → no effect.
type AIFalsePositiveVerdict struct {
	Likely     bool
	Likelihood float64
}

// AITriageVerdictLookup batch-loads the latest AI-triage false-positive verdict
// per finding, tenant-scoped, in ONE query — so the batch classify path stays
// free of N+1. It returns entries only for findings that carry a high-confidence
// verdict; a nil lookup, an error, or a missing/low-confidence verdict all yield
// "no verdict", which (because AI may only lower priority, and only on a
// high-confidence verdict) means no effect.
type AITriageVerdictLookup interface {
	GetFalsePositiveVerdicts(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) (map[shared.ID]AIFalsePositiveVerdict, error)
}

// SetAITriageVerdictLookup wires the AI-triage false-positive lookup used to
// de-escalate a finding whose latest completed triage flagged it as a
// high-confidence false positive. Optional — nil keeps classification unchanged
// (no AI signal → never a downgrade).
func (s *PriorityClassificationService) SetAITriageVerdictLookup(l AITriageVerdictLookup) {
	s.aiTriage = l
}

// aiFalsePositiveVerdicts fetches the high-confidence false-positive verdicts for
// the given findings. A nil lookup, an empty input, or any error yields a nil map
// (classification proceeds with no AI signal — never a downgrade). Callers read
// per-finding with map indexing; a missing key is the zero verdict (no effect).
func (s *PriorityClassificationService) aiFalsePositiveVerdicts(
	ctx context.Context,
	tenantID shared.ID,
	findingIDs []shared.ID,
) map[shared.ID]AIFalsePositiveVerdict {
	if s.aiTriage == nil || len(findingIDs) == 0 {
		return nil
	}
	m, err := s.aiTriage.GetFalsePositiveVerdicts(ctx, tenantID, findingIDs)
	if err != nil {
		s.logger.Warn("AI triage verdict lookup failed",
			"tenant_id", tenantID.String(), "error", err.Error())
		return nil
	}
	return m
}
