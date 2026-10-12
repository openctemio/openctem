package validation

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Confirm-or-downgrade verdict (RFC-011.2 Phase 2a).
//
// A validation re-check produces an Outcome (see executor.go). This file turns
// that Outcome into the finding-level *verdict* the CTEM Validation stage cares
// about — "is this exposure still real?" — and records it durably so the
// downgrade % outcome metric becomes measurable:
//
//	OutcomeNotDetected  →  VerdictNotReproducible  ("exposure no longer observable")
//	OutcomeDetected     →  VerdictReproducible     ("still exploitable")
//
// The verdict string is persisted on findings.validation_outcome by a
// VerdictRecorder. Only OutcomeNotDetected / OutcomeDetected carry a verdict;
// inconclusive / error / skipped leave the finding's recorded verdict untouched.

// Verdict is the persisted finding-level validation verdict value. It is the
// enum stored in findings.validation_outcome (see migration 000209).
type Verdict string

const (
	// VerdictReproducible: the validation re-check still observed the exposure
	// condition. The finding stays open ("still exploitable").
	VerdictReproducible Verdict = "reproducible"
	// VerdictNotReproducible: the validation re-check no longer observed the
	// exposure condition — the input to a confirm-or-downgrade decision.
	VerdictNotReproducible Verdict = "not_reproducible"
)

// verdictFor maps an execution Outcome to the finding-level Verdict. The second
// return is false when the outcome carries no confirm/downgrade signal
// (inconclusive / error / skipped) and the finding's verdict must be left as-is.
func verdictFor(o Outcome) (Verdict, bool) {
	switch o {
	case OutcomeNotDetected:
		return VerdictNotReproducible, true
	case OutcomeDetected:
		return VerdictReproducible, true
	default:
		return "", false
	}
}

// actionableVerdict is the verdict an Evidence may act on, or false when it
// carries none (RFC-039 D3, owner decision 2026-10-03):
//
//   - A reachability probe (safe-check, or an unknown executor) answers "does
//     the host answer", not "is the vulnerability there". It never moves a
//     finding: an open port is not proof the fix failed, a refused connection
//     is not proof it worked. Its evidence stays visible on the finding.
//   - A detection re-run (nuclei, BAS) that matched is a verdict: reproducible.
//   - A detection re-run that did NOT match only counts when the evidence says
//     the target answered (raw_meta.reachable == true). nuclei prints nothing
//     and exits 0 for a host that does not answer, so a bare not_detected is
//     indistinguishable from "host down" — unknown, never fixed. A retest
//     (RFC-039) proves reachability with its own probe and settles the finding
//     itself; this rule only governs plain validation evidence.
func actionableVerdict(ev Evidence) (Verdict, bool) {
	verdict, ok := verdictFor(ev.Outcome)
	if !ok {
		return "", false
	}
	switch ExecutorKind(ev.ExecutorKind) {
	case KindNuclei, KindAtomicRedTeam, KindCaldera:
	default:
		return "", false
	}
	if verdict == VerdictNotReproducible {
		if reachable, _ := ev.RawMeta["reachable"].(bool); !reachable {
			return "", false
		}
	}
	return verdict, true
}

// VerdictRecorder durably stamps the validation verdict on a finding. It is a
// narrow side-write next to the status transition: the status change rides the
// finding entity's normal Update, while validation_outcome / downgraded_at are
// columns the entity round-trip does not carry, so they are written directly.
//
// downgradedAt is non-nil ONLY when a still-open finding is being downgraded to
// validated_fixed; implementations must preserve any existing downgraded_at
// when it is nil (a later reproducible verdict must not erase the downgrade
// history the metric depends on).
//
// A nil VerdictRecorder is tolerated by the verdict logic (the state transition
// still happens); the metric simply is not fed.
type VerdictRecorder interface {
	RecordVerdict(ctx context.Context, tenantID, findingID shared.ID, verdict Verdict, downgradedAt *time.Time) error
}

// DowngradePct computes the CTEM "downgrade %" outcome metric: of the findings
// that have been validated, the share that a validation re-check downgraded
// (verdict not_reproducible on a still-open finding). Returns 0 when nothing has
// been validated yet — an honest "0% measured", distinct from the pre-2a
// "not measured" blank. Result is clamped to [0,100].
func DowngradePct(downgraded, validated int) float64 {
	if validated <= 0 || downgraded <= 0 {
		return 0
	}
	pct := float64(downgraded) / float64(validated) * 100
	if pct > 100 {
		return 100
	}
	return pct
}
