package scan

// Structured refusal codes (RFC-054 §6.5) for what the gate refuses.

import (
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RefusalCodeForState maps an ownership-gate state to its refusal code.
func RefusalCodeForState(s attribution.State) string {
	switch s {
	case attribution.StateRejected:
		return scopedom.RefusalRejected
	case attribution.StateNeedsReview:
		return scopedom.RefusalNeedsReview
	case attribution.StateCandidate:
		return scopedom.RefusalCandidate
	case attribution.StateDependency:
		return scopedom.RefusalDependency
	case attribution.StateMonitorOnly:
		return scopedom.RefusalMonitorOnly
	case attribution.StatePlatformDenied:
		return scopedom.RefusalDenyList
	case attribution.StateProofRequired:
		return scopedom.RefusalProofRequired
	}
	// unattributed, out_of_scope: nothing covers it.
	return scopedom.RefusalNoEntry
}

// RefusalCodeForActReason maps an act-scope reason to its refusal code.
func RefusalCodeForActReason(reason string) string {
	switch reason {
	case actscope.ReasonOutOfDataScope:
		return scopedom.RefusalOutOfDataScope
	case actscope.ReasonNotAnAsset:
		return scopedom.RefusalNotAnAsset
	}
	return scopedom.RefusalNoEntry
}

// refusalError refuses a request as a whole (TARGET_OUT_OF_SCOPE) and lists
// every refused target with its code and fixes in the error details. The
// message keeps the human reasons (bounded, sorted).
func refusalError(refusals []scopedom.Refusal) error {
	sort.Slice(refusals, func(i, j int) bool { return refusals[i].Target < refusals[j].Target })
	parts := make([]string, 0, min(len(refusals), maxListedRefusals)+1)
	for i, r := range refusals {
		if i == maxListedRefusals {
			parts = append(parts, fmt.Sprintf("and %d more", len(refusals)-i))
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", r.Target, r.Message))
	}
	return shared.NewDomainError("TARGET_OUT_OF_SCOPE",
		"You may not scan these targets: "+strings.Join(parts, "; "), shared.ErrValidation).
		WithDetails(map[string]any{"refused": refusals})
}
