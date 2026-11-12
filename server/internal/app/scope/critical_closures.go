package scope

// A permanent not_ours or retired exclusion closes the open findings of the
// assets it matches (effects.go). When some of them are in the critical tier
// (critical severity, P0 or KEV; vulnerability.FindingRiskTier), marking the
// asset out of scope could hide a real exposure, so the caller must confirm
// it: the request is refused with EXCLUSION_CLOSES_CRITICAL_FINDINGS and the
// count until it says confirm_critical (research/438). The count is the
// whole organization's, taken after the data scope reach check
// (exclusion_reach.go), so a member with limited access only ever counts
// assets they can see.

import (
	"context"
	"fmt"

	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// CodeClosesCriticalFindings is the error code of a closing exclusion that
// needs the critical-findings confirm.
const CodeClosesCriticalFindings = "EXCLUSION_CLOSES_CRITICAL_FINDINGS"

// ErrClosesCriticalFindings is the refusal (errors.Is target).
var ErrClosesCriticalFindings = shared.NewDomainError(CodeClosesCriticalFindings,
	"This would close critical, P0 or KEV findings; confirm to continue", shared.ErrConflict)

// CriticalClosuresError is the refusal with the number of open
// critical-tier findings the exclusion would close (the API returns it in
// details.critical_findings).
type CriticalClosuresError struct{ Count int }

func (e *CriticalClosuresError) Error() string {
	return fmt.Sprintf("This would close %d open critical, P0 or KEV finding(s) as out of scope (not fixed). "+
		"Confirm to continue, or mark it Do not scan to keep them open", e.Count)
}

// Unwrap makes errors.Is(err, ErrClosesCriticalFindings) and
// errors.Is(err, shared.ErrConflict) hold.
func (e *CriticalClosuresError) Unwrap() error { return ErrClosesCriticalFindings }

// checkCriticalClosures refuses closing items whose matched assets hold
// open critical-tier findings, unless confirmed. Without the match counter
// it refuses (fail closed).
func (s *Service) checkCriticalClosures(ctx context.Context, tenantID shared.ID, items []BulkExclusionItem, confirmed bool) error {
	if confirmed || len(items) == 0 {
		return nil
	}
	if s.exclusionMatches == nil {
		return fmt.Errorf("%w: closing exclusions need the findings check", ErrClosesCriticalFindings)
	}
	matches, err := s.exclusionMatches.ExclusionMatches(ctx, tenantID, nil, items)
	if err != nil {
		return err
	}
	n := 0
	for _, m := range matches {
		n += m.CriticalFindings
	}
	if n > 0 {
		return &CriticalClosuresError{Count: n}
	}
	return nil
}

// checkBulkCriticalClosures is checkCriticalClosures for a bulk request that
// closes findings (a closing kind, no end date), over its valid items, so
// nothing is written before the caller confirmed.
func (s *Service) checkBulkCriticalClosures(ctx context.Context, in BulkExclusionsInput) error {
	kind, err := scopedom.ParseExclusionKind(in.Kind)
	if err != nil {
		return err
	}
	if !kind.ClosesFindings() || in.ExpiresAt != nil || in.ConfirmCritical {
		return nil
	}
	tid, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	valid := make([]BulkExclusionItem, 0, len(in.Items))
	for _, it := range in.Items {
		if t, err := itemType(it); err == nil && scopedom.ExclusionTypeNamesAssets(t) {
			valid = append(valid, BulkExclusionItem{ExclusionType: string(t), Pattern: it.Pattern})
		}
	}
	return s.checkCriticalClosures(ctx, tid, valid, false)
}
