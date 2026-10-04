package retest

import (
	"context"
	"errors"

	retestdom "github.com/openctemio/openctem/api/pkg/domain/retest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// FindingValidator dispatches a plain validation re-check
// (*validation.RunService.ValidateFinding).
type FindingValidator interface {
	ValidateFinding(ctx context.Context, tenantID, findingID shared.ID) (shared.ID, error)
}

// ProofOfFix is what runs when a finding is marked fix_applied — by a person
// (POST /findings/actions/fix-applied) or by a Jira "Done". A finding with a
// deterministic re-check (a nuclei template) gets a proof-of-fix retest: its
// own template plus a reachability probe, so "fixed" means the template no
// longer matched on a target that answered, and "still there" sends it back to
// in_progress. Any other finding falls back to a plain validation re-check,
// whose verdict rule never resolves on a reachability probe or a bare miss
// (RFC-039 D3). It replaces the retired whole-asset verification scan (D4).
type ProofOfFix struct {
	retest   *Service
	fallback FindingValidator
}

// NewProofOfFix wires the validator. fallback may be nil.
func NewProofOfFix(retest *Service, fallback FindingValidator) *ProofOfFix {
	return &ProofOfFix{retest: retest, fallback: fallback}
}

// ValidateFinding implements finding.AutoValidator. It returns the retest id
// (or the validation command id on the fallback path).
func (p *ProofOfFix) ValidateFinding(ctx context.Context, tenantID, findingID shared.ID) (shared.ID, error) {
	if p.retest != nil {
		rt, err := p.retest.Request(ctx, RequestInput{TenantID: tenantID, FindingID: findingID, Trigger: retestdom.TriggerProofOfFix})
		switch {
		case err == nil:
			return rt.ID, nil
		case errors.Is(err, retestdom.ErrNotEligible), errors.Is(err, retestdom.ErrNoSensor):
			// No deterministic re-check for this finding, or no sensor that
			// can run one: fall back to the plain re-check below.
		default:
			return shared.ID{}, err
		}
	}
	if p.fallback == nil {
		return shared.ID{}, retestdom.ErrNotEligible
	}
	return p.fallback.ValidateFinding(ctx, tenantID, findingID)
}
