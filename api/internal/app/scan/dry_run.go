package scan

// Dry run of the active-probe gate (RFC-054 §6.4, POST /scope/check): the
// same checks a dispatch runs, for the caller, without dispatching, logging
// or auditing a refusal.

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxDryRunTargets bounds one dry run.
const MaxDryRunTargets = 200

// DryRunInput is what the caller would scan.
type DryRunInput struct {
	TenantID shared.ID
	Targets  []string
	// SensorPreference: auto (default), tenant or platform.
	SensorPreference string
	// Tier: 0 passive, 1 safe active (default), 2 intrusive.
	Tier int
}

// DryRunResult is the gate's answer for one target.
type DryRunResult struct {
	Target  string
	Allowed bool
	// Code is a scopedom.Refusal* code when refused.
	Code     string
	Reason   string
	ZoneID   string
	ZoneName string
}

// DryRunTargets answers what the gate would do with each target for the
// caller. Restricted members get the act-scope answer first, so the dry run
// never tells them anything about assets outside their data scope.
func (s *Service) DryRunTargets(ctx context.Context, in DryRunInput) ([]DryRunResult, error) {
	targets := dedupeTargets(in.Targets)
	if len(targets) > MaxDryRunTargets {
		return nil, fmt.Errorf("%w: at most %d targets per check", shared.ErrValidation, MaxDryRunTargets)
	}
	out := make([]DryRunResult, 0, len(targets))
	if len(targets) == 0 {
		return out, nil
	}
	byTarget := make(map[string]*DryRunResult, len(targets))
	for _, t := range targets {
		out = append(out, DryRunResult{Target: t})
		byTarget[t] = &out[len(out)-1]
	}

	// 1. Act scope first (who may scan what).
	remaining := targets
	if s.actScope != nil {
		d, err := s.actScope.Check(ctx, actscope.Input{TenantID: in.TenantID, Targets: targets})
		if err != nil {
			return nil, fmt.Errorf("act-scope check failed: %w", err)
		}
		remaining = remaining[:0:0]
		for _, t := range targets {
			// Only the actor's own limits answer here; "nothing covers it"
			// is the gate's answer below (it also sees the validator and
			// the platform deny list, which come first).
			if reason, no := d.RefusedTargets[t]; no && RefusalCodeForActReason(reason) != scopedom.RefusalNoEntry {
				r := byTarget[t]
				r.Code, r.Reason = RefusalCodeForActReason(reason), reason
				continue
			}
			remaining = append(remaining, t)
		}
	}
	if len(remaining) == 0 {
		return out, nil
	}

	// 2. The dispatch gate: validator, exclusions, ownership and authority,
	// zones.
	tier := scopedom.Tier(min(max(in.Tier, 0), int(scopedom.TierIntrusive)))
	res, err := s.ResolveDispatchTargets(ctx, DispatchTargetsInput{TenantID: in.TenantID, Targets: remaining, DryRun: true, Tier: &tier})
	if err != nil {
		return nil, err
	}
	for _, t := range res.Excluded {
		if r := byTarget[t]; r != nil {
			r.Code, r.Reason = scopedom.RefusalExcluded, scopedom.RefusalMessages[scopedom.RefusalExcluded]
		}
	}
	for _, rt := range res.Refused {
		if r := byTarget[rt.Target]; r != nil {
			r.Code, r.Reason = rt.Code, rt.Reason
		}
	}

	// 3. Proof: platform sensors under the operator's requirement, and
	// intrusive probes always.
	needProof := in.Tier >= int(scopedom.TierIntrusive) ||
		(in.SensorPreference == "platform" && s.platformNeedsProof())
	allowed := res.Allowed
	if needProof && len(allowed) > 0 {
		missing, err := s.unverified(ctx, in.TenantID, allowed)
		if err != nil {
			return nil, fmt.Errorf("proof check failed: %w", err)
		}
		unproven := make(map[string]bool, len(missing))
		for _, m := range missing {
			unproven[m] = true
		}
		kept := allowed[:0:0]
		for _, t := range allowed {
			if unproven[t] {
				r := byTarget[t]
				r.Code, r.Reason = scopedom.RefusalProofRequired, scopedom.RefusalMessages[scopedom.RefusalProofRequired]
				continue
			}
			kept = append(kept, t)
		}
		allowed = kept
	}
	for _, t := range allowed {
		r := byTarget[t]
		if r == nil {
			continue
		}
		r.Allowed = true
		if z := res.Zone(t); z != nil {
			r.ZoneID, r.ZoneName = z.ID.String(), z.Name
		}
	}
	return out, nil
}
