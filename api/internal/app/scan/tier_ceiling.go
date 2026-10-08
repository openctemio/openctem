package scan

// Tier ceilings at dispatch (RFC-054 §4.2 step 6): a scope entry authorizes
// probes up to its max_tier; nothing else authorizes (verified domains prove).
// A target the tenant's authority covers only below the probe's tier is
// refused with tier_exceeds on every dispatch path: scan create and quick
// scan refuse the request, a run leaves the target out with a warning, a
// workflow step leaves it out of that step, and the dispatch gate
// (POST /scan-workflows/runs, chained hops, coverage, validation, the dry run)
// reports it refused. Intrusive (t2) workflow steps also need proof per
// step (§8.1): every target at or under a verified domain.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// ProbeTier is the tier a run of the tool probes at (the highest tier of its
// stages; an unknown tool is t1).
func ProbeTier(tool string) scopedom.Tier {
	return scopedom.Tier(stage.ProbeTier(tool))
}

// scanDispatchGate is the gate record of a single-scanner run's commands, for
// the claim-time re-check: the scanner's tier, the run actor's act scope (the
// person who triggered it, else the scan's owner), and the loose ownership
// rule of a passive or takeover-only probe. It never asks more than the
// trigger checked (resolveScanTargets).
func scanDispatchGate(sc *scan.Scan, run *scanrun.Run) *command.DispatchGate {
	tier := ProbeTier(sc.ScannerName)
	g := &command.DispatchGate{
		Tier:     int(tier),
		Passive:  tier <= scopedom.TierPassive || IsTakeoverOnlyProbe(sc.ScannerName, sc.ScannerConfig),
		ActScope: true,
	}
	recorded, _ := run.Context[RunContextKeyActor].(string)
	actor := userIDPtr(recorded)
	if actor == nil {
		actor = userIDPtr(run.TriggeredBy)
	}
	if actor == nil {
		actor = sc.CreatedBy
	}
	if actor != nil && !actor.IsZero() {
		g.Actor = actor.String()
	}
	return g
}

// tierExceeded asks the ownership gate which targets exceed their ceiling
// at tier. A t0 probe exceeds nothing. Without an ownership gate nothing is
// checked here: the paths that need one refuse earlier
// (ErrAttributionGateUnavailable), the others never had one wired.
func (s *Service) tierExceeded(ctx context.Context, tenantID shared.ID, targets []string, tier scopedom.Tier) (map[string]*scopedom.RuleRef, error) {
	if tier <= scopedom.TierPassive || len(targets) == 0 || s.attributionGate == nil {
		return nil, nil
	}
	return s.attributionGate.TierExceeded(ctx, tenantID, targets, tier)
}

// refuseTierExceeded refuses a request (scan create, quick scan) as a whole
// when a target is covered only below the scanner's tier: TARGET_OUT_OF_SCOPE
// with each target's tier_exceeds refusal and fixes.
func (s *Service) refuseTierExceeded(ctx context.Context, tenantID shared.ID, scanner string, targets []string) error {
	if scanner == "" {
		return nil // a workflow: each step is checked at its dispatch
	}
	tier := ProbeTier(scanner)
	over, err := s.tierExceeded(ctx, tenantID, targets, tier)
	if err != nil {
		return fmt.Errorf("tier check failed, nothing saved or dispatched: %w", err)
	}
	if len(over) == 0 {
		return nil
	}
	refusals := make([]scopedom.Refusal, 0, len(over))
	for t, rule := range over {
		refusals = append(refusals, scopedom.NewTierRefusal(t, rule, tier, 0))
	}
	return refusalError(refusals)
}

// dropTierExceeded leaves out of a run the targets covered only below the
// scanner's tier, counting them and naming why in a warning.
func (s *Service) dropTierExceeded(ctx context.Context, tenantID shared.ID, scanner string, r *resolvedTargets) error {
	if scanner == "" || len(r.Targets) == 0 {
		return nil
	}
	tier := ProbeTier(scanner)
	over, err := s.tierExceeded(ctx, tenantID, r.Targets, tier)
	if err != nil {
		return fmt.Errorf("tier check failed, scan not dispatched: %w", err)
	}
	if len(over) == 0 {
		return nil
	}
	kept := r.Targets[:0:0]
	for _, t := range r.Targets {
		if _, no := over[t]; no {
			delete(r.TargetTypes, t)
			continue
		}
		kept = append(kept, t)
	}
	r.TierExceeded = len(r.Targets) - len(kept)
	r.Targets = kept
	r.Warnings = append(r.Warnings, fmt.Sprintf(
		"%d target(s) were skipped: %s runs %s probes and the scope entries covering them allow less (raise the entry's tier in Scoping > Targets)",
		r.TierExceeded, scanner, tier))
	return nil
}

// stepScopeFilter leaves out of one workflow step the targets its tool may
// not probe: those covered only below the tool's tier and, for an intrusive
// (t2) tool, those not at or under a verified domain (proof is checked per
// step: a workflow scan may mix passive, active and intrusive steps). It
// returns the kept targets and a reason naming what was left out.
func (s *Service) stepScopeFilter(ctx context.Context, tenantID shared.ID, tool string, targets []string) ([]string, int, string, error) {
	if tool == "" || len(targets) == 0 {
		return targets, 0, "", nil
	}
	tier := ProbeTier(tool)
	if tier <= scopedom.TierPassive {
		return targets, 0, "", nil
	}
	over, err := s.tierExceeded(ctx, tenantID, targets, tier)
	if err != nil {
		return nil, 0, "", fmt.Errorf("tier check failed, step not dispatched: %w", err)
	}
	unproven := map[string]bool{}
	if tier >= scopedom.TierIntrusive {
		missing, err := s.unverified(ctx, tenantID, targets)
		if err != nil {
			return nil, 0, "", fmt.Errorf("proof check failed, step not dispatched: %w", err)
		}
		for _, m := range missing {
			unproven[m] = true
		}
	}
	if len(over) == 0 && len(unproven) == 0 {
		return targets, 0, "", nil
	}
	kept := make([]string, 0, len(targets))
	var tierOut, proofOut []string
	for _, t := range targets {
		if _, no := over[t]; no {
			tierOut = append(tierOut, t)
			continue
		}
		if unproven[t] {
			proofOut = append(proofOut, t)
			continue
		}
		kept = append(kept, t)
	}
	var reason string
	if len(tierOut) > 0 {
		reason = fmt.Sprintf("%d target(s) covered only below %s by their scope entries (%s)", len(tierOut), tier, listed(tierOut))
	}
	if len(proofOut) > 0 {
		if reason != "" {
			reason += "; "
		}
		reason += fmt.Sprintf("%d target(s) not under a verified domain, which intrusive probes need (%s)", len(proofOut), listed(proofOut))
	}
	return kept, len(tierOut) + len(proofOut), reason, nil
}

// listed names up to maxListedRefusals targets, sorted.
func listed(ts []string) string {
	ts = append([]string(nil), ts...)
	sort.Strings(ts)
	if len(ts) <= maxListedRefusals {
		return strings.Join(ts, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(ts[:maxListedRefusals], ", "), len(ts)-maxListedRefusals)
}

// codeTierExceeds refuses a run whose every target is covered only below
// the scanner's tier.
const codeTierExceeds = "TIER_EXCEEDS"
