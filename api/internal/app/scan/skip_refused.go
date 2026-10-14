package scan

// "Scan the allowed targets, skip the rest" (RFC-054 §6.4): a create that
// asks for it runs the same dry run the Review step showed, saves the scan
// with the targets the gate allows and records the others, with their
// refusal codes, on the scan; every run copies them into its context. The
// remaining targets then pass every normal create check, so this never
// admits a target the gate refuses: if the dry run and the create checks
// disagree, the create is refused as before (fail closed).

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// RunContextKeySkippedTargets holds the targets left out when the scan was
// saved ([]scan.SkippedTarget).
const RunContextKeySkippedTargets = "skipped_targets"

// codeNothingAllowed refuses a skip request when no target is left.
const codeNothingAllowed = "NO_ALLOWED_TARGETS"

// createTier is the probe tier the create of input is checked at, as the
// scope check of the same form: the intensity ceiling of a workflow, the
// scanner's tier for a single scan (capped by an explicit intensity).
func createTier(cat stage.Catalog, input CreateScanInput) int {
	tier := int(scopedom.TierActive)
	if input.ScanType == string(scan.ScanTypeSingle) && input.ScannerName != "" {
		tier = int(ProbeTier(cat, input.ScannerName))
	}
	if i, err := scan.ParseIntensity(input.Intensity); err == nil && input.Intensity != "" {
		if input.ScanType == string(scan.ScanTypeWorkflow) || i.MaxTier() < tier {
			tier = i.MaxTier()
		}
	}
	return tier
}

// partitionRefused splits the direct targets into what the gate allows now
// and what it refuses (with codes), by the dry run of the caller.
func (s *Service) partitionRefused(ctx context.Context, tenantID shared.ID, input CreateScanInput) ([]string, []scan.SkippedTarget, error) {
	if len(input.Targets) == 0 {
		return input.Targets, nil, nil
	}
	pref := input.SensorPreference
	if input.TenantRunner {
		pref = string(scan.SensorPreferenceTenant)
	}
	cat, err := s.catalog(ctx, tenantID)
	if err != nil {
		return nil, nil, err
	}
	tier := createTier(cat, input)
	refused := map[string]string{}
	for i := 0; i < len(input.Targets); i += MaxDryRunTargets {
		batch := input.Targets[i:min(i+MaxDryRunTargets, len(input.Targets))]
		res, err := s.DryRunTargets(ctx, DryRunInput{TenantID: tenantID, Targets: batch, SensorPreference: pref, Tier: tier})
		if err != nil {
			return nil, nil, fmt.Errorf("scope check failed, nothing saved: %w", err)
		}
		for _, r := range res {
			if !r.Allowed {
				refused[strings.ToLower(r.Target)] = r.Code
			}
		}
	}
	kept := make([]string, 0, len(input.Targets))
	skipped := make([]scan.SkippedTarget, 0, len(refused))
	for _, t := range input.Targets {
		if code, no := refused[strings.ToLower(strings.TrimSpace(t))]; no {
			if len(skipped) < scan.MaxSkippedTargets {
				skipped = append(skipped, scan.SkippedTarget{Target: t, Code: code})
			}
			continue
		}
		kept = append(kept, t)
	}
	if len(kept) == 0 && input.AssetGroupID == "" && len(input.AssetGroupIDs) == 0 {
		return nil, nil, shared.NewDomainError(codeNothingAllowed,
			"none of the targets may be scanned now, so there is nothing to start; fix the scope or remove the targets", shared.ErrValidation)
	}
	return kept, skipped, nil
}

// recordSkippedTargets copies the scan's skipped targets into a run context.
func recordSkippedTargets(sc *scan.Scan, runContext map[string]any) {
	if sc == nil || len(sc.SkippedTargets) == 0 || runContext == nil {
		return
	}
	runContext[RunContextKeySkippedTargets] = sc.SkippedTargets
}

// WithRevealResolved lets the scope check show the private address a
// refused hostname resolved to. The wiring sets it only when that answer
// cannot come from the platform's own internal DNS: zone routing resolves
// through a public resolver, or organizations are not self-service (the
// operator runs them). Otherwise the answer could disclose the platform's
// internal names to a tenant.
func WithRevealResolved(on bool) ServiceOption {
	return func(s *Service) { s.revealResolved = on }
}
