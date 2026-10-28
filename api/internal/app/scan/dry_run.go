package scan

// Dry run of the active-probe gate (RFC-054 §6.4, POST /scope/check): the
// same checks a dispatch runs, for the caller, without dispatching, logging
// or auditing a refusal.

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MaxDryRunTargets bounds one dry run (typed targets and assets together).
const MaxDryRunTargets = 200

// AssetTargetResolver names what a dispatch probes for each of the tenant's
// assets: the asset name first, then the other values an exclusion of the
// asset also matches. An id that is not the tenant's, or a deleted asset, is
// absent. Implemented by *easm.ActiveGate.
type AssetTargetResolver interface {
	AssetTargets(ctx context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID][]string, error)
}

// DryRunInput is what the caller would scan.
type DryRunInput struct {
	TenantID shared.ID
	Targets  []string
	// AssetIDs are inventory assets, checked by their name as a scan of
	// them would be (their other names count for exclusions).
	AssetIDs []shared.ID
	// SensorPreference: auto (default), tenant or platform.
	SensorPreference string
	// Tier: 0 passive, 1 safe active (default), 2 intrusive.
	Tier int
	// Tool is the scanner of a single scan ("" for a workflow): the tenant
	// sensor that would take the job must run it.
	Tool string
}

// DryRunResult is the gate's answer for one target or asset.
type DryRunResult struct {
	// Target is the typed target, or the asset's name. An asset the caller
	// may not see (outside their data scope, another tenant's, deleted)
	// keeps its id here, and nothing else about it is answered.
	Target  string
	AssetID string
	Allowed bool
	// Code is a scopedom.Refusal* code when refused.
	Code     string
	Reason   string
	ZoneID   string
	ZoneName string
	// Resolved are the addresses a hostname resolved to when zone routing
	// refused it (a name that resolves to a private address).
	Resolved []string
}

// DryRunOutcome is the dry run's answer per target and where the job would
// run.
type DryRunOutcome struct {
	Results []DryRunResult
	Routing DryRunRouting
}

// Routing decisions of a dry run (DryRunRouting.RunsOn).
const (
	RoutingTenant   = "tenant"
	RoutingPlatform = "platform"
	// RoutingWaits: no sensor can take the job now; it waits.
	RoutingWaits = "waits"
)

// Reasons for a routing decision (DryRunRouting.Reason).
const (
	// RoutingReasonProof: platform sensors need a verified domain and some
	// targets have none, so auto runs the job on the tenant's sensor.
	RoutingReasonProof = "platform_needs_proof"
	// RoutingReasonTenantFirst: auto runs on the tenant's own sensors first.
	RoutingReasonTenantFirst = "tenant_first"
	// RoutingReasonTenantBusy: the tenant's capable sensors are busy; the
	// job waits for them.
	RoutingReasonTenantBusy = "tenant_busy"
	// RoutingReasonInternal: private targets run on the tenant's sensors.
	RoutingReasonInternal = "internal_targets"
	// RoutingReasonNoTenantSensor: no tenant sensor can take the job.
	RoutingReasonNoTenantSensor = "no_tenant_sensor"
	// RoutingReasonPlatform: the job goes to the platform's sensors.
	RoutingReasonPlatform = "platform_sensors"
)

// DryRunRouting says where the job would run and why. A platform sensor is
// never named (tenants never see platform sensors); the tenant's own sensor
// is.
type DryRunRouting struct {
	Preference string
	RunsOn     string
	Reason     string
	SensorID   string
	SensorName string
}

// DryRunTargets answers what the gate would do with each target and asset
// for the caller (DryRun without the routing).
func (s *Service) DryRunTargets(ctx context.Context, in DryRunInput) ([]DryRunResult, error) {
	out, err := s.DryRun(ctx, in)
	if err != nil {
		return nil, err
	}
	return out.Results, nil
}

// DryRun answers what the gate would do with each target and asset for the
// caller, and where the job would run. Restricted members get the
// act-scope answer first, so the dry run never tells them anything about
// assets outside their data scope.
func (s *Service) DryRun(ctx context.Context, in DryRunInput) (*DryRunOutcome, error) {
	routing := DryRunRouting{Preference: dryRunPreference(in.SensorPreference)}
	results, err := s.dryRunResults(ctx, in, &routing)
	if err != nil {
		return nil, err
	}
	return &DryRunOutcome{Results: results, Routing: routing}, nil
}

// Sensor preferences as the dry run takes them.
const (
	prefAuto     = string(scan.SensorPreferenceAuto)
	prefTenant   = string(scan.SensorPreferenceTenant)
	prefPlatform = string(scan.SensorPreferencePlatform)
)

func dryRunPreference(p string) string {
	if p == prefTenant || p == prefPlatform {
		return p
	}
	return prefAuto
}

// dryRunProof refuses the allowed targets that need proof and lack it, when
// the platform requires proof. Proof is for jobs that run on platform
// sensors, which send from the operator's addresses: a job on the
// organization's own sensor needs none, at any tier (an intrusive probe is
// governed by the scope entry's tier ceiling). In auto mode a job with an
// unproven target runs on the tenant's own sensor (the trigger's rule); only
// without one do those targets need proof, because the job never falls back
// to platform sensors for an unproven target. It also fills routing.
func (s *Service) dryRunProof(ctx context.Context, in DryRunInput, checked, allowed []string, routing *DryRunRouting,
	set func(string, func(*DryRunResult)),
) ([]string, error) {
	var unproven map[string]bool
	if s.platformNeedsProof(ctx) && len(allowed) > 0 && in.SensorPreference != prefTenant {
		missing, err := s.unverified(ctx, in.TenantID, allowed)
		if err != nil {
			return nil, fmt.Errorf("proof check failed: %w", err)
		}
		unproven = make(map[string]bool, len(missing))
		for _, m := range missing {
			unproven[m] = true
		}
	}
	s.decideDryRunRouting(ctx, in, checked, len(unproven) > 0, routing)
	if len(unproven) == 0 || routing.RunsOn == RoutingTenant {
		return allowed, nil
	}
	why := proofReasonNoSensor
	if routing.Preference == prefPlatform {
		why = proofReasonPlatform
	}
	kept := allowed[:0:0]
	for _, t := range allowed {
		if unproven[t] {
			set(t, func(r *DryRunResult) { r.Code, r.Reason = scopedom.RefusalProofRequired, why })
			continue
		}
		kept = append(kept, t)
	}
	return kept, nil
}

// Why an unproven target is refused (the dry run's reason for proof_required).
const (
	proofReasonPlatform = "Platform sensors need a verified domain of your organization. Verify the domain, or run this scan on your own sensor."
	proofReasonNoSensor = "No sensor of yours can run this scan, and platform sensors need a verified domain of your organization. Verify the domain, or connect a sensor."
)

func (s *Service) dryRunResults(ctx context.Context, in DryRunInput, routing *DryRunRouting) ([]DryRunResult, error) {
	targets := dedupeTargets(in.Targets)
	assetIDs := dedupeIDs(in.AssetIDs)
	if len(targets)+len(assetIDs) > MaxDryRunTargets {
		return nil, fmt.Errorf("%w: at most %d targets and assets per check", shared.ErrValidation, MaxDryRunTargets)
	}
	out := make([]DryRunResult, 0, len(targets)+len(assetIDs))
	if len(targets)+len(assetIDs) == 0 {
		return out, nil
	}
	// One result per typed target and per asset; results naming the same
	// target (an asset whose name was also typed) share one answer.
	byTarget := make(map[string][]int, len(targets)+len(assetIDs))
	for _, t := range targets {
		out = append(out, DryRunResult{Target: t})
		byTarget[strings.ToLower(t)] = append(byTarget[strings.ToLower(t)], len(out)-1)
	}
	set := func(target string, f func(r *DryRunResult)) {
		for _, i := range byTarget[strings.ToLower(target)] {
			f(&out[i])
		}
	}

	// 1. Act scope first (who may scan what). An asset the caller may not
	// act on is answered by its id only.
	remaining := targets
	assetsOK := assetIDs
	if s.actScope != nil {
		d, err := s.actScope.Check(ctx, actscope.Input{TenantID: in.TenantID, Targets: targets, AssetIDs: assetIDs})
		if err != nil {
			return nil, fmt.Errorf("act-scope check failed: %w", err)
		}
		remaining = remaining[:0:0]
		for _, t := range targets {
			// Only the actor's own limits answer here; "nothing covers it"
			// is the gate's answer below (it also sees the validator and
			// the platform deny list, which come first).
			if reason, no := d.RefusedTargets[t]; no && RefusalCodeForActReason(reason) != scopedom.RefusalNoEntry {
				set(t, func(r *DryRunResult) { r.Code, r.Reason = RefusalCodeForActReason(reason), reason })
				continue
			}
			remaining = append(remaining, t)
		}
		assetsOK = assetsOK[:0:0]
		for _, id := range assetIDs {
			if d.RefusedAssets[id] {
				out = append(out, outOfDataScope(id))
				continue
			}
			assetsOK = append(assetsOK, id)
		}
	}

	// 2. The assets' names, tenant-scoped. An id that is not the tenant's
	// answers exactly like an asset outside the caller's data scope, so the
	// dry run is no oracle for another tenant's or a hidden asset.
	dispatchAssets, err := s.dryRunAssets(ctx, in.TenantID, assetsOK, &out, byTarget, &remaining)
	if err != nil {
		return nil, err
	}
	if len(remaining) == 0 {
		return out, nil
	}

	// 3. The dispatch gate: validator, exclusions, ownership and authority,
	// zones.
	tier := scopedom.Tier(min(max(in.Tier, 0), int(scopedom.TierIntrusive)))
	// Where the job would run decides whether ownership confirmation applies.
	place := s.placementFor(ctx, in.TenantID, scan.SensorPreference(dryRunPreference(in.SensorPreference)), false, false, scannerTools(in.Tool)...)
	res, err := s.ResolveDispatchTargets(ctx, DispatchTargetsInput{TenantID: in.TenantID, Targets: remaining, Assets: dispatchAssets, DryRun: true, Tier: &tier, Placement: place})
	if err != nil {
		return nil, err
	}
	for _, t := range res.Excluded {
		set(t, func(r *DryRunResult) {
			r.Code, r.Reason = scopedom.RefusalExcluded, scopedom.RefusalMessages[scopedom.RefusalExcluded]
		})
	}
	for _, rt := range res.Refused {
		set(rt.Target, func(r *DryRunResult) { r.Code, r.Reason, r.Resolved = rt.Code, rt.Reason, rt.Resolved })
	}

	// 4. Proof, when the platform requires it: platform sensors need it, the
	// organization's own sensors do not. In auto mode a job with an unproven
	// target runs on the tenant's own sensor (the trigger's rule); only
	// without one does the target need proof.
	allowed, err := s.dryRunProof(ctx, in, remaining, res.Allowed, routing, set)
	if err != nil {
		return nil, err
	}
	// 5. Bug-bounty program targets never go to platform sensors (RFC-065 §8).
	if in.SensorPreference == prefPlatform && len(allowed) > 0 {
		programOnly, err := s.programOnly(ctx, in.TenantID, allowed)
		if err != nil {
			return nil, fmt.Errorf("program target check failed: %w", err)
		}
		refused := make(map[string]bool, len(programOnly))
		for _, t := range programOnly {
			refused[t] = true
		}
		kept := allowed[:0:0]
		for _, t := range allowed {
			if refused[t] {
				set(t, func(r *DryRunResult) {
					r.Code, r.Reason = scopedom.RefusalProgramPlatform, scopedom.RefusalMessages[scopedom.RefusalProgramPlatform]
				})
				continue
			}
			kept = append(kept, t)
		}
		allowed = kept
	}
	for _, t := range allowed {
		z := res.Zone(t)
		set(t, func(r *DryRunResult) {
			r.Allowed = true
			if z != nil {
				r.ZoneID, r.ZoneName = z.ID.String(), z.Name
			}
		})
	}
	return out, nil
}

// dryRunAssets looks the assets up (tenant-scoped), appends one result per
// asset to out, adds the names not already typed to remaining and returns
// the dispatch view of the assets, keyed by lower-cased name. Without a
// resolver nothing is answered (fail closed).
func (s *Service) dryRunAssets(ctx context.Context, tenantID shared.ID, ids []shared.ID, out *[]DryRunResult,
	byTarget map[string][]int, remaining *[]string,
) (map[string]DispatchAsset, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	resolver, ok := s.attributionGate.(AssetTargetResolver)
	if !ok || resolver == nil {
		return nil, ErrAttributionGateUnavailable
	}
	named, err := resolver.AssetTargets(ctx, tenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("asset lookup failed: %w", err)
	}
	assets := make(map[string]DispatchAsset, len(named))
	for _, id := range ids {
		values := named[id]
		if len(values) == 0 || strings.TrimSpace(values[0]) == "" {
			*out = append(*out, outOfDataScope(id))
			continue
		}
		name := strings.TrimSpace(values[0])
		key := strings.ToLower(name)
		*out = append(*out, DryRunResult{Target: name, AssetID: id.String()})
		if _, seen := byTarget[key]; !seen {
			*remaining = append(*remaining, name)
		}
		byTarget[key] = append(byTarget[key], len(*out)-1)
		a := assets[key]
		a.IDs = append(a.IDs, id.String())
		a.AlsoMatch = append(a.AlsoMatch, values[1:]...)
		assets[key] = a
	}
	return assets, nil
}

// outOfDataScope is the answer for an asset the caller may not see.
func outOfDataScope(id shared.ID) DryRunResult {
	return DryRunResult{Target: id.String(), AssetID: id.String(), Code: scopedom.RefusalOutOfDataScope,
		Reason: scopedom.RefusalMessages[scopedom.RefusalOutOfDataScope]}
}

// dedupeIDs drops zero and repeated ids, keeping the input order.
func dedupeIDs(in []shared.ID) []shared.ID {
	seen := make(map[shared.ID]bool, len(in))
	out := make([]shared.ID, 0, len(in))
	for _, id := range in {
		if id.IsZero() || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// decideDryRunRouting fills routing the way the trigger decides
// (shouldUsePlatformSensor): tenant sensors first in auto mode, platform
// sensors only for public, proven (when required) targets and a tenant that
// may use them. needsProof: some target lacks the proof platform sensors
// need. A failed sensor lookup says the job waits (never a guess that it
// runs).
func (s *Service) decideDryRunRouting(ctx context.Context, in DryRunInput, checked []string, needsProof bool, routing *DryRunRouting) {
	routing.Preference = dryRunPreference(in.SensorPreference)
	if routing.Preference == prefPlatform {
		routing.RunsOn, routing.Reason = RoutingPlatform, RoutingReasonPlatform
		return
	}
	if s.sensorSelector == nil {
		routing.RunsOn, routing.Reason = RoutingWaits, RoutingReasonNoTenantSensor
		return
	}
	req := SelectSensorRequest{TenantID: in.TenantID, Tool: in.Tool, Mode: SelectTenantFirst, AllowQueue: true}
	if in.Tool != "" {
		req.Capabilities = []string{in.Tool}
	}
	res, err := s.sensorSelector.SelectSensor(ctx, req)
	if err != nil {
		s.logger.Warn("scope check: sensor lookup failed", "error", err)
		routing.RunsOn, routing.Reason = RoutingWaits, RoutingReasonNoTenantSensor
		return
	}
	own := res != nil && res.Sensor != nil && !res.IsPlatform
	switch {
	case own:
		routing.RunsOn, routing.SensorID, routing.SensorName = RoutingTenant, res.Sensor.ID.String(), res.Sensor.Name
		routing.Reason = RoutingReasonTenantFirst
		if needsProof && routing.Preference == prefAuto {
			routing.Reason = RoutingReasonProof
		}
		return
	case res != nil && res.TenantBusy:
		routing.RunsOn, routing.Reason = RoutingTenant, RoutingReasonTenantBusy
		return
	case routing.Preference == prefTenant:
		routing.RunsOn, routing.Reason = RoutingWaits, RoutingReasonNoTenantSensor
		return
	}
	// Auto without a tenant sensor: platform sensors only for public,
	// proven targets of a tenant that may use them.
	if hasInternalTarget(checked) {
		routing.RunsOn, routing.Reason = RoutingWaits, RoutingReasonInternal
		return
	}
	if canUse, _ := s.sensorSelector.CanUsePlatformSensors(ctx, in.TenantID); canUse && !needsProof {
		routing.RunsOn, routing.Reason = RoutingPlatform, RoutingReasonPlatform
		return
	}
	routing.RunsOn, routing.Reason = RoutingWaits, RoutingReasonNoTenantSensor
}
