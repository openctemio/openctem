package scan

// One target gate for every path that sends traffic at a target: the scan
// trigger (resolveScanTargets), POST /scan-workflows/runs and its hops, the
// coverage dispatcher, connector scans, the quick-scan dry run, and every
// validate command (finding re-checks, retests, attack-simulation
// safe-checks); POST /commands goes through GateCommandPayload. Design:
// docs/rfcs/RFC-042-asset-inventory-v2.md (§3.3 F16, §6.11, §6.13);
// architecture: docs/architecture/active-probe-gate.md.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ErrDispatchGateUnavailable is returned when the target gate cannot check
// exclusions (not wired). Nothing is dispatched then (fail closed).
var ErrDispatchGateUnavailable = errors.New("scope exclusion check is not configured; nothing dispatched")

// ErrAttributionGateUnavailable is returned when a target names an inventory
// asset and the attribution check is not wired. Nothing is dispatched then.
var ErrAttributionGateUnavailable = errors.New("attribution check is not configured; nothing dispatched")

// DispatchAsset is the inventory asset (or assets: two assets can share an
// address) behind a target.
type DispatchAsset struct {
	IDs []string // asset ids (UUIDs; anything else fails the lookup)
	// AlsoMatch are the asset's other names (its inventory name when the
	// target is a URL on it, its addresses). An exclusion of any of them
	// excludes the target, as on a scan run.
	AlsoMatch []string
}

// typed reports whether the entry names no asset id and only adds names for
// the exclusion match: the target is then checked by name, as one with no
// entry. An entry with neither ids nor names is malformed (refused).
func (a DispatchAsset) typed() bool { return len(a.IDs) == 0 && len(a.AlsoMatch) > 0 }

// DispatchTargetsInput is a target list about to be dispatched.
type DispatchTargetsInput struct {
	TenantID shared.ID
	Targets  []string
	// SensorID is the sensor the work is pinned to, or nil. A target in a
	// scan zone the sensor is not assigned to is refused.
	SensorID *shared.ID
	// Assets maps a target to the inventory asset it probes. Such a target is
	// refused while the ownership gate refuses any of its assets (RFC-036
	// §6.3), like an asset-group member of a scan. A target with no entry is
	// checked by name (it may name an asset, or sit under a rejected name).
	// Keys match targets case-insensitively.
	Assets map[string]DispatchAsset
	// ActScope limits the targets to what the actor may scan (research/15
	// L-06, D9): the request caller, else FallbackUser. Set it on every path
	// a person starts; system paths (coverage, validation) leave it off.
	ActScope     bool
	FallbackUser *shared.ID
	// PassiveOnly gates targets for a passive (T0) stage of a chain
	// (research/27 §5.7): the ownership gate refuses only rejected names
	// (a rejection tombstone, a rejected record, or a name under a rejected
	// parent). A name that is not confirmed yet (needs_review, candidate,
	// unattributed) may be resolved, never actively probed: every other
	// path leaves this off and gets the full active-scan gate.
	PassiveOnly bool
	// DryRun answers POST /scope/check: nothing is logged as refused.
	DryRun bool
	// Tier is the probe's tier (RFC-054 §4.2 step 6): a target the scope
	// authority covers only below it is refused (tier_exceeds). Nil is t1,
	// the safe active probe every path sends unless it says otherwise;
	// PassiveOnly dispatches are not tier-checked.
	Tier *scopedom.Tier

	// The options below are for the scan trigger (resolveScanTargets), which
	// builds its own candidate list (asset groups, the scanner type gate,
	// archived members) and plans zones itself. Their zero value is the
	// strict behavior every other path gets.

	// AllowNonNetworkTargets replaces the scan target validator with the
	// private-range rule alone, applied after the act scope: an internal
	// address (private, loopback, link-local, unspecified, carrier-grade
	// NAT; literal, range, URL or host:port) is refused while the tenant has
	// no scan zone; with zones, zone routing (or the caller's own zone
	// planning) refuses what no zone covers. For target lists naming
	// inventory assets the validator refuses as not network targets
	// (repositories, container images): a scan's asset-group members, and
	// its direct targets, validated when the scan was saved.
	AllowNonNetworkTargets bool
	// SkipZoneRouting leaves zone routing to the caller: Allowed is every
	// target the other checks kept, ZoneOf stays nil. Only for a caller that
	// routes, batches and pins per zone itself and refuses what no zone
	// covers (the scan trigger's planZoneDispatch).
	SkipZoneRouting bool
	// TakeoverOnly applies the takeover exception (research/22 E13) to the
	// ownership check: a dependency asset with an open dangling_cname is
	// admitted. IsTakeoverOnlyProbe decides which scans qualify.
	TakeoverOnly bool
	// ActScopeAssetsByID checks a target that has asset ids in Assets
	// against the act scope by those ids only. Off, its name is also
	// checked as free text (a scope entry must cover it). For a scan's
	// asset-group members: the member is the asset, its name is not
	// something the actor typed.
	ActScopeAssetsByID bool
	// MaxTargets bounds the input list (0 = maxResolvedTargets). The scan
	// trigger passes its own pre-check bound and caps what is left after
	// the checks itself.
	MaxTargets int
	// Path names the dispatch path in refusal logs ("" = dispatch_gate).
	Path string
}

// ReasonInternalOutsideZones is the reason an internal address is refused
// while the tenant has no scan zone (AllowNonNetworkTargets).
const ReasonInternalOutsideZones = "internal addresses are scanned only inside a scan zone of this organization"

// gatePath is the dispatch path named in refusal logs.
func (in DispatchTargetsInput) gatePath() string {
	if in.Path == "" {
		return "dispatch_gate"
	}
	return in.Path
}

// RefusedTarget is a target the gate will not dispatch, with the reason and
// its structured code (RFC-054 §6.5, scopedom.Refusal*).
type RefusedTarget struct {
	Target string `json:"target"`
	Reason string `json:"reason"`
	Code   string `json:"code"`
}

// DispatchTargets is the gate's decision for every input target.
type DispatchTargets struct {
	// Allowed are the targets that may be dispatched, in input order,
	// deduplicated case-insensitively.
	Allowed []string
	// Excluded match an active scope exclusion.
	Excluded []string
	// Refused fail the scan target validator (internal, loopback,
	// link-local, metadata or malformed; a private address is allowed only
	// inside a scan zone), name an asset whose ownership is not confirmed,
	// or fail zone routing (no zone covers it, its zone has no
	// sensor, or the pinned sensor is not in its zone).
	Refused []RefusedTarget

	ZoneOf map[string]*scanzone.Zone // allowed target -> zone; nil = unzoned
}

// Zone returns the scan zone an allowed target routes to, or nil when it is
// unzoned (public, or the tenant has no zones).
func (d *DispatchTargets) Zone(target string) *scanzone.Zone {
	if d == nil || d.ZoneOf == nil {
		return nil
	}
	return d.ZoneOf[target]
}

// SingleZone returns the one zone every allowed target routes to (nil when
// they are all unzoned). Targets in several zones, or zoned next to unzoned
// targets, cannot be one job: ZONE_SPLIT_REQUIRED.
func (d *DispatchTargets) SingleZone() (*scanzone.Zone, error) {
	var zone *scanzone.Zone
	unzoned := false
	for _, t := range d.Allowed {
		z := d.Zone(t)
		switch {
		case z == nil:
			unzoned = true
		case zone == nil:
			zone = z
		case !zone.ID.Equals(z.ID):
			return nil, zoneSplitError()
		}
	}
	if zone != nil && unzoned {
		return nil, zoneSplitError()
	}
	return zone, nil
}

func zoneSplitError() error {
	return shared.NewDomainError("ZONE_SPLIT_REQUIRED",
		"The targets are in more than one scan zone (or in a zone and outside every zone); a run stays in one zone, so start one run per zone.",
		shared.ErrValidation)
}

// NewTargetGate builds a Service that only answers ResolveDispatchTargets:
// for tests and tools that need the gate without a scan service's other
// dependencies. Production uses the scan service itself, wired with the same
// options.
func NewTargetGate(exclusions ScopeExclusionFilter, attr AttributionGate, zones ZoneDirectory, resolver scanzone.Resolver, log *logger.Logger) *Service {
	return &Service{scopeExclusions: exclusions, attributionGate: attr, zones: zones, zoneResolver: resolver,
		logger: log.With("service", "scan-target-gate")}
}

// ResolveDispatchTargets is the one target gate of every dispatch path. In
// order, each check on what the previous ones kept:
//
//   - the scan target validator with the private-range policy of scan
//     create (private addresses only inside a scan zone of the tenant);
//     AllowNonNetworkTargets keeps only the private-range rule, applied
//     after the act scope;
//   - active scope exclusions, matched as on a scan run (URL and host:port
//     forms included); a failed or unwired lookup returns an error (fail
//     closed);
//   - ownership (AttributionGate): the inventory asset behind a target
//     (in.Assets, or the asset a typed target names) must be authorized for
//     active checks, and no target may be or sit under a rejected name; a
//     failed or unwired lookup returns an error (fail closed);
//   - the act scope (ActScope): what the actor may scan;
//   - the tier ceiling (Tier): the scope entries covering a target must
//     allow the probe's tier;
//   - scan-zone routing (unless SkipZoneRouting): uncovered targets, zones
//     without sensors and a pinned sensor outside the target's zone are
//     refused.
//
// It returns an error only when the checks themselves cannot run; a refused
// or excluded target is reported in the result, once, under the first check
// that refused it.
func (s *Service) ResolveDispatchTargets(ctx context.Context, in DispatchTargetsInput) (*DispatchTargets, error) {
	if s.scopeExclusions == nil {
		return nil, ErrDispatchGateUnavailable
	}
	targets := dedupeTargets(in.Targets)
	out := &DispatchTargets{}
	if len(targets) == 0 {
		return out, nil
	}
	limit := maxResolvedTargets
	if in.MaxTargets > 0 {
		limit = in.MaxTargets
	}
	if len(targets) > limit {
		return nil, fmt.Errorf("%w: %d targets, more than the %d allowed per run",
			shared.ErrValidation, len(targets), limit)
	}
	in.Assets = foldAssets(in.Assets)

	accepted := targets
	if !in.AllowNonNetworkTargets {
		var rejected []rejectedTarget
		var err error
		accepted, rejected, err = s.validateTargetsEach(ctx, in.TenantID.String(), targets, limit)
		if err != nil {
			return nil, err
		}
		for _, r := range rejected {
			out.Refused = append(out.Refused, RefusedTarget{Target: r.Target, Reason: r.Reason, Code: scopedom.RefusalInvalidTarget})
		}
	}
	ok := make(map[string]bool, len(accepted))
	for _, a := range accepted {
		ok[a] = true
	}

	candidates := make([]scope.ExclusionCandidate, 0, len(accepted))
	byID := make(map[shared.ID]string, len(accepted))
	for _, t := range targets {
		if !ok[t] {
			continue
		}
		id := shared.NewID()
		values := []string{t}
		if a, ok := assetOf(in.Assets, t); ok {
			for _, v := range a.AlsoMatch {
				if v = strings.TrimSpace(v); v != "" && !strings.EqualFold(v, t) {
					values = append(values, v)
				}
			}
		}
		candidates = append(candidates, scope.ExclusionCandidate{ID: id, Values: values})
		byID[id] = t
	}
	excluded := map[shared.ID]bool{}
	if len(candidates) > 0 {
		var err error
		excluded, err = s.scopeExclusions.ExcludedTargets(ctx, in.TenantID.String(), candidates)
		if err != nil {
			return nil, fmt.Errorf("scope exclusion check failed, nothing dispatched: %w", err)
		}
	}
	kept := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if excluded[c.ID] {
			out.Excluded = append(out.Excluded, byID[c.ID])
			continue
		}
		kept = append(kept, byID[c.ID])
	}

	for _, check := range []func(context.Context, DispatchTargetsInput, []string, *DispatchTargets) ([]string, error){
		s.refuseUnconfirmed,
		s.refuseOutOfActScopeTargets,
		s.refuseInternalOutsideZones,
		s.refuseOverTier,
	} {
		var err error
		if kept, err = check(ctx, in, kept, out); err != nil {
			return nil, err
		}
	}

	if in.SkipZoneRouting {
		out.Allowed = kept
		return out, nil
	}
	if err := s.routeDispatchTargets(ctx, in, kept, out); err != nil {
		return nil, err
	}
	return out, nil
}

// refuseInternalOutsideZones applies the private-range policy of scan create
// when the validator is off (AllowNonNetworkTargets): an internal address
// (private, loopback, link-local, unspecified, carrier-grade NAT; a literal
// address, a range, a URL or a host:port with one) is refused while the
// tenant has no scan zone. A tenant with zones gets the rule from zone
// routing, which refuses every target no zone covers.
//
// A scan run is built later and from more than the saved direct targets:
// asset-group members were never validated, and a zone that admitted a
// private target may have been deleted since. Hostnames are not resolved
// here, as on create: the zone router and the sensor's local policy route
// them.
func (s *Service) refuseInternalOutsideZones(ctx context.Context, in DispatchTargetsInput, kept []string, out *DispatchTargets) ([]string, error) {
	if !in.AllowNonNetworkTargets || len(kept) == 0 {
		return kept, nil
	}
	internal := map[string]bool{}
	for _, t := range kept {
		if pt := scanzone.ParseTarget(t); pt.IsAddr && isInternalAddr(pt.Prefix.Addr()) {
			internal[t] = true
		}
	}
	if len(internal) == 0 {
		return kept, nil
	}
	zones, err := s.loadZones(ctx, in.TenantID)
	if err != nil {
		return nil, err
	}
	if len(zones) > 0 {
		return kept, nil
	}
	allowed := make([]string, 0, len(kept)-len(internal))
	for _, t := range kept {
		if internal[t] {
			out.Refused = append(out.Refused, RefusedTarget{Target: t, Reason: ReasonInternalOutsideZones, Code: scopedom.RefusalZoneNone})
			continue
		}
		allowed = append(allowed, t)
	}
	if !in.DryRun && s.logger != nil {
		s.logger.Warn("SECURITY: internal targets outside every scan zone refused",
			"tenant_id", in.TenantID.String(), "path", in.gatePath(), "count", len(internal))
	}
	return allowed, nil
}

// refuseUnconfirmed moves every kept target the ownership gate refuses to
// Refused: a target whose inventory asset (in.Assets) is not authorized for
// active checks, and a typed target that names such an asset or sits under
// a name the tenant rejected. The caller sees a generic reason; the state
// is logged. No gate, or a failed lookup, refuses everything (fail closed).
func (s *Service) refuseUnconfirmed(ctx context.Context, in DispatchTargetsInput, kept []string, out *DispatchTargets) ([]string, error) {
	if len(kept) == 0 {
		return kept, nil
	}
	ids := make([]string, 0, len(kept))
	var typed []string
	for _, t := range kept {
		a, ok := assetOf(in.Assets, t)
		if !ok || a.typed() {
			typed = append(typed, t)
			continue
		}
		if len(a.IDs) == 0 {
			return nil, fmt.Errorf("%w: target %q names an asset without an id", shared.ErrValidation, t)
		}
		for _, id := range a.IDs {
			if strings.TrimSpace(id) == "" {
				return nil, fmt.Errorf("%w: target %q names an asset without an id", shared.ErrValidation, t)
			}
			ids = append(ids, id)
		}
	}
	if s.attributionGate == nil {
		return nil, ErrAttributionGateUnavailable
	}
	blocked := map[string]attribution.State{}
	if len(ids) > 0 {
		var err error
		blocked, err = s.attributionGate.ActiveCheckBlocked(ctx, in.TenantID, ids)
		if err == nil && in.TakeoverOnly {
			err = s.admitTakeoverTargets(ctx, in.TenantID, blocked, true)
		}
		if err != nil {
			return nil, fmt.Errorf("attribution check failed, nothing dispatched: %w", err)
		}
	}
	blockedTyped := map[string]attribution.State{}
	if len(typed) > 0 {
		var err error
		blockedTyped, err = s.attributionGate.BlockedTargets(ctx, in.TenantID, typed)
		if err == nil && in.TakeoverOnly {
			err = s.admitTakeoverTargets(ctx, in.TenantID, blockedTyped, false)
		}
		if err != nil {
			return nil, fmt.Errorf("attribution check failed, nothing dispatched: %w", err)
		}
	}
	allowed := make([]string, 0, len(kept))
	for _, t := range kept {
		state, no := unconfirmedState(in.Assets, t, blocked)
		if !no {
			state, no = blockedTyped[t]
		}
		if no && in.PassiveOnly {
			// A passive stage may resolve a name nobody confirmed yet; only
			// a rejection (of any asset behind the target) refuses it.
			if rejectedState(in.Assets, t, blocked) || blockedTyped[t] == attribution.StateRejected {
				state = attribution.StateRejected
			} else {
				no = false
			}
		}
		if no {
			if !in.DryRun {
				s.logRefusedTarget(ctx, in.TenantID, in.gatePath(), t, state)
			}
			out.Refused = append(out.Refused, RefusedTarget{Target: t, Reason: ReasonOwnershipNotConfirmed, Code: RefusalCodeForState(state)})
			continue
		}
		allowed = append(allowed, t)
	}
	return allowed, nil
}

// unconfirmedState reports the attribution state of the first asset behind
// target that is not confirmed.
func unconfirmedState(assets map[string]DispatchAsset, target string, blocked map[string]attribution.State) (attribution.State, bool) {
	a, ok := assetOf(assets, target)
	if !ok {
		return "", false
	}
	for _, id := range a.IDs {
		if state, no := blocked[id]; no {
			return state, true
		}
	}
	return "", false
}

// rejectedState reports whether any asset behind target is rejected.
func rejectedState(assets map[string]DispatchAsset, target string, blocked map[string]attribution.State) bool {
	a, ok := assetOf(assets, target)
	if !ok {
		return false
	}
	for _, id := range a.IDs {
		if blocked[id] == attribution.StateRejected {
			return true
		}
	}
	return false
}

// refuseOverTier moves every kept target the scope authority covers only
// below the probe's tier to Refused (tier_exceeds). A passive dispatch is
// not checked.
func (s *Service) refuseOverTier(ctx context.Context, in DispatchTargetsInput, kept []string, out *DispatchTargets) ([]string, error) {
	if in.PassiveOnly || len(kept) == 0 {
		return kept, nil
	}
	tier := scopedom.TierActive
	if in.Tier != nil {
		tier = *in.Tier
	}
	over, err := s.tierExceeded(ctx, in.TenantID, kept, tier)
	if err != nil {
		return nil, fmt.Errorf("tier check failed, nothing dispatched: %w", err)
	}
	if len(over) == 0 {
		return kept, nil
	}
	allowed := make([]string, 0, len(kept))
	for _, t := range kept {
		if _, no := over[t]; no {
			out.Refused = append(out.Refused, RefusedTarget{Target: t, Code: scopedom.RefusalTierExceeds,
				Reason: scopedom.RefusalMessages[scopedom.RefusalTierExceeds]})
			continue
		}
		allowed = append(allowed, t)
	}
	return allowed, nil
}

// refuseOutOfActScopeTargets moves every kept target the actor may not scan
// to Refused, when the input asks for the act-scope check. The caller scope
// seam of the gate: one call per dispatch, before any command exists.
func (s *Service) refuseOutOfActScopeTargets(ctx context.Context, in DispatchTargetsInput, kept []string, out *DispatchTargets) ([]string, error) {
	if !in.ActScope || len(kept) == 0 {
		return kept, nil
	}
	if s.actScope == nil {
		return nil, ErrActScopeUnavailable
	}
	check := actscope.Input{TenantID: in.TenantID, FallbackUser: in.FallbackUser}
	for _, t := range kept {
		a, ok := assetOf(in.Assets, t)
		if !ok || len(a.IDs) == 0 || !in.ActScopeAssetsByID {
			check.Targets = append(check.Targets, t)
		}
		for _, id := range a.IDs {
			if pid, err := shared.IDFromString(id); err == nil {
				check.AssetIDs = append(check.AssetIDs, pid)
			}
		}
	}
	d, err := s.actScope.Check(ctx, check)
	if err != nil {
		return nil, fmt.Errorf("act-scope check failed, nothing dispatched: %w", err)
	}
	allowed := make([]string, 0, len(kept))
	for _, t := range kept {
		if reason, no := d.RefusedTargets[t]; no {
			out.Refused = append(out.Refused, RefusedTarget{Target: t, Reason: reason, Code: RefusalCodeForActReason(reason)})
			continue
		}
		if a, ok := assetOf(in.Assets, t); ok && anyRefused(a.IDs, d.RefusedAssets) {
			out.Refused = append(out.Refused, RefusedTarget{Target: t, Reason: actscope.ReasonOutOfDataScope, Code: scopedom.RefusalOutOfDataScope})
			continue
		}
		allowed = append(allowed, t)
	}
	return allowed, nil
}

func anyRefused(ids []string, refused map[shared.ID]bool) bool {
	for _, id := range ids {
		if pid, err := shared.IDFromString(id); err == nil && refused[pid] {
			return true
		}
	}
	return false
}

// assetKey is a target's key in folded Assets.
func assetKey(target string) string { return strings.ToLower(strings.TrimSpace(target)) }

// foldAssets keys Assets case-insensitively, once per gate call, so a lookup
// is one map read on a list of thousands. Keys that differ only in case name
// the same target: their ids and names are merged, so every asset behind it
// is checked.
func foldAssets(assets map[string]DispatchAsset) map[string]DispatchAsset {
	if len(assets) == 0 {
		return nil
	}
	out := make(map[string]DispatchAsset, len(assets))
	for k, a := range assets {
		key := assetKey(k)
		if prev, dup := out[key]; dup {
			a = DispatchAsset{
				IDs:       append(append([]string(nil), prev.IDs...), a.IDs...),
				AlsoMatch: append(append([]string(nil), prev.AlsoMatch...), a.AlsoMatch...),
			}
		}
		out[key] = a
	}
	return out
}

// assetOf finds the inventory asset behind a target in folded Assets
// (case-insensitive).
func assetOf(assets map[string]DispatchAsset, target string) (DispatchAsset, bool) {
	if len(assets) == 0 {
		return DispatchAsset{}, false
	}
	a, ok := assets[assetKey(target)]
	return a, ok
}

// routeDispatchTargets routes the kept targets over the tenant's zones and
// fills Allowed (and Refused for what cannot be routed).
func (s *Service) routeDispatchTargets(ctx context.Context, in DispatchTargetsInput, kept []string, out *DispatchTargets) error {
	if len(kept) == 0 {
		return nil
	}
	zones, err := s.loadZones(ctx, in.TenantID)
	if err != nil {
		return err
	}
	if len(zones) == 0 {
		out.Allowed = kept
		return nil
	}
	plan := scanzone.NewRouter(zones, s.zoneResolver).Plan(ctx, kept)
	out.ZoneOf = make(map[string]*scanzone.Zone, len(kept))
	for _, r := range plan.Routes {
		switch {
		case r.Zone == nil && !r.Unzoned:
			reason := r.Reason
			if reason == "" {
				reason = "no scan zone covers this target"
			}
			out.Refused = append(out.Refused, RefusedTarget{Target: r.Target, Reason: reason, Code: scopedom.RefusalZoneNone})
		case r.Zone != nil && len(r.Zone.SensorIDs) == 0:
			out.Refused = append(out.Refused, RefusedTarget{Target: r.Target,
				Reason: fmt.Sprintf("scan zone %q has no sensors assigned", r.Zone.Name), Code: scopedom.RefusalZoneNoSensor})
		case r.Zone != nil && in.SensorID != nil && !r.Zone.HasSensor(*in.SensorID):
			out.Refused = append(out.Refused, RefusedTarget{Target: r.Target,
				Reason: fmt.Sprintf("target is in scan zone %q and the pinned sensor is not assigned to it", r.Zone.Name), Code: scopedom.RefusalZoneSensorMismatch})
		default:
			out.Allowed = append(out.Allowed, r.Target)
			out.ZoneOf[r.Target] = r.Zone
		}
	}
	return nil
}

// dedupeTargets trims, drops empty entries and removes case-insensitive
// duplicates, keeping the first spelling and the input order.
func dedupeTargets(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t == "" || seen[strings.ToLower(t)] {
			continue
		}
		seen[strings.ToLower(t)] = true
		out = append(out, t)
	}
	return out
}
