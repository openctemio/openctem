package scan

// One target gate for the paths that send traffic at a target outside a scan
// trigger: POST /pipelines/runs, the coverage dispatcher, and every validate
// command (finding re-checks, retests, attack-simulation safe-checks). Design:
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
}

// RefusedTarget is a target the gate will not dispatch, with the reason.
type RefusedTarget struct {
	Target string `json:"target"`
	Reason string `json:"reason"`
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

// ResolveDispatchTargets applies the checks of a scan trigger to a target
// list that is dispatched some other way:
//
//   - the scan target validator with the private-range policy of scan
//     create (private addresses only inside a scan zone of the tenant);
//   - active scope exclusions, matched as on a scan run (URL and host:port
//     forms included); a failed lookup returns an error (fail closed);
//   - ownership (AttributionGate): the inventory asset behind a target
//     (in.Assets, or the asset a typed target names) must be authorized for
//     active checks, and no target may be or sit under a rejected name; a
//     failed or unwired lookup returns an error (fail closed);
//   - scan-zone routing: uncovered targets, zones without sensors and a
//     pinned sensor outside the target's zone are refused.
//
// It returns an error only when the checks themselves cannot run; a refused
// or excluded target is reported in the result.
func (s *Service) ResolveDispatchTargets(ctx context.Context, in DispatchTargetsInput) (*DispatchTargets, error) {
	if s.scopeExclusions == nil {
		return nil, ErrDispatchGateUnavailable
	}
	targets := dedupeTargets(in.Targets)
	out := &DispatchTargets{}
	if len(targets) == 0 {
		return out, nil
	}
	if len(targets) > maxResolvedTargets {
		return nil, fmt.Errorf("%w: %d targets, more than the %d allowed per run",
			shared.ErrValidation, len(targets), maxResolvedTargets)
	}

	accepted, rejected, err := s.validateTargetsEach(ctx, in.TenantID.String(), targets, maxResolvedTargets)
	if err != nil {
		return nil, err
	}
	for _, r := range rejected {
		out.Refused = append(out.Refused, RefusedTarget(r))
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

	kept, err = s.refuseUnconfirmed(ctx, in, kept, out)
	if err != nil {
		return nil, err
	}

	kept, err = s.refuseOutOfActScopeTargets(ctx, in, kept, out)
	if err != nil {
		return nil, err
	}

	if err := s.routeDispatchTargets(ctx, in, kept, out); err != nil {
		return nil, err
	}
	return out, nil
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
		if !ok {
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
		if blocked, err = s.attributionGate.ActiveCheckBlocked(ctx, in.TenantID, ids); err != nil {
			return nil, fmt.Errorf("attribution check failed, nothing dispatched: %w", err)
		}
	}
	blockedTyped := map[string]attribution.State{}
	if len(typed) > 0 {
		var err error
		if blockedTyped, err = s.attributionGate.BlockedTargets(ctx, in.TenantID, typed); err != nil {
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
			s.logRefusedTarget(ctx, in.TenantID, "dispatch_gate", t, state)
			out.Refused = append(out.Refused, RefusedTarget{Target: t, Reason: ReasonOwnershipNotConfirmed})
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
	check := actscope.Input{TenantID: in.TenantID, FallbackUser: in.FallbackUser, Targets: kept}
	for _, t := range kept {
		if a, ok := assetOf(in.Assets, t); ok {
			for _, id := range a.IDs {
				if pid, err := shared.IDFromString(id); err == nil {
					check.AssetIDs = append(check.AssetIDs, pid)
				}
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
			out.Refused = append(out.Refused, RefusedTarget{Target: t, Reason: reason})
			continue
		}
		if a, ok := assetOf(in.Assets, t); ok && anyRefused(a.IDs, d.RefusedAssets) {
			out.Refused = append(out.Refused, RefusedTarget{Target: t, Reason: actscope.ReasonOutOfDataScope})
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

// assetOf finds the inventory asset behind a target (case-insensitive).
func assetOf(assets map[string]DispatchAsset, target string) (DispatchAsset, bool) {
	if len(assets) == 0 {
		return DispatchAsset{}, false
	}
	if a, ok := assets[target]; ok {
		return a, true
	}
	want := strings.ToLower(strings.TrimSpace(target))
	for k, a := range assets {
		if strings.ToLower(strings.TrimSpace(k)) == want {
			return a, true
		}
	}
	return DispatchAsset{}, false
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
			out.Refused = append(out.Refused, RefusedTarget{Target: r.Target, Reason: reason})
		case r.Zone != nil && len(r.Zone.SensorIDs) == 0:
			out.Refused = append(out.Refused, RefusedTarget{Target: r.Target,
				Reason: fmt.Sprintf("scan zone %q has no sensors assigned", r.Zone.Name)})
		case r.Zone != nil && in.SensorID != nil && !r.Zone.HasSensor(*in.SensorID):
			out.Refused = append(out.Refused, RefusedTarget{Target: r.Target,
				Reason: fmt.Sprintf("target is in scan zone %q and the pinned sensor is not assigned to it", r.Zone.Name)})
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
