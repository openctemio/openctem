package scan

// One target gate for the paths that dispatch scan work outside a scan
// trigger: POST /pipelines/runs and the coverage dispatcher. Design:
// docs/rfcs/RFC-042-asset-inventory-v2.md (§3.3 F16, §6.11, §6.13).

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrDispatchGateUnavailable is returned when the target gate cannot check
// exclusions (not wired). Nothing is dispatched then (fail closed).
var ErrDispatchGateUnavailable = errors.New("scope exclusion check is not configured; nothing dispatched")

// DispatchTargetsInput is a target list about to be dispatched.
type DispatchTargetsInput struct {
	TenantID shared.ID
	Targets  []string
	// SensorID is the sensor the work is pinned to, or nil. A target in a
	// scan zone the sensor is not assigned to is refused.
	SensorID *shared.ID
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
	// inside a scan zone) or zone routing (no zone covers it, its zone has no
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

// ResolveDispatchTargets applies the checks of a scan trigger to a target
// list that is dispatched some other way:
//
//   - the scan target validator with the private-range policy of scan
//     create (private addresses only inside a scan zone of the tenant);
//   - active scope exclusions, matched as on a scan run (URL and host:port
//     forms included); a failed lookup returns an error (fail closed);
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
		candidates = append(candidates, scope.ExclusionCandidate{ID: id, Values: []string{t}})
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

	if err := s.routeDispatchTargets(ctx, in, kept, out); err != nil {
		return nil, err
	}
	return out, nil
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
