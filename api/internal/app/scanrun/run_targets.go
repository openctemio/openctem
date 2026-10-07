package scanrun

// Targets of a scan run started directly (POST /api/v1/scan-workflows/runs, the
// trigger_pipeline workflow action) go through the target gate of a scan
// trigger. Design: docs/rfcs/RFC-042-asset-inventory-v2.md (§3.3 F16).

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Run-context keys the gate reads and writes.
const (
	runContextKeyTargets       = "targets"
	runContextKeyTarget        = "target"
	runContextKeyExcludedCount = "excluded_target_count"
)

// userIDOf parses a triggered_by user id; anything else is nil.
func userIDOf(s string) *shared.ID {
	id, err := shared.IDFromString(strings.TrimSpace(s))
	if err != nil || id.IsZero() {
		return nil
	}
	return &id
}

// gateRunContext checks the targets a run is started with and returns the
// context to store:
//
//   - `target` and `targets` are replaced by one checked `targets` list;
//   - a target the scan target validator or zone routing refuses fails the
//     whole run (400): the caller named it explicitly;
//   - a target the actor may not scan (outside their data scope, or free
//     text matching no scope target) fails the run (research/15 L-06);
//   - a target matching an active scope exclusion is dropped, as on a scan
//     run, and counted; a run whose every target is excluded is refused;
//   - `scan_zone_id` is never taken from the caller: it is set from the
//     routing, so the steps are claimed only by that zone's sensors.
//
// A run with no targets is unchanged, apart from the zone key. A failed
// exclusion lookup, or no gate wired, refuses a run with targets (fail
// closed).
func (s *Service) gateRunContext(ctx context.Context, tenantID shared.ID, triggeredBy string, in map[string]any) (map[string]any, error) {
	out := maps.Clone(in)
	if out == nil {
		return nil, nil
	}
	delete(out, scanrun.RunContextKeyScanZoneID)
	// The platform routing decision is the scan trigger's, never a caller's.
	delete(out, scanrun.RunContextKeySensorRouting)

	targets, err := runContextTargets(out)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return out, nil
	}
	if s.targetGate == nil {
		return nil, errors.New("pipeline target gate is not configured; run not started")
	}
	gated, err := s.targetGate.ResolveDispatchTargets(ctx, scanapp.DispatchTargetsInput{
		TenantID: tenantID, Targets: targets,
		// The person who starts the run (or, from a workflow, triggered_by
		// when it names a user) may scan only targets in their act scope.
		ActScope: true, FallbackUser: userIDOf(triggeredBy),
	})
	if err != nil {
		return nil, err
	}
	if len(gated.Refused) > 0 {
		parts := make([]string, 0, len(gated.Refused))
		for _, r := range gated.Refused {
			parts = append(parts, fmt.Sprintf("%s (%s)", r.Target, r.Reason))
		}
		return nil, shared.NewDomainError("TARGET_REFUSED",
			"These targets cannot be scanned: "+strings.Join(parts, "; "), shared.ErrValidation)
	}
	if len(gated.Allowed) == 0 && len(gated.Excluded) == 0 {
		return nil, fmt.Errorf("%w: context.targets has no target", shared.ErrValidation)
	}
	if len(gated.Allowed) == 0 {
		return nil, shared.NewDomainError("ALL_TARGETS_EXCLUDED",
			"Every target of this run is excluded by scope; nothing to scan.", shared.ErrValidation)
	}
	zone, err := gated.SingleZone()
	if err != nil {
		return nil, err
	}

	delete(out, runContextKeyTarget)
	out[runContextKeyTargets] = gated.Allowed
	if len(gated.Excluded) > 0 {
		out[runContextKeyExcludedCount] = len(gated.Excluded)
	}
	if zone != nil {
		out[scanrun.RunContextKeyScanZoneID] = zone.ID.String()
	}
	return out, nil
}

// runContextTargets reads `target` (a string) and `targets` (a list of
// strings) from a run context. Any other shape is refused rather than passed
// to a sensor unchecked.
func runContextTargets(rc map[string]any) ([]string, error) {
	var targets []string
	switch t := rc[runContextKeyTarget].(type) {
	case nil:
	case string:
		targets = append(targets, t)
	default:
		return nil, fmt.Errorf("%w: context.target must be a string", shared.ErrValidation)
	}
	switch ts := rc[runContextKeyTargets].(type) {
	case nil:
	case []string:
		targets = append(targets, ts...)
	case []any:
		for _, v := range ts {
			str, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("%w: context.targets must be a list of strings", shared.ErrValidation)
			}
			targets = append(targets, str)
		}
	default:
		return nil, fmt.Errorf("%w: context.targets must be a list of strings", shared.ErrValidation)
	}
	return targets, nil
}
