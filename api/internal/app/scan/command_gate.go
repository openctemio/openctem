package scan

// Scan commands created directly through POST /api/v1/commands go through the
// same target checks as a triggered scan (RFC-040 §6.1 group A, owner decision
// Q5 (c)). Design: docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrCommandTargetRefused is wrapped by every refusal of GateCommandPayload
// that is about the targets themselves (excluded, outside the zones,
// internal, invalid). It also wraps shared.ErrValidation, so HTTP callers
// answer 400.
var ErrCommandTargetRefused = errors.New("scan command target refused")

// GatedCommand is a scan command payload after the target checks.
type GatedCommand struct {
	// Payload is the input payload with `target` and `targets` rewritten
	// to the checked, deduplicated list in the shape a triggered scan uses.
	Payload json.RawMessage
	// Targets is the checked target list.
	Targets []string
	// ScanZoneID is the zone every target routes to, or nil when the
	// tenant has no zones or the targets are unzoned. A zoned command is
	// claimable only by that zone's sensors.
	ScanZoneID *shared.ID
}

// GateCommandPayload checks a `scan` command payload created outside a scan
// run (POST /api/v1/commands) the way a scan trigger checks its targets:
//
//   - every target passes the scan target validator, which refuses internal,
//     loopback and link-local addresses unless a scan zone of the tenant
//     covers them (the private-range policy of scan create);
//   - no target matches an active scope exclusion (a failed lookup refuses
//     the command: fail closed);
//   - with zones, every target routes to one zone (or every target is
//     unzoned), nothing is uncovered, and a pinned sensor is assigned to
//     that zone.
//
// Unlike a scan run, which drops excluded targets and keeps the rest, a
// command is refused as a whole: the caller named those targets explicitly.
// sensorID is the sensor the command is pinned to, or nil.
func (s *Service) GateCommandPayload(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, payload json.RawMessage) (*GatedCommand, error) {
	fields, targets, err := commandTargets(payload)
	if err != nil {
		return nil, err
	}

	validated, err := s.validateScanTargets(ctx, CreateScanInput{TenantID: tenantID.String(), Targets: targets})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCommandTargetRefused, err)
	}
	// The validator returns valid targets first and zone-admitted private
	// ones after; keep the caller's order for the payload.
	ok := make(map[string]bool, len(validated))
	for _, v := range validated {
		ok[v] = true
	}
	checked := make([]string, 0, len(targets))
	for _, t := range targets {
		if ok[t] {
			checked = append(checked, t)
		}
	}
	if len(checked) != len(targets) {
		return nil, refused("every target must be a valid scan target")
	}

	if err := s.refuseExcluded(ctx, tenantID, checked); err != nil {
		return nil, err
	}
	if err := s.refuseOutOfActScope(ctx, tenantID, nil, checked); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCommandTargetRefused, err)
	}
	if err := s.refuseUnownedTargets(ctx, tenantID, "command", checked); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrCommandTargetRefused, err)
	}

	zoneID, err := s.commandZone(ctx, tenantID, sensorID, checked)
	if err != nil {
		return nil, err
	}

	scanner, _ := fields["scanner"].(string)
	if scanner == "" {
		scanner, _ = fields["scanner_name"].(string)
	}
	delete(fields, "target")
	delete(fields, "targets")
	applyTargetsToPayload(fields, scanner, checked)
	out, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("encode scan command payload: %w", err)
	}
	return &GatedCommand{Payload: out, Targets: checked, ScanZoneID: zoneID}, nil
}

func refused(msg string) error {
	return fmt.Errorf("%w: %w: %s", shared.ErrValidation, ErrCommandTargetRefused, msg)
}

// nestedTargetKeys are payload objects that may not carry their own target
// list in a user-issued command: sensors read only the top-level `target`
// and `targets`, and a list the gate did not check must not ride along for a
// future reader to pick up.
var nestedTargetKeys = []string{"config", "scanner_config", "context", "step_config"}

// commandTargets decodes a scan command payload and returns its fields and
// the deduplicated union of `target` and `targets`.
func commandTargets(payload json.RawMessage) (map[string]any, []string, error) {
	if len(payload) == 0 {
		return nil, nil, refused("a scan command needs a payload with target or targets")
	}
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil || fields == nil {
		return nil, nil, fmt.Errorf("%w: scan command payload must be a JSON object", shared.ErrValidation)
	}
	for _, k := range nestedTargetKeys {
		nested, ok := fields[k].(map[string]any)
		if !ok {
			continue
		}
		for _, tk := range []string{"target", "targets"} {
			if _, has := nested[tk]; has {
				return nil, nil, refused(fmt.Sprintf("put targets in the payload's target or targets, not in %s.%s", k, tk))
			}
		}
	}

	var raw []string
	switch t := fields["target"].(type) {
	case nil:
	case string:
		raw = append(raw, t)
	default:
		return nil, nil, refused("target must be a string")
	}
	switch ts := fields["targets"].(type) {
	case nil:
	case []any:
		for _, v := range ts {
			s, ok := v.(string)
			if !ok {
				return nil, nil, refused("targets must be a list of strings")
			}
			raw = append(raw, s)
		}
	default:
		return nil, nil, refused("targets must be a list of strings")
	}

	seen := make(map[string]bool, len(raw))
	targets := make([]string, 0, len(raw))
	for _, t := range raw {
		t = strings.TrimSpace(t)
		if t == "" {
			return nil, nil, refused("empty target")
		}
		if seen[strings.ToLower(t)] {
			continue
		}
		seen[strings.ToLower(t)] = true
		targets = append(targets, t)
	}
	if len(targets) == 0 {
		return nil, nil, refused("a scan command needs target or targets")
	}
	return fields, targets, nil
}

// refuseExcluded refuses the command when any target matches an active
// scope exclusion. Without an exclusion filter nothing could be checked, so
// the command is refused (fail closed).
func (s *Service) refuseExcluded(ctx context.Context, tenantID shared.ID, targets []string) error {
	if s.scopeExclusions == nil {
		return errors.New("scope exclusion check is not configured; scan command not created")
	}
	candidates := make([]scope.ExclusionCandidate, len(targets))
	for i, t := range targets {
		candidates[i] = scope.ExclusionCandidate{ID: shared.NewID(), Values: []string{t}}
	}
	excluded, err := s.scopeExclusions.ExcludedTargets(ctx, tenantID.String(), candidates)
	if err != nil {
		return fmt.Errorf("scope exclusion check failed, scan command not created: %w", err)
	}
	var names []string
	for _, c := range candidates {
		if excluded[c.ID] {
			names = append(names, c.Values[0])
		}
	}
	if len(names) > 0 {
		return refused(fmt.Sprintf("target(s) match an active scope exclusion: %s", strings.Join(names, ", ")))
	}
	return nil
}

// commandZone routes the targets over the tenant's zones and returns the one
// zone they all route to (nil when the tenant has no zones or they are all
// unzoned). A command is one job on one sensor, so targets in different
// zones, or zoned next to unzoned targets, are refused; so is a pinned
// sensor that is not assigned to the zone.
func (s *Service) commandZone(ctx context.Context, tenantID shared.ID, sensorID *shared.ID, targets []string) (*shared.ID, error) {
	zones, err := s.loadZones(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if len(zones) == 0 {
		return nil, nil
	}
	plan := scanzone.NewRouter(zones, s.zoneResolver).Plan(ctx, targets)
	if len(plan.Uncovered) > 0 {
		u := plan.Uncovered[0]
		return nil, refused(fmt.Sprintf("target %q cannot be scanned: %s", u.Target, u.Reason))
	}
	if len(plan.ZoneOrder) == 0 {
		return nil, nil
	}
	if len(plan.ZoneOrder) > 1 || len(plan.Unzoned) > 0 {
		return nil, refused("targets route to more than one scan zone; send one command per zone")
	}
	zone := plan.Zones[plan.ZoneOrder[0]]
	if sensorID != nil && !zone.HasSensor(*sensorID) {
		return nil, refused(fmt.Sprintf("the targets are in scan zone %q and the sensor is not assigned to it", zone.Name))
	}
	id := zone.ID
	return &id, nil
}
