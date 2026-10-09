package scan

// The scanner/asset type gate (RFC-042 §6.3.8 O6,
// docs/rfcs/RFC-042-asset-inventory-v2.md): a scanner is handed only the
// assets whose stored (type, sub_type) it can scan, as the registry's
// scannable_by says (plus active admin target mappings). It used to be
// advisory: the run reported assets as "skipped" and dispatched them anyway.
//
// The gate is enforced at both dispatch points:
//   - a single-scanner run, when its targets are resolved
//     (resolveScanTargets): incompatible asset-group members are left out
//     and counted; a run with nothing left is refused (NO_COMPATIBLE_TARGETS);
//   - every workflow step, when its command is built for a sensor
//     (FilterStepTargets): the run's typed targets the step's tool cannot
//     scan are left out of that step's command; a step with nothing left
//     fails with INCOMPATIBLE_TARGETS instead of reaching a sensor.
//
// Only targets whose type is known are gated: asset-group members carry their
// stored pair. A direct target is a string the tenant typed; it has no stored
// type and keeps the checks it always had. An `unclassified` asset, a type the
// registry does not know and a tool that declares no platform target type
// cannot be decided and are never refused here.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RunContextKeyTargetTypes is the run-context key holding the stored pair of
// every typed target (asset-group member) of a run: target name ->
// "type" or "type/sub_type". Steps read it to gate their targets; it is
// never sent to a sensor.
const RunContextKeyTargetTypes = "target_types"

// RunContextKeyActor is the run-context key holding the user a run acts
// for: who triggered it, else the scan's owner (a scheduled run). Chained
// stages check derived targets against that user's act scope. Platform
// bookkeeping: never sent to a sensor.
const RunContextKeyActor = "actor_user_id"

// Error codes of the gate.
const (
	codeNoCompatibleTargets  = "NO_COMPATIBLE_TARGETS"
	codeIncompatibleTargets  = "INCOMPATIBLE_TARGETS"
	maxIncompatibleTypeNames = 10
)

// scannerTypeGate gates typed targets for one tool.
type scannerTypeGate struct {
	tool    string
	compat  *typeCompatibility
	skipped map[string]int // type label -> members left out
}

// newScannerTypeGate returns the gate of a tool, or nil when nothing can be
// decided for it (no tool name, no tool repository, an unknown tool, or a
// tool that declares no target type). A failed tool or mapping lookup is
// returned: the caller does not dispatch (fail closed).
func (s *Service) newScannerTypeGate(ctx context.Context, tenantID shared.ID, toolName string) (*scannerTypeGate, error) {
	if strings.TrimSpace(toolName) == "" || s.toolRepo == nil {
		return nil, nil
	}
	t, err := s.toolRepo.GetByName(ctx, tenantID, toolName)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("scanner type check: get tool %q: %w", toolName, err)
	}
	if t == nil || len(t.SupportedTargets) == 0 {
		return nil, nil
	}
	compat, err := newTypeCompatibility(ctx, s.targetMappingRepo, t.SupportedTargets)
	if err != nil {
		return nil, fmt.Errorf("scanner type check: %w", err)
	}
	if !compat.known {
		return nil, nil
	}
	return &scannerTypeGate{tool: t.Name, compat: compat, skipped: map[string]int{}}, nil
}

// admits reports whether the tool can scan an asset of the stored pair, and
// counts it when not.
func (g *scannerTypeGate) admits(ref asset.TypeRef) bool {
	if g == nil {
		return true
	}
	ok, decidable := g.compat.decide(ref)
	if ok || !decidable {
		return true
	}
	g.skipped[typeLabel(asset.CanonicalPair(ref.Type, ref.SubType))]++
	return false
}

// total is the number of targets left out.
func (g *scannerTypeGate) total() int {
	if g == nil {
		return 0
	}
	n := 0
	for _, c := range g.skipped {
		n += c
	}
	return n
}

// describe names what was left out and why: "3 application/mobile_app,
// 1 repository: nuclei scans url, domain, ip (accepts ...)".
func (g *scannerTypeGate) describe() string {
	labels := make([]string, 0, len(g.skipped))
	for l := range g.skipped {
		labels = append(labels, l)
	}
	sort.Strings(labels)
	parts := make([]string, 0, len(labels))
	for i, l := range labels {
		if i == maxIncompatibleTypeNames {
			parts = append(parts, fmt.Sprintf("%d more type(s)", len(labels)-i))
			break
		}
		parts = append(parts, fmt.Sprintf("%d %s", g.skipped[l], l))
	}
	return fmt.Sprintf("%s cannot scan %s (it scans target types %s)",
		g.tool, strings.Join(parts, ", "), strings.Join(g.compat.targets, ", "))
}

// ParseTypeLabel reads a stored pair written by typeLabel ("type" or
// "type/sub_type").
func parseTypeLabel(label string) asset.TypeRef {
	t, sub, _ := strings.Cut(label, "/")
	return asset.TypeRef{Type: asset.AssetType(t), SubType: sub}
}

// StepTargets is what one workflow step may dispatch.
type StepTargets struct {
	// Targets is the run's target list minus the typed targets the step's
	// tool cannot scan, in the run's order. Nil when the run has none.
	Targets []string
	// Refused counts the targets left out; Reason names them.
	Refused int
	Reason  string
}

// FilterStepTargets gates a run's targets for one workflow step's tool. A
// run without typed targets, or a tool nothing can be decided for, keeps
// every target. Every target being refused is an error
// (INCOMPATIBLE_TARGETS, wrapping shared.ErrValidation): the step must not
// reach a sensor with nothing it can scan.
func (s *Service) FilterStepTargets(ctx context.Context, tenantID shared.ID, toolName string, runContext map[string]any) (*StepTargets, error) {
	// Every step dispatch (scan runs and direct scan runs) passes here:
	// a tool the organization disabled never reaches a sensor.
	if s.tenantTools != nil && s.toolRepo != nil && strings.TrimSpace(toolName) != "" {
		if t, err := s.toolRepo.GetByName(ctx, tenantID, toolName); err == nil {
			if err := s.checkTenantToolEnabled(ctx, tenantID, t); err != nil {
				return nil, err
			}
		}
	}
	targets := contextTargets(runContext)
	out, err := s.filterStepTypes(ctx, tenantID, toolName, targets, contextTargetTypes(runContext))
	if err != nil {
		return nil, err
	}
	// The step's own tier: its tool's ceiling against the scope entries,
	// and proof for an intrusive tool (RFC-054 §4.2 step 6, §8.1).
	kept, refused, reason, err := s.stepScopeFilter(ctx, tenantID, toolName, out.Targets)
	if err != nil {
		return nil, err
	}
	if refused == 0 {
		return out, nil
	}
	out.Targets = kept
	out.Refused += refused
	if out.Reason != "" {
		out.Reason += "; "
	}
	out.Reason += reason
	if len(kept) == 0 {
		return nil, shared.NewDomainError(CodeStepTargetsRefused,
			"No target of this step may be probed by "+toolName+": "+reason+".", shared.ErrValidation)
	}
	return out, nil
}

// CodeStepTargetsRefused: a workflow step whose every target the tier
// ceiling or the proof requirement refused.
const CodeStepTargetsRefused = "STEP_TARGETS_REFUSED"

// filterStepTypes leaves out the typed targets the step's tool cannot scan.
func (s *Service) filterStepTypes(ctx context.Context, tenantID shared.ID, toolName string, targets []string, types map[string]string) (*StepTargets, error) {
	out := &StepTargets{Targets: targets}
	if len(targets) == 0 || len(types) == 0 {
		return out, nil
	}
	gate, err := s.newScannerTypeGate(ctx, tenantID, toolName)
	if err != nil || gate == nil {
		return out, err
	}
	kept := make([]string, 0, len(targets))
	for _, t := range targets {
		if label, typed := types[t]; typed && !gate.admits(parseTypeLabel(label)) {
			continue
		}
		kept = append(kept, t)
	}
	out.Targets = kept
	out.Refused = gate.total()
	if out.Refused == 0 {
		return out, nil
	}
	out.Reason = gate.describe()
	if len(kept) == 0 {
		return nil, shared.NewDomainError(codeIncompatibleTargets,
			"No target of this step can be scanned: "+out.Reason+".", shared.ErrValidation)
	}
	return out, nil
}

// StepRunContext is the run context a step's command carries: the step's own
// targets, and no target_types or actor (platform bookkeeping, never sent to
// a sensor).
func StepRunContext(runContext map[string]any, st *StepTargets) map[string]any {
	if runContext == nil {
		return nil
	}
	out := maps.Clone(runContext)
	delete(out, RunContextKeyTargetTypes)
	delete(out, RunContextKeyActor)
	delete(out, RunContextKeyWindowWaits)
	if st != nil && st.Targets != nil {
		if _, had := out["targets"]; had {
			out["targets"] = st.Targets
		}
	}
	return out
}

// contextTargets reads the run's `targets` list (a []string before the run
// is stored, a []any after a JSON round trip).
func contextTargets(rc map[string]any) []string {
	switch ts := rc["targets"].(type) {
	case []string:
		return ts
	case []any:
		out := make([]string, 0, len(ts))
		for _, v := range ts {
			if str, ok := v.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

// contextTargetTypes reads RunContextKeyTargetTypes.
func contextTargetTypes(rc map[string]any) map[string]string {
	switch m := rc[RunContextKeyTargetTypes].(type) {
	case map[string]string:
		return m
	case map[string]any:
		out := make(map[string]string, len(m))
		for k, v := range m {
			if str, ok := v.(string); ok {
				out[k] = str
			}
		}
		return out
	}
	return nil
}
