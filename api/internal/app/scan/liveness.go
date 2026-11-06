package scan

// Live hosts first for address ranges. Design:
// docs/rfcs/RFC-088-scope-aware-target-allocation.md; architecture:
// docs/architecture/scan-targets.md.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// RunContextKeyCIDRMode is the run context key of the scan's CIDR mode
// when it is liveness: the step planner sends ranges only to host
// discovery and passive stages (LivenessSeeds). Never sent to a sensor.
const RunContextKeyCIDRMode = "cidr_mode"

// CodeLivenessNeedsHostDiscovery: a scan whose ranges are scanned live
// hosts first runs a workflow without a host discovery step.
const CodeLivenessNeedsHostDiscovery = "LIVENESS_NEEDS_HOST_DISCOVERY"

// CodeLargeRangeNeedsLiveness: a scan names a range wider than a /16 and
// scans every address of its ranges (sweep). Such a range is scanned live
// hosts first only (RFC-151).
const CodeLargeRangeNeedsLiveness = "LARGE_RANGE_NEEDS_LIVENESS"

// hasLargeRangeTarget reports whether a target list holds a range wider
// than MaxRangeAddresses (a /16).
func hasLargeRangeTarget(targets []string) bool {
	for _, t := range targets {
		if r, ok := rangeTarget(strings.TrimSpace(t)); ok {
			if n, full := r.Size(); full || n > MaxRangeAddresses {
				return true
			}
		}
	}
	return false
}

// hasRangeTarget reports whether a target list holds an address range.
func hasRangeTarget(targets []string) bool {
	for _, t := range targets {
		if _, ok := rangeTarget(strings.TrimSpace(t)); ok {
			return true
		}
	}
	return false
}

// workflowFindsHosts reports whether a scan workflow has a host discovery
// step (a step whose stage is discover.hosts).
func (s *Service) workflowFindsHosts(ctx context.Context, workflowID shared.ID) (bool, error) {
	if s.stepRepo == nil {
		return false, nil
	}
	steps, err := s.stepRepo.GetByScanWorkflowID(ctx, workflowID)
	if err != nil {
		return false, fmt.Errorf("read the scan workflow steps: %w", err)
	}
	for _, st := range steps {
		if sg, ok := stage.ForStep(st.Tool, st.Capabilities); ok && sg.Key == stage.DiscoverHosts {
			return true, nil
		}
	}
	return false, nil
}

// applyCIDRMode settles the CIDR mode of a scan being saved. A scan with a
// range that names no mode gets liveness when its scan runs it (a
// single-scanner scan, or a workflow with a host discovery step) and sweep
// otherwise; explicit liveness on a workflow without host discovery is
// refused, because its active stages would get no range and find no host.
// explicit says whether the request named the mode.
//
// A range wider than a /16 is scanned live hosts first only (RFC-151): the
// host discovery pass sweeps its /16 chunks and only the hosts it finds
// reach the port and vulnerability stages. Sweep, or a workflow without a
// host discovery step, is refused for such a scan.
func (s *Service) applyCIDRMode(ctx context.Context, sc *scan.Scan, explicit bool) error {
	if !hasRangeTarget(sc.Targets) {
		return nil
	}
	mode := sc.TargetOptions.CIDRMode
	large := hasLargeRangeTarget(sc.Targets)
	if large && mode != "" && mode != scan.CIDRModeLiveness {
		return shared.NewDomainError(CodeLargeRangeNeedsLiveness,
			"A range wider than a /16 is scanned live hosts first: a host discovery pass finds the live hosts, and only those are scanned further. Choose Live hosts first, or split the range into /16 ranges or smaller.",
			shared.ErrValidation)
	}
	if explicit && mode != scan.CIDRModeLiveness {
		return nil
	}
	if !explicit && mode != "" {
		return nil
	}
	finds := true
	if sc.ScanType == scan.ScanTypeWorkflow && sc.ScanWorkflowID != nil {
		var err error
		if finds, err = s.workflowFindsHosts(ctx, *sc.ScanWorkflowID); err != nil {
			return err
		}
	}
	switch {
	case finds:
		sc.TargetOptions.CIDRMode = scan.CIDRModeLiveness
	case explicit, large:
		return shared.NewDomainError(CodeLivenessNeedsHostDiscovery,
			"Live hosts first needs a Host discovery step in the scan workflow, before the steps that scan the hosts. Add one, use the Network workflow, or scan every address of the ranges.",
			shared.ErrValidation)
	}
	return nil
}

// LivenessSeeds is what a workflow step takes from the run's seeds when the
// run scans its ranges live hosts first (run context cidr_mode liveness):
// host discovery and passive stages keep every seed; every other step drops
// the ranges and keeps the rest (the inventory's addresses inside them,
// names, URLs). Its live hosts reach it from the host discovery step it
// follows. Another run is unchanged.
func LivenessSeeds(runContext map[string]any, resolved StepTool, st *StepTargets) *StepTargets {
	if mode, _ := runContext[RunContextKeyCIDRMode].(string); mode != string(scan.CIDRModeLiveness) {
		return st
	}
	if resolved.HasStage && (resolved.Stage.Key == stage.DiscoverHosts || resolved.Stage.Tier.Passive()) {
		return st
	}
	if !resolved.HasStage && stage.PassiveTool(resolved.Name) {
		return st
	}
	targets := runTargetList(st, runContext)
	if targets == nil {
		return st
	}
	kept := make([]string, 0, len(targets))
	dropped := 0
	for _, t := range targets {
		if _, ok := rangeTarget(strings.TrimSpace(t)); ok {
			dropped++
			continue
		}
		kept = append(kept, t)
	}
	if dropped == 0 {
		return st
	}
	out := &StepTargets{Targets: kept}
	if st != nil {
		out.Refused, out.Reason = st.Refused, st.Reason
	}
	return out
}

// runTargetList is a step's explicit target list, else the run's.
func runTargetList(st *StepTargets, runContext map[string]any) []string {
	if st != nil && st.Targets != nil {
		return st.Targets
	}
	switch ts := runContext["targets"].(type) {
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

// ErrStepSettled is what the step queuer answers for a step it settled
// without a command because it had nothing to do (a host discovery step of a
// run without addresses): not a failure, but the run must be advanced so the
// steps after it start.
var ErrStepSettled = errors.New("step settled without a command")
