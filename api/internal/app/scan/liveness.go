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
func (s *Service) workflowFindsHosts(ctx context.Context, tenantID, workflowID shared.ID) (bool, error) {
	if s.stepRepo == nil {
		return false, nil
	}
	steps, err := s.stepRepo.GetByScanWorkflowID(ctx, workflowID)
	if err != nil {
		return false, fmt.Errorf("read the scan workflow steps: %w", err)
	}
	cat, err := s.catalog(ctx, tenantID)
	if err != nil {
		return false, err
	}
	for _, st := range steps {
		if sg, ok := cat.ForStep(st.Tool, st.Capabilities); ok && sg.Key == stage.DiscoverHosts {
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
func (s *Service) applyCIDRMode(ctx context.Context, sc *scan.Scan, explicit bool) error {
	if !hasRangeTarget(sc.Targets) {
		return nil
	}
	mode := sc.TargetOptions.CIDRMode
	if explicit && mode != scan.CIDRModeLiveness {
		return nil
	}
	if !explicit && mode != "" {
		return nil
	}
	finds := true
	if sc.ScanType == scan.ScanTypeWorkflow && sc.ScanWorkflowID != nil {
		var err error
		if finds, err = s.workflowFindsHosts(ctx, sc.TenantID, *sc.ScanWorkflowID); err != nil {
			return err
		}
	}
	switch {
	case finds:
		sc.TargetOptions.CIDRMode = scan.CIDRModeLiveness
	case explicit:
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
func LivenessSeeds(cat stage.Catalog, runContext map[string]any, resolved StepTool, st *StepTargets) *StepTargets {
	if mode, _ := runContext[RunContextKeyCIDRMode].(string); mode != string(scan.CIDRModeLiveness) {
		return st
	}
	if resolved.HasStage && (resolved.Stage.Key == stage.DiscoverHosts || resolved.Stage.Tier.Passive()) {
		return st
	}
	if !resolved.HasStage && cat.PassiveTool(resolved.Name) {
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
