package scanrun

// The gate of path discovery on workflow steps
// (docs/architecture/web-discovery.md): a step that runs enumerate.web_paths
// is skipped with the reason while the organization has path discovery
// turned off, and at dispatch it keeps only the origins the same gate the
// coverage planner uses lets through (the daily request budget, an active
// scope entry naming the origin's host, the shared edge and program
// refusals, an edge that did not challenge the last probe, new inventory, no
// run within 30 days from any caller). Unwired, such a step is skipped (fail
// closed). The dispatch itself is claimed in the path discovery ledger by the
// web job guard every command passes, so a race cannot exceed the cap.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	commanddom "github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// PathDiscoveryGate is the organization's path discovery policy
// (coverage.PathDiscoveryPolicy).
type PathDiscoveryGate interface {
	PathDiscoveryEnabled(ctx context.Context, tenantID shared.ID) (bool, error)
	PathDiscoveryFit(ctx context.Context, tenantID shared.ID) (int, error)
	PathDiscoveryRefusals(ctx context.Context, tenantID shared.ID, targets []string) (map[string]string, error)
}

// SetPathDiscoveryGate wires the gate.
func (s *Service) SetPathDiscoveryGate(g PathDiscoveryGate) { s.pathGate = g }

// Skip reasons of a path discovery step.
const (
	skipPathDiscoveryOff     = "Path discovery is turned off for the organization (scope settings)."
	skipPathDiscoveryUnknown = "Path discovery is not configured on this server, or its switch could not be read."
)

// stepRunsPathDiscovery reports whether the step runs enumerate.web_paths.
func stepRunsPathDiscovery(step *scanworkflow.Step) bool {
	if step == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(step.Tool), commanddom.DiscoveryTool) {
		return true
	}
	for _, c := range step.Capabilities {
		w, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(c)), "@")
		if w == commanddom.DiscoveryCapability {
			return true
		}
	}
	return false
}

// pathDiscoverySkipReason is why a path discovery step does not run ("" when
// it runs, and for every other step).
func (s *Service) pathDiscoverySkipReason(ctx context.Context, run *scanrun.Run, step *scanworkflow.Step) string {
	if !stepRunsPathDiscovery(step) {
		return ""
	}
	if s.pathGate == nil || run == nil {
		return skipPathDiscoveryUnknown
	}
	on, err := s.pathGate.PathDiscoveryEnabled(ctx, run.TenantID)
	if err != nil {
		s.logger.Warn("path discovery switch unreadable; step skipped", "run_id", run.ID.String(), "error", logger.SanitizeError(err))
		return skipPathDiscoveryUnknown
	}
	if !on {
		return skipPathDiscoveryOff
	}
	return ""
}

// admitPathDiscovery leaves a path discovery step the origins the gate lets
// through (the other steps keep their targets). The origins left out are
// logged with their reasons; nothing left is a step without inputs.
func (s *Service) admitPathDiscovery(ctx context.Context, run *scanrun.Run, step *scanworkflow.Step, st *scanapp.StepTargets, run0 map[string]any) (*scanapp.StepTargets, error) {
	if !stepRunsPathDiscovery(step) {
		return st, nil
	}
	if s.pathGate == nil {
		return nil, &noInputsError{summary: skipPathDiscoveryUnknown}
	}
	targets := chunkTargets(st, run0)
	refused, err := s.pathGate.PathDiscoveryRefusals(ctx, run.TenantID, targets)
	if err != nil {
		return nil, fmt.Errorf("path discovery gate: %w", err)
	}
	fit, err := s.pathGate.PathDiscoveryFit(ctx, run.TenantID)
	if err != nil {
		return nil, fmt.Errorf("path discovery budget: %w", err)
	}
	kept := make([]string, 0, len(targets))
	why := map[string]int{}
	for _, t := range targets {
		switch r, bad := refused[t]; {
		case bad:
			why[r]++
		case len(kept) >= fit:
			why["budget"]++
		default:
			kept = append(kept, t)
		}
	}
	if len(why) > 0 {
		s.logger.Info("path discovery origins left out of a step", "run_id", run.ID.String(),
			"step_key", logger.SanitizeValue(step.StepKey), "kept", len(kept), "left_out", why)
	}
	if len(kept) == 0 {
		reasons := make([]string, 0, len(why))
		for r, n := range why {
			reasons = append(reasons, fmt.Sprintf("%d %s", n, r))
		}
		sort.Strings(reasons)
		return nil, &noInputsError{summary: "path discovery has no origin to run on now (" + strings.Join(reasons, ", ") + ")"}
	}
	out := &scanapp.StepTargets{Targets: kept}
	if st != nil {
		out.Refused, out.Reason = st.Refused, st.Reason
	}
	return out, nil
}
