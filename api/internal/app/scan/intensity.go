package scan

// Scan intensity (docs/rfcs/RFC-071-scan-intensity.md): the probe ceiling a
// scan's runs may reach, chosen when the scan is saved. A single-scanner
// scan whose tool, or a workflow scan with a step, above the ceiling is
// refused when it is saved; a run copies the ceiling into its context and a
// step above it is skipped, never dispatched (scanrun); the claim refuses a
// command whose tier is above the ceiling it was queued with.

import (
	"context"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// RunContextKeyIntensity is the run context key holding the scan's
// intensity ("passive", "active", "intrusive") when the run started. Never
// read from a trigger's context: the trigger overwrites it.
const RunContextKeyIntensity = scanrun.RunContextKeyIntensity

// StepIntensityTier is the tier a workflow step counts at against the
// scan's intensity (stage.IntensityTier).
func StepIntensityTier(step *scanworkflow.Step) int {
	if step == nil {
		return int(stage.TierActive)
	}
	return int(stage.IntensityTier(step.Tool, step.Capabilities, step.Config))
}

// probeCeiling is the highest tier the scan's tool or workflow steps probe
// at, and what reaches it (for the refusal message).
func (s *Service) probeCeiling(ctx context.Context, sc *scan.Scan) (int, string, error) {
	if sc.ScanType != scan.ScanTypeWorkflow {
		return int(stage.IntensityTier(sc.ScannerName, nil, sc.ScannerConfig)), fmt.Sprintf("Scanner %q", sc.ScannerName), nil
	}
	if sc.ScanWorkflowID == nil || s.stepRepo == nil {
		return int(stage.TierActive), "The workflow", nil
	}
	steps, err := s.stepRepo.GetByScanWorkflowID(ctx, *sc.ScanWorkflowID)
	if err != nil {
		return 0, "", fmt.Errorf("failed to get scan workflow steps: %w", err)
	}
	if len(steps) == 0 {
		return int(stage.TierActive), "The workflow", nil
	}
	top, what := -1, ""
	for _, st := range steps {
		if t := StepIntensityTier(st); t > top {
			top, what = t, fmt.Sprintf("Workflow step %q", st.StepKey)
		}
	}
	return top, what, nil
}

// applyIntensity sets the scan's intensity and refuses a tool or step above
// it. requested "" takes the tier the scan already probes at (an API caller
// that does not choose); the web always sends one. The intensity is the
// scan's own ceiling: it is not compared with scope entries.
func (s *Service) applyIntensity(ctx context.Context, sc *scan.Scan, requested string) error {
	top, what, err := s.probeCeiling(ctx, sc)
	if err != nil {
		return err
	}
	intensity := scan.IntensityForTier(top)
	if requested != "" {
		if intensity, err = scan.ParseIntensity(requested); err != nil {
			return err
		}
	}
	if !intensity.Allows(top) {
		return scan.IntensityExceededError(intensity, what, top)
	}
	return sc.SetIntensity(intensity)
}

// refuseRunAboveIntensity refuses a single-scanner run whose tool probes
// above the scan's intensity (the scan was saved before a tool change, or
// its row was edited). A workflow is checked per step at dispatch.
func refuseRunAboveIntensity(sc *scan.Scan) error {
	if sc.ScanType == scan.ScanTypeWorkflow || sc.ScannerName == "" {
		return nil
	}
	i := sc.EffectiveIntensity()
	if t := int(stage.IntensityTier(sc.ScannerName, nil, sc.ScannerConfig)); !i.Allows(t) {
		return scan.IntensityExceededError(i, fmt.Sprintf("Scanner %q", sc.ScannerName), t)
	}
	return nil
}

// RunIntensity is the intensity a run records, or "" for a run that has
// none (a workflow run started without a scan, or before intensities).
func RunIntensity(run *scanrun.Run) scan.Intensity {
	if run == nil {
		return ""
	}
	raw, _ := run.Context[RunContextKeyIntensity].(string)
	i, err := scan.ParseIntensity(raw)
	if err != nil {
		return ""
	}
	return i
}

// IntensitySkipReason is why a workflow step is skipped in a run: it
// probes above the intensity the run started with; "" when it fits, or the
// run has no intensity.
func IntensitySkipReason(run *scanrun.Run, step *scanworkflow.Step) string {
	return intensitySkipReason(RunIntensity(run), StepIntensityTier(step))
}

// IntensitySkipReasonForTier is IntensitySkipReason for a step whose tool
// is resolved: tier is the resolved tool's tier.
func IntensitySkipReasonForTier(run *scanrun.Run, tier int) string {
	return intensitySkipReason(RunIntensity(run), tier)
}

func intensitySkipReason(i scan.Intensity, tier int) string {
	if i == "" || i.Allows(tier) {
		return ""
	}
	return fmt.Sprintf("skipped: this step probes at %s, above the scan's %s intensity", scan.TierLabel(tier), i)
}
