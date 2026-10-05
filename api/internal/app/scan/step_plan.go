package scan

// One planner for every pipeline step (research/27 P0-2;
// docs/architecture/scan-stages.md): the tool a step runs and the command
// payload a sensor receives are decided here, for both the scan trigger and
// the pipeline service. Two dispatchers used to build their own payloads and
// drifted apart.
//
// F1: a step that named only a capability passed validation (a tool matched
// it) but its command carried no `scanner`, so every sensor failed it with
// "scanner not found: ". The planner now resolves capability -> tool once,
// with the same rule validation uses, and the payload always names the tool.
// Owner decision G10: a pinned tool is strict; a capability-only step may
// run any active implementation of its stage, the catalog default first.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
)

// Error codes of the planner.
const (
	codeNoMatchingTool       = "NO_MATCHING_TOOL"
	codeStepCapabilityUnsure = "STEP_CAPABILITY_AMBIGUOUS"
	codeStepInvalid          = "STEP_INVALID"
)

// StepTool is the tool a step runs.
type StepTool struct {
	// Name is the tool registry name the command's `scanner` carries.
	Name string
	// Pinned: the step names the tool itself (strict, G10).
	Pinned bool
	// Stage is the catalog stage the step runs; HasStage is false for a
	// step the catalog cannot place (a tenant tool), which never chains.
	Stage    stage.Stage
	HasStage bool
}

// StepToolLookup is the slice of the tool registry the planner reads.
type StepToolLookup interface {
	GetPlatformToolByName(ctx context.Context, name string) (*tool.Tool, error)
	FindByCapabilities(ctx context.Context, tenantID shared.ID, capabilities []string) (*tool.Tool, error)
}

// ResolveStepTool decides the tool a step runs:
//
//   - a step that names a tool runs that tool (whether it exists and is
//     active is the caller's strict check, as before);
//   - a step that names a catalog capability (a stage key such as
//     "scan.ports", or a word that names one stage, such as "portscan") runs
//     the first active platform implementation of that stage, the default
//     first; none active is NO_MATCHING_TOOL;
//   - capabilities that name more than one stage are refused
//     (STEP_CAPABILITY_AMBIGUOUS), never guessed;
//   - capabilities the catalog does not know fall back to the tenant's
//     active tool with all of them (platform tools first), as before.
//
// A collector or connector is never picked for a capability. The tenant id
// scopes the fallback lookup; a platform implementation is read by name
// among platform tools only, never another tenant's tool of that name.
func ResolveStepTool(ctx context.Context, tools StepToolLookup, tenantID shared.ID, step *pipeline.Step) (StepTool, error) {
	if step == nil {
		return StepTool{}, shared.NewDomainError(codeStepInvalid, "step is missing", shared.ErrValidation)
	}
	if name := strings.TrimSpace(step.Tool); name != "" {
		st, ok := stage.ForStep(name, step.Capabilities)
		return StepTool{Name: name, Pinned: true, Stage: st, HasStage: ok}, nil
	}
	if len(step.Capabilities) == 0 {
		return StepTool{}, shared.NewDomainError(codeStepInvalid,
			fmt.Sprintf("Step '%s' has no tool or capabilities configured. Please edit the pipeline and configure a scanner for this step.", step.StepKey),
			shared.ErrValidation)
	}
	if tools == nil {
		return StepTool{}, fmt.Errorf("step %s: tool registry is not configured; nothing dispatched", step.StepKey)
	}
	st, err := stage.ForCapabilities(step.Capabilities)
	switch {
	case err == nil:
		for _, name := range st.Tools() {
			t, lerr := tools.GetPlatformToolByName(ctx, name)
			if lerr != nil {
				if errors.Is(lerr, shared.ErrNotFound) {
					continue
				}
				return StepTool{}, fmt.Errorf("step %s: look up tool %q: %w", step.StepKey, name, lerr)
			}
			if usableScanner(t) {
				return StepTool{Name: t.Name, Stage: st, HasStage: true}, nil
			}
		}
		return StepTool{}, shared.NewDomainError(codeNoMatchingTool,
			fmt.Sprintf("No active tool runs '%s' for step '%s' (it can run on %s). Enable one of them or pin a tool.",
				st.Key, step.StepKey, strings.Join(st.Tools(), ", ")),
			shared.ErrValidation)
	case errors.Is(err, stage.ErrAmbiguousCapability):
		return StepTool{}, shared.NewDomainError(codeStepCapabilityUnsure,
			fmt.Sprintf("Step '%s' names capabilities %v that match more than one kind of scan; pin a tool or keep one capability.",
				step.StepKey, step.Capabilities),
			shared.ErrValidation)
	}
	t, err := tools.FindByCapabilities(ctx, tenantID, step.Capabilities)
	if err != nil {
		return StepTool{}, fmt.Errorf("step %s: find tool by capabilities: %w", step.StepKey, err)
	}
	if !usableScanner(t) {
		return StepTool{}, shared.NewDomainError(codeNoMatchingTool,
			fmt.Sprintf("No active tool found for step '%s' with capabilities %v. Please configure a tool for this step.", step.StepKey, step.Capabilities),
			shared.ErrValidation)
	}
	return StepTool{Name: t.Name}, nil
}

// usableScanner reports whether a tool can run a dispatched scan step.
func usableScanner(t *tool.Tool) bool {
	return t != nil && t.IsActive && !t.IsCollector() && !t.IsConnector()
}

// WithTool returns a copy of the step that runs the resolved tool, for the
// checks and payload that read step.Tool.
func (t StepTool) WithTool(step *pipeline.Step) *pipeline.Step {
	cp := *step
	cp.Tool = t.Name
	return &cp
}

// StepCommandPayload is the command payload of one pipeline step, built the
// same way for every dispatcher. The resolved tool is always named in
// `scanner` (the key the sensor SDK runs, ScanCommandPayload) and in
// `preferred_tool` (the platform's tool gate and older readers). The step's
// settings go under PayloadKeyConfig, normalized for that tool; a setting
// the sensor would refuse fails here, before any command exists. The step's
// targets (the type-gated run targets, or the hop router's plan) are at the
// top level, where sensors read them; the run context goes along without
// platform bookkeeping (StepRunContext).
func StepCommandPayload(run *pipeline.Run, step *pipeline.Step, toolName, stepRunID string, st *StepTargets) (map[string]any, error) {
	toolName = strings.TrimSpace(toolName)
	if toolName == "" {
		return nil, shared.NewDomainError(codeNoMatchingTool,
			fmt.Sprintf("step %s has no tool to run", step.StepKey), shared.ErrValidation)
	}
	config, err := pipeline.NormalizeStepConfig(toolName, step.Config)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{
		pipeline.PayloadKeyPipelineRunID: run.ID.String(),
		pipeline.PayloadKeyStepRunID:     stepRunID,
		pipeline.PayloadKeyStepKey:       step.StepKey,
		"step_id":                        step.ID.String(),
		pipeline.PayloadKeyConfig:        config,
		"required_capabilities":          step.Capabilities,
		"preferred_tool":                 toolName,
		"scanner":                        toolName,
		"timeout_seconds":                step.TimeoutSeconds,
		"context":                        StepRunContext(run.Context, st),
	}
	if targets, ok := run.Context["targets"]; ok {
		payload["targets"] = targets
		if st != nil && st.Targets != nil {
			payload["targets"] = st.Targets
		}
	}
	if run.AssetID != nil {
		payload["asset_id"] = run.AssetID.String()
	}
	return payload, nil
}

// StepQueuer queues one step of a run on the pipeline service's dispatcher
// (*pipeline.Service): the one path every step command is created on.
type StepQueuer interface {
	QueueRunStep(ctx context.Context, run *pipeline.Run, step *pipeline.Step) error
}

// SetStepQueuer wires the step dispatcher the scan trigger hands workflow
// steps to. A setter because the pipeline service is built after the scan
// service. Without it a workflow scan is refused (fail closed).
func (s *Service) SetStepQueuer(q StepQueuer) { s.stepQueuer = q }

// ErrStepQueuerUnavailable: no step dispatcher is wired.
var ErrStepQueuerUnavailable = errors.New("workflow step dispatcher is not configured; nothing dispatched")
