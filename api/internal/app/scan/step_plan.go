package scan

// One planner for every workflow step (research/27 P0-2;
// docs/architecture/scan-stages.md): the tool a step runs and the command
// payload a sensor receives are decided here, for both the scan trigger and
// the scan run service. Two dispatchers used to build their own payloads and
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
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/domain/toolbudget"
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
	// Candidates are the tools the step could run, in the order tried
	// (the pin alone for a pinned step).
	Candidates []string
	// Catalog is the organization's catalog the step was resolved in; the
	// checks and the payload of the step read the same one.
	Catalog stage.Catalog
}

// Capability is the versioned capability the step runs ("scan.ports@1"),
// empty for a step the catalog cannot place.
func (t StepTool) Capability() string {
	if !t.HasStage {
		return ""
	}
	return t.Stage.ID()
}

// StepToolLookup is the slice of the tool registry the planner reads.
type StepToolLookup interface {
	// GetByName resolves a tool name as the tenant sees it: the platform
	// tool of that name, else the tenant's own tool (a tool its sensors
	// declare); never another tenant's.
	GetByName(ctx context.Context, tenantID shared.ID, name string) (*tool.Tool, error)
	FindByCapabilities(ctx context.Context, tenantID shared.ID, capabilities []string) (*tool.Tool, error)
}

// ResolveStepTool decides the tool a step runs:
//
//   - a step that names a tool runs that tool (whether it exists and is
//     active is the caller's strict check, as before);
//   - a step that names a catalog capability (a stage key such as
//     "scan.ports", or a word that names one stage, such as "portscan") runs
//     the first active implementation of that stage in the organization's
//     catalog (the tools whose reported contracts implement it) that
//     accepts the step's standard params: in the step's prefer_tools order
//     when it has one, else the catalog order, the default first. A tool that does
//     not take a param the step sets is skipped, never handed the step with
//     that value dropped. None left is NO_MATCHING_TOOL, with the reasons;
//   - capabilities that name more than one stage are refused
//     (STEP_CAPABILITY_AMBIGUOUS), never guessed;
//   - capabilities the catalog does not know fall back to the tenant's
//     active tool with all of them (platform tools first), as before.
//
// A collector or connector is never picked for a capability. The tenant id
// scopes every lookup: cat is the tenant's catalog, and an implementation
// is read by name among platform tools and the tenant's own, never another
// tenant's tool of that name.
func ResolveStepTool(ctx context.Context, tools StepToolLookup, cat stage.Catalog, tenantID shared.ID, step *scanworkflow.Step) (StepTool, error) {
	if step == nil {
		return StepTool{}, shared.NewDomainError(codeStepInvalid, "step is missing", shared.ErrValidation)
	}
	if name := strings.TrimSpace(step.Tool); name != "" {
		st, ok := cat.ForStep(name, step.Capabilities)
		return StepTool{Name: name, Pinned: true, Stage: st, HasStage: ok, Candidates: []string{name}, Catalog: cat}, nil
	}
	if len(step.Capabilities) == 0 {
		return StepTool{}, shared.NewDomainError(codeStepInvalid,
			fmt.Sprintf("Step '%s' has no tool or capabilities configured. Edit the scan workflow and configure a scanner for this step.", step.StepKey),
			shared.ErrValidation)
	}
	if tools == nil {
		return StepTool{}, fmt.Errorf("step %s: tool registry is not configured; nothing dispatched", step.StepKey)
	}
	st, err := cat.ForCapabilities(step.Capabilities)
	switch {
	case err == nil:
		candidates := stepCandidates(st, step)
		var skipped []string
		for _, name := range candidates {
			if missing := stage.UnsupportedParams(st, name, step.Config); len(missing) > 0 {
				skipped = append(skipped, fmt.Sprintf("%s does not take %s", name, strings.Join(missing, ", ")))
				continue
			}
			t, lerr := tools.GetByName(ctx, tenantID, name)
			if lerr != nil {
				if errors.Is(lerr, shared.ErrNotFound) {
					continue
				}
				return StepTool{}, fmt.Errorf("step %s: look up tool %q: %w", step.StepKey, name, lerr)
			}
			if usableScanner(t) {
				return StepTool{Name: t.Name, Stage: st, HasStage: true, Candidates: candidates, Catalog: cat}, nil
			}
		}
		reason := ""
		if len(skipped) > 0 {
			reason = " (" + strings.Join(skipped, "; ") + ")"
		}
		return StepTool{}, shared.NewDomainError(codeNoMatchingTool,
			fmt.Sprintf("No active tool runs '%s' for step '%s' (it can run on %s)%s. Enable one of them, change the settings or pin a tool.",
				st.Key, step.StepKey, strings.Join(candidates, ", "), reason),
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
	return StepTool{Name: t.Name, Catalog: cat}, nil
}

// stepCandidates are the tools a capability step may run, in the order
// tried: its prefer_tools (those that implement the capability) or the
// catalog order, the default first.
func stepCandidates(st stage.Stage, step *scanworkflow.Step) []string {
	if len(step.PreferTools) == 0 {
		return st.Tools()
	}
	out := make([]string, 0, len(step.PreferTools))
	for _, t := range step.PreferTools {
		t = strings.ToLower(strings.TrimSpace(t))
		if st.Implements(t) && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// usableScanner reports whether a tool can run a dispatched scan step.
func usableScanner(t *tool.Tool) bool {
	return t != nil && t.IsActive && !t.IsCollector() && !t.IsConnector()
}

// WithTool returns a copy of the step that runs the resolved tool, for the
// checks and payload that read step.Tool and step.Config: the config is the
// one that tool receives (its keys for the standard params, its extras).
func (t StepTool) WithTool(step *scanworkflow.Step) *scanworkflow.Step {
	cp := *step
	cp.Tool = t.Name
	if t.HasStage {
		cp.Config = stage.ToolConfig(t.Stage, t.Name, step.Config, t.Pinned)
	}
	return &cp
}

// StepCommandPayload is the command payload of one workflow step, built the
// same way for every dispatcher. The resolved tool is always named in
// `scanner` (the key the sensor SDK runs, ScanCommandPayload) and in
// `preferred_tool` (the platform's tool gate and older readers). The step's
// settings go under PayloadKeyConfig, normalized for that tool; a setting
// the sensor would refuse fails here, before any command exists. The step's
// targets (the type-gated run targets, or the hop router's plan) are at the
// top level, where sensors read them; the run context goes along without
// platform bookkeeping (StepRunContext).
func StepCommandPayload(cat stage.Catalog, run *scanrun.Run, step *scanworkflow.Step, toolName, stepRunID string, st *StepTargets) (map[string]any, error) {
	toolName = strings.TrimSpace(toolName)
	if toolName == "" {
		return nil, shared.NewDomainError(codeNoMatchingTool,
			fmt.Sprintf("step %s has no tool to run", step.StepKey), shared.ErrValidation)
	}
	config, err := scanworkflow.NormalizeStepConfig(toolName, step.Config)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{
		scanrun.PayloadKeyScanRunID:   run.ID.String(),
		scanrun.PayloadKeyStepRunID:   stepRunID,
		scanrun.PayloadKeyStepKey:     step.StepKey,
		"step_id":                     step.ID.String(),
		scanworkflow.PayloadKeyConfig: config,
		"required_capabilities":       step.Capabilities,
		"preferred_tool":              toolName,
		"scanner":                     toolName,
		"timeout_seconds":             step.TimeoutSeconds,
		"context":                     StepRunContext(run.Context, st),
	}
	if targets, ok := run.Context["targets"]; ok {
		payload["targets"] = targets
		if st != nil && st.Targets != nil {
			payload["targets"] = st.Targets
		}
	}
	// The task's layered budget (research/122): the sensor bounds each
	// target with it and stops the task at the step's timeout_seconds when
	// set, else at twice its expected time (the platform's overrun re-queue
	// waits for the same deadline);
	// the platform calls the task stalled when no target finishes within
	// the stall window.
	payload[PayloadKeyBudget] = toolbudget.ForTask(toolName, payloadTargetCount(payload["targets"]))
	if run.AssetID != nil {
		payload["asset_id"] = run.AssetID.String()
	}
	// A capability job (RFC-055): the sensor checks that the tool implements
	// the capability, checks the output against its contract and stamps it
	// in the provenance; the platform's grant check applies the
	// capability's tier floor. The settings stay in config, mapped to the
	// tool's keys as before, so an older sensor runs the step unchanged.
	// Every tool whose reported contract implements the stage takes
	// capability jobs.
	if st, ok := cat.ForStep(toolName, step.Capabilities); ok {
		payload[PayloadKeyCapability] = st.ID()
		// The platform decides how hosts are probed: a host discovery step
		// that names no ports probes the platform's set, never a default
		// a sensor picks.
		if st.Key == stage.DiscoverHosts {
			if key, ok := st.ToolParamKey(toolName, "ports"); ok {
				if config == nil {
					config = map[string]any{}
				}
				if _, set := config[key]; !set {
					config[key] = stage.HostProbePorts
					payload[scanworkflow.PayloadKeyConfig] = config
				}
			}
		}
	}
	if c := withWildcardFilter(toolName, config); c != nil {
		payload[scanworkflow.PayloadKeyConfig] = c
	}
	return payload, nil
}

// PayloadKeyBudget is the command payload key of the task's budget
// (toolbudget.Task; sdk-go ScanCommandPayload.Budget).
const PayloadKeyBudget = "budget"

// payloadTargetCount is how many targets a payload's "targets" holds.
func payloadTargetCount(v any) int {
	switch ts := v.(type) {
	case []string:
		return len(ts)
	case []any:
		return len(ts)
	}
	return 1
}

// wildcardFilterKey is dnsx's setting that drops names resolving only
// through a wildcard record.
const wildcardFilterKey = "wildcard_filter"

// withWildcardFilter turns the wildcard-DNS filter on for a dnsx job that
// does not set it (RFC-088 decision A4): the platform decides it, so a
// wildcard zone never floods the inventory with names that only resolve
// through it, whatever a sensor's own default is. nil when unchanged.
func withWildcardFilter(tool string, config map[string]any) map[string]any {
	if !strings.EqualFold(strings.TrimSpace(tool), "dnsx") {
		return nil
	}
	if _, set := config[wildcardFilterKey]; set {
		return nil
	}
	out := make(map[string]any, len(config)+1)
	for k, v := range config {
		out[k] = v
	}
	out[wildcardFilterKey] = true
	return out
}

// PayloadKeyCapability is the command payload key of a capability job's
// capability ("scan.ports@1"; sdk-go ScanCommandPayload.Capability).
const PayloadKeyCapability = "capability"

// StepQueuer queues one step of a run on the scan run service's dispatcher
// (*scanrun.Service): the one path every step command is created on.
type StepQueuer interface {
	QueueRunStep(ctx context.Context, run *scanrun.Run, step *scanworkflow.Step) error
}

// RunAdvancer re-evaluates a run whose first steps were just handed to the
// StepQueuer: steps that could not be queued are failed already, dependents
// that can no longer run are skipped, and a run with nothing left to run
// settles. The scan run service implements it.
type RunAdvancer interface {
	AdvanceRun(ctx context.Context, run *scanrun.Run) error
}

// SetStepQueuer wires the step dispatcher the scan trigger hands workflow
// steps to. A setter because the scan run service is built after the scan
// service. Without it a workflow scan is refused (fail closed).
func (s *Service) SetStepQueuer(q StepQueuer) { s.stepQueuer = q }

// SetWorkflowVersions pins each workflow run to the scan workflow version
// it starts with (research/62 P0-10); the scan run service then reads that
// version for every later step.
func (s *Service) SetWorkflowVersions(store scanworkflow.VersionStore) { s.workflowVersions = store }

// ErrStepQueuerUnavailable: no step dispatcher is wired.
var ErrStepQueuerUnavailable = errors.New("workflow step dispatcher is not configured; nothing dispatched")
