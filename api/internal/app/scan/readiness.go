package scan

// Workflow readiness: whether a scan workflow can run for a tenant now, and
// why not, step by step. One computation from the same sources the
// dispatch gate reads (the tenant's tool availability: catalog, sensors,
// grants, manifests, zones; and the platform scanning offer), so the New
// Scan picker, the workflow list and the server-side refusal agree.
//
// States, per step and for the workflow:
//   - ready: a tool that runs the step is on an online sensor that may run it;
//   - waiting: such sensors exist but none is online now (a scheduled scan
//     queues; a run now is refused by the trigger-time availability check);
//   - ci_only: the step's capability runs in the CI images (code analysis)
//     and no sensor here offers it: it runs from the customer's CI pipeline;
//     Also waiting: the tool is enabled but no sensor of the organization
//     has advertised it yet (a new organization before its first sensor);
//   - blocked: no enabled tool runs the step, or no sensor may run one.
//   - skipped (steps only): an optional step (run_policy.optional) that no
//     installed tool implements. The run skips it with the reason
//     (scanrun optionalSkipMessage), so it never blocks the workflow; it is
//     reported so the list can say which step is left out and how to add
//     it. A workflow whose every step is skipped is blocked.
//
// Each step also carries a stable reason code and the tools it names, so
// the web app shows the reason in the reader's language; Reason and Fix
// stay as the English text (API clients, the refusal message).
//
// Platform sensors are counted as "platform scanning" only: never named or
// counted per sensor (the tenant view of #1362).

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// Readiness states.
const (
	ReadinessReady   = "ready"
	ReadinessWaiting = "waiting"
	ReadinessCIOnly  = "ci_only"
	ReadinessBlocked = "blocked"
	// ReadinessSkipped is a step state only: an optional step without a
	// tool, which the run skips with the reason.
	ReadinessSkipped = "skipped"
)

// Step readiness reason codes (StepReadiness.Code).
const (
	ReasonSensorOffline    = "sensor_offline"
	ReasonNoSensorYet      = "no_sensor_yet"
	ReasonCIOnly           = "ci_only"
	ReasonNoTool           = "no_tool"
	ReasonToolDisabled     = "tool_disabled"
	ReasonToolNotInstalled = "tool_not_installed"
	ReasonNoSensor         = "no_sensor"
)

// CodeWorkflowNotRunnable refuses a scan of a workflow that cannot run.
const CodeWorkflowNotRunnable = "WORKFLOW_NOT_RUNNABLE"

// ciCapabilities run in the CI images (openctemio/ci): code analysis on a
// repository checkout.
var ciCapabilities = map[stage.Key]bool{
	stage.SASTCode: true, stage.SecretsCode: true, stage.SCADeps: true, stage.IaCMisconfig: true,
}

// StepReadiness is one step's readiness.
type StepReadiness struct {
	StepKey    string `json:"step_key"`
	Name       string `json:"name"`
	Capability string `json:"capability,omitempty"`
	State      string `json:"state"`
	// Optional: the step is skipped by a run when no tool implements it.
	Optional bool `json:"optional,omitempty"`
	// Code is the stable reason code (Reason* constants); Tools are the
	// tools the reason and the fix name.
	Code   string   `json:"code,omitempty"`
	Tools  []string `json:"tools,omitempty"`
	Reason string   `json:"reason,omitempty"`
	Fix    string   `json:"fix,omitempty"`
}

// WorkflowReadiness is a workflow's readiness for one tenant.
type WorkflowReadiness struct {
	State string          `json:"state"`
	Steps []StepReadiness `json:"steps"`
}

// Runnable reports whether a scan may be created for the workflow.
func (r *WorkflowReadiness) Runnable() bool {
	return r == nil || r.State == ReadinessReady || r.State == ReadinessWaiting
}

// ToolStatuses is the tenant's tool availability by tool name (the tools of
// its catalog); nil means unknown.
type ToolStatuses func(ctx context.Context, tenantID shared.ID) (map[string]sensordom.ToolStatus, error)

// PlatformOffer is what platform scanning offers the tenant: whether it is
// offered, whether it can take work now, and the tools it runs.
type PlatformOffer func(ctx context.Context, tenantID shared.ID) (offered, online bool, tools []string, err error)

// WithReadinessSources enables workflow readiness.
func WithReadinessSources(statuses ToolStatuses, platform PlatformOffer) ServiceOption {
	return func(s *Service) {
		s.readiness = &readinessSources{statuses: statuses, platform: platform, cache: map[shared.ID]readinessSnapshot{}}
	}
}

// readinessTTL is how long one tenant's sources are reused.
const readinessTTL = 10 * time.Second

type readinessSnapshot struct {
	at        time.Time
	statuses  map[string]sensordom.ToolStatus
	pfOffered bool
	pfOnline  bool
	pfTools   []string
}

type readinessSources struct {
	statuses ToolStatuses
	platform PlatformOffer
	mu       sync.Mutex
	cache    map[shared.ID]readinessSnapshot
}

func (r *readinessSources) snapshot(ctx context.Context, tenantID shared.ID) (readinessSnapshot, bool, error) {
	r.mu.Lock()
	if snap, ok := r.cache[tenantID]; ok && time.Since(snap.at) < readinessTTL {
		r.mu.Unlock()
		return snap, true, nil
	}
	r.mu.Unlock()
	var snap readinessSnapshot
	if r.statuses == nil {
		return snap, false, nil
	}
	st, err := r.statuses(ctx, tenantID)
	if err != nil {
		return snap, false, err
	}
	if st == nil {
		return snap, false, nil
	}
	snap.statuses = st
	if r.platform != nil {
		if snap.pfOffered, snap.pfOnline, snap.pfTools, err = r.platform(ctx, tenantID); err != nil {
			return snap, false, err
		}
	}
	snap.at = time.Now()
	r.mu.Lock()
	r.cache[tenantID] = snap
	r.mu.Unlock()
	return snap, true, nil
}

// WorkflowReadiness computes the readiness of each workflow (with its steps
// loaded) for the tenant, in one pass over the tenant's sources. The result
// is nil when readiness is not wired or the sources are unknown.
func (s *Service) WorkflowReadiness(ctx context.Context, tenantID shared.ID, workflows []*scanworkflow.Workflow) (map[shared.ID]*WorkflowReadiness, error) {
	if s.readiness == nil {
		return nil, nil
	}
	snap, known, err := s.readiness.snapshot(ctx, tenantID)
	if err != nil || !known {
		return nil, err
	}
	out := make(map[shared.ID]*WorkflowReadiness, len(workflows))
	for _, w := range workflows {
		out[w.ID] = s.workflowReadiness(ctx, tenantID, w, snap)
	}
	return out, nil
}

func (s *Service) workflowReadiness(ctx context.Context, tenantID shared.ID, w *scanworkflow.Workflow, snap readinessSnapshot) *WorkflowReadiness {
	pref := w.Settings.SensorPreference
	usePlatform := snap.pfOffered && pref != scanworkflow.SensorPreferenceTenant
	useTenant := pref != scanworkflow.SensorPreferencePlatform
	r := &WorkflowReadiness{State: ReadinessReady, Steps: make([]StepReadiness, 0, len(w.Steps))}
	rank := map[string]int{ReadinessReady: 0, ReadinessWaiting: 1, ReadinessCIOnly: 2, ReadinessBlocked: 3}
	counted := 0
	for _, step := range w.Steps {
		sr := s.stepReadiness(ctx, tenantID, step, snap, useTenant, usePlatform)
		r.Steps = append(r.Steps, sr)
		if sr.State == ReadinessSkipped {
			continue
		}
		counted++
		if rank[sr.State] > rank[r.State] {
			r.State = sr.State
		}
	}
	// No steps, or only optional steps that all wait for a tool: a run
	// would do nothing.
	if counted == 0 {
		r.State = ReadinessBlocked
	}
	return r
}

// toolState is how a tool of the catalog can run for the tenant now:
// ready, waiting, or "" (no sensor may run it).
func (snap readinessSnapshot) toolState(name string, status sensordom.ToolStatus, useTenant, usePlatform bool) string {
	state := ""
	if useTenant {
		switch status {
		case sensordom.ToolReady, sensordom.ToolOutdated:
			state = ReadinessReady
		case sensordom.ToolOfflineOnly:
			state = ReadinessWaiting
		}
	}
	if state != ReadinessReady && usePlatform && slices.Contains(snap.pfTools, name) {
		if snap.pfOnline {
			return ReadinessReady
		}
		return ReadinessWaiting
	}
	return state
}

func (s *Service) stepReadiness(ctx context.Context, tenantID shared.ID, step *scanworkflow.Step, snap readinessSnapshot, useTenant, usePlatform bool) StepReadiness {
	sr := StepReadiness{StepKey: step.StepKey, Name: step.Name, Optional: step.RunPolicy.Optional}
	if sr.Name == "" {
		sr.Name = step.StepKey
	}
	st, placed := stage.ForStep(step.Tool, step.Capabilities)
	what := "this step"
	if placed {
		sr.Capability = string(st.Key)
		what = st.Name
	} else if len(step.Capabilities) > 0 {
		// A planned capability (an optional step that waits for a tool) is
		// still named, so the reader sees what is missing.
		sr.Capability = strings.ToLower(strings.TrimSpace(step.Capabilities[0]))
		what = sr.Capability
	}
	var candidates []string
	switch {
	case strings.TrimSpace(step.Tool) != "":
		candidates = []string{strings.ToLower(strings.TrimSpace(step.Tool))}
	case placed:
		// The organization's declared implementations are candidates too; a
		// failed lookup leaves only the catalog's (readiness is advisory).
		declared, _ := declaredImplementations(ctx, s.toolRepo, tenantID, st)
		candidates = stepCandidates(st, step, declared)
	default:
		if t, err := ResolveStepTool(ctx, s.toolRepo, tenantID, step); err == nil && t.Name != "" {
			candidates = []string{t.Name}
		}
	}

	best := ""
	var disabled, notInstalled, missing, noSensorYet []string
	for _, name := range candidates {
		status, inCatalog := snap.statuses[name]
		if !inCatalog {
			notInstalled = append(notInstalled, name)
			continue
		}
		if status == sensordom.ToolDisabled {
			disabled = append(disabled, name)
			continue
		}
		state := snap.toolState(name, status, useTenant, usePlatform)
		switch {
		case state == ReadinessReady:
			best = ReadinessReady
		case state == ReadinessWaiting && best == "":
			best = ReadinessWaiting
		case state == "":
			missing = append(missing, name)
			// An enabled tool that no sensor of the organization has
			// advertised yet: a sensor that connects later brings it.
			if status == sensordom.ToolNoSensor && useTenant {
				noSensorYet = append(noSensorYet, name)
			}
		}
		if best == ReadinessReady {
			break
		}
	}

	switch {
	case best == ReadinessReady:
		sr.State = ReadinessReady
	case best == ReadinessWaiting:
		sr.State, sr.Code, sr.Tools = ReadinessWaiting, ReasonSensorOffline, candidates
		sr.Reason = fmt.Sprintf("No sensor that can run %s is online now", what)
		sr.Fix = "Start a sensor that has one of: " + strings.Join(candidates, ", ")
	case len(noSensorYet) > 0 && !(placed && ciCapabilities[st.Key]):
		// Nothing is wrong with the workflow: no sensor with the tool has
		// connected yet. It can be saved and starts once one is online.
		sr.State, sr.Code, sr.Tools = ReadinessWaiting, ReasonNoSensorYet, noSensorYet
		sr.Reason = fmt.Sprintf("Waits for a sensor with %s", what)
		sr.Fix = "Add a sensor with " + strings.Join(noSensorYet, " or ")
	case placed && ciCapabilities[st.Key]:
		sr.State, sr.Code = ReadinessCIOnly, ReasonCIOnly
		sr.Reason = fmt.Sprintf("%s runs in your CI pipeline", st.Name)
		sr.Fix = "Set up the CI pipeline integration"
	case len(candidates) == 0:
		sr.State, sr.Code = ReadinessBlocked, ReasonNoTool
		sr.Reason = fmt.Sprintf("No tool runs %s", what)
		sr.Fix = "Pick another capability or a tool for the step"
	case len(missing) == 0 && len(disabled) > 0:
		sr.State, sr.Code, sr.Tools = ReadinessBlocked, ReasonToolDisabled, disabled
		sr.Reason = fmt.Sprintf("No enabled tool runs %s (%s is turned off)", what, strings.Join(disabled, ", "))
		sr.Fix = "Enable " + strings.Join(disabled, " or ")
	case len(missing) == 0:
		sr.State, sr.Code, sr.Tools = ReadinessBlocked, ReasonToolNotInstalled, notInstalled
		sr.Reason = fmt.Sprintf("%s is not installed in this organization", strings.Join(notInstalled, ", "))
		sr.Fix = "Pick \"Any tool\" for the step, or add the tool"

	default:
		sr.State, sr.Code, sr.Tools = ReadinessBlocked, ReasonNoSensor, missing
		sr.Reason = fmt.Sprintf("No sensor offers %s", what)
		sr.Fix = "Add a sensor with " + strings.Join(missing, " or ")
	}
	// An optional step that no installed and enabled tool implements is
	// skipped by the run (the dispatch refusal NO_MATCHING_TOOL): it never
	// blocks the workflow. A tool that is installed but on no sensor still
	// blocks, because the run would dispatch it.
	if sr.State == ReadinessBlocked && step.RunPolicy.Optional && len(missing) == 0 {
		sr.State = ReadinessSkipped
		sr.Reason = "Skipped: " + lowerFirst(sr.Reason) + "; the workflow runs without this step"
	}
	return sr
}

// lowerFirst lower-cases the first letter of a sentence that continues
// another (tool names are already lower case).
func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// requireWorkflowRunnable refuses a workflow that is blocked or runs only
// in CI, naming the steps and why. Unknown readiness lets it through (the
// trigger-time checks still apply).
func (s *Service) requireWorkflowRunnable(ctx context.Context, tenantID shared.ID, w *scanworkflow.Workflow) error {
	if s.readiness == nil || w == nil {
		return nil
	}
	m, err := s.WorkflowReadiness(ctx, tenantID, []*scanworkflow.Workflow{w})
	if err != nil {
		s.logger.Warn("workflow readiness unreadable; not refusing", "scan_workflow_id", w.ID.String(), "error", err)
		return nil
	}
	r := m[w.ID]
	if r.Runnable() {
		return nil
	}
	var parts []string
	for _, st := range r.Steps {
		if st.State == ReadinessBlocked || st.State == ReadinessCIOnly {
			parts = append(parts, fmt.Sprintf("%s: %s", st.Name, st.Reason))
		}
	}
	if len(parts) == 0 && len(r.Steps) > 0 {
		parts = append(parts, "every step is optional and no installed tool runs one")
	}
	if len(parts) == 0 {
		parts = append(parts, "it has no steps")
	}
	return shared.NewDomainError(CodeWorkflowNotRunnable,
		fmt.Sprintf("Workflow %q cannot run here: %s", w.Name, strings.Join(parts, "; ")),
		shared.ErrValidation)
}
