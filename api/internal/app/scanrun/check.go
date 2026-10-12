package scanrun

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// Checking a draft scan workflow: every problem of every step, anchored to
// the step and the field, split into blocking issues (the workflow cannot
// run: structure, unknown capability or tool, settings of the wrong type,
// tier) and warnings (it can run, but not now or not as drawn: no online
// sensor offers a tool). The editor shows each issue on its node; a save
// still refuses on the first blocking one.

// Issue codes added by the step check (the graph check has its own).
const (
	IssueInvalidStep     = "INVALID_STEP"
	IssueToolUnavailable = "TOOL_UNAVAILABLE"
	IssueNoSensorForCap  = "NO_SENSOR_FOR_CAPABILITY"
)

// RunnableTools answers which tools a job can be dispatched for now
// (enabled, on an online sensor allowed to run them). A nil map means
// unknown. Satisfied by the tool service.
type RunnableTools interface {
	RunnableToolNames(ctx context.Context, tenantID string) (map[string]bool, error)
}

// WithRunnableTools enables the "no online sensor" warnings of CheckSteps.
func WithRunnableTools(r RunnableTools) Option {
	return func(s *Service) { s.runnableTools = r }
}

// fixFor is the suggested fix for a step validation code.
func fixFor(code string) string {
	switch code {
	case "INVALID_TOOL":
		return `Pick "Any tool" for the step, or add the tool to the organization.`
	case "CAPABILITY_TOOL_MISMATCH":
		return "Choose a capability the tool runs, or a tool that runs this capability."
	case "INVALID_CAPABILITY":
		return "Choose a capability from the list."
	case "INVALID_STEP_SETTING":
		return "Clear the setting, or enter a value of the type the tool expects."
	case "DANGEROUS_CONFIG_KEY", "DANGEROUS_CONFIG_VALUE":
		return "Remove the setting."
	case "INVALID_IDENTIFIER_FORMAT", "EMPTY_IDENTIFIER", "IDENTIFIER_TOO_LONG":
		return "Use letters, digits, - and _ only (at most 100)."
	}
	return ""
}

// CheckSteps checks draft steps as a save would, and reports every problem
// instead of stopping at the first. It stores nothing. An error is returned
// only for a request that cannot be checked (a bad tenant id).
func (s *Service) CheckSteps(ctx context.Context, input ValidateGraphInput) (stage.GraphReport, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return stage.GraphReport{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	rep := stage.GraphReport{Errors: []stage.GraphIssue{}, Warnings: []stage.GraphIssue{}}
	steps := make([]*scanworkflow.Step, 0, len(input.Steps))
	blockedTool := map[string]bool{}
	for i, in := range input.Steps {
		if in.Order == 0 {
			in.Order = i + 1
		}
		st, issues := s.checkStep(ctx, tenantID, in)
		for _, is := range issues {
			if is.Field == "tool" {
				blockedTool[in.StepKey] = true
			}
		}
		rep.Errors = append(rep.Errors, issues...)
		if st != nil {
			steps = append(steps, st)
		}
	}
	graph := stage.ValidateGraph(StepsGraph(steps))
	rep.Errors = append(rep.Errors, graph.Errors...)
	rep.Warnings = append(rep.Warnings, graph.Warnings...)
	rep.Warnings = append(rep.Warnings, s.availabilityWarnings(ctx, input.TenantID, steps, blockedTool)...)
	return rep, nil
}

// checkStep reports every problem of one step and the step to place in the
// graph (built leniently when the input has problems, so the graph check
// still sees its key, tool and dependencies; nil without a key).
func (s *Service) checkStep(ctx context.Context, tenantID shared.ID, in AddStepInput) (*scanworkflow.Step, []stage.GraphIssue) {
	var issues []stage.GraphIssue
	add := func(code, field, msg string) {
		issues = append(issues, stage.GraphIssue{
			Code: code, Node: in.StepKey, Field: field,
			Message: stepMessage(in, msg), Fix: fixFor(code),
		})
	}
	if s.securityValidator != nil {
		for _, e := range s.securityValidator.ValidateIdentifier(in.StepKey, 100, "step_key").Errors {
			add(e.Code, "step_key", e.Message)
		}
	}
	caps := s.stepCapabilities(ctx, tenantID, in)
	if s.securityValidator != nil {
		for _, e := range s.securityValidator.ValidateStepConfig(ctx, tenantID, in.Tool, caps, in.Config).Errors {
			add(e.Code, e.Field, e.Message)
		}
	}
	st, err := constructStep(shared.ID{}, in, caps)
	if err == nil {
		return st, issues
	}
	add(IssueInvalidStep, "", strings.TrimPrefix(err.Error(), shared.ErrValidation.Error()+": "))
	if strings.TrimSpace(in.StepKey) == "" {
		return nil, issues
	}
	// Lenient: what the graph check needs.
	return &scanworkflow.Step{
		StepKey: in.StepKey, Name: in.Name, Tool: strings.ToLower(strings.TrimSpace(in.Tool)),
		Capabilities: caps, DependsOn: in.DependsOn,
	}, issues
}

// availabilityWarnings warn about steps no online sensor can run now: a
// pinned tool that is on no sensor, or a capability none of whose tools
// (the preferred ones when listed) is. They do not block: sensors come and
// go, and the run is refused at trigger time if it is still true then.
func (s *Service) availabilityWarnings(ctx context.Context, tenantID string, steps []*scanworkflow.Step, skip map[string]bool) []stage.GraphIssue {
	if s.runnableTools == nil {
		return nil
	}
	runnable, err := s.runnableTools.RunnableToolNames(ctx, tenantID)
	if err != nil || runnable == nil {
		return nil
	}
	var out []stage.GraphIssue
	for _, st := range steps {
		if skip[st.StepKey] {
			continue
		}
		name := st.Name
		if name == "" {
			name = st.StepKey
		}
		if st.Tool != "" {
			if !runnable[st.Tool] {
				out = append(out, stage.GraphIssue{
					Code: IssueToolUnavailable, Node: st.StepKey, Field: "tool",
					Message: fmt.Sprintf("step %q: %s is not on any online sensor", name, st.Tool),
					Fix:     fmt.Sprintf(`Pick "Any tool", or install %s on a sensor.`, st.Tool),
				})
			}
			continue
		}
		cap, ok := stage.ForStep("", st.Capabilities)
		if !ok {
			continue
		}
		candidates := st.PreferTools
		if len(candidates) == 0 {
			candidates = cap.Tools()
		}
		any := false
		for _, t := range candidates {
			if runnable[t] {
				any = true
				break
			}
		}
		if !any {
			out = append(out, stage.GraphIssue{
				Code: IssueNoSensorForCap, Node: st.StepKey, Field: "tool",
				Message: fmt.Sprintf("step %q: no online sensor offers %s (%s)", name, cap.Name, cap.Key),
				Fix:     fmt.Sprintf("Install one of %s on a sensor.", strings.Join(candidates, ", ")),
			})
		}
	}
	return out
}
