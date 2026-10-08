package scanrun

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type runnableSet map[string]bool

func (r runnableSet) RunnableToolNames(context.Context, string) (map[string]bool, error) {
	return r, nil
}

// checkValidator refuses the tool "gowitness" (not installed) and a config
// value "bad", the way the real validator does, and accepts the rest.
func checkValidator() *SecurityValidatorFunc {
	return &SecurityValidatorFunc{
		ValidateIdentifierFunc: func(v string, _ int, _ string) *ValidationResult {
			if v == "bad key" {
				return &ValidationResult{Errors: []ValidationError{{Field: "step_key", Code: "INVALID_IDENTIFIER_FORMAT", Message: "step_key contains invalid characters"}}}
			}
			return &ValidationResult{Valid: true}
		},
		ValidateStepConfigFunc: func(_ context.Context, _ shared.ID, tool string, _ []string, cfg map[string]any) *ValidationResult {
			r := &ValidationResult{Valid: true}
			if tool == "gowitness" {
				r.Valid = false
				r.Errors = append(r.Errors, ValidationError{Field: "tool", Code: "INVALID_TOOL", Message: `tool "gowitness" is not installed in this organization`})
			}
			if cfg["x"] == "bad" {
				r.Valid = false
				r.Errors = append(r.Errors, ValidationError{Field: "config", Code: "INVALID_STEP_SETTING", Message: "x: not a number"})
			}
			return r
		},
	}
}

func issueCodes(issues []stage.GraphIssue) map[string]stage.GraphIssue {
	out := map[string]stage.GraphIssue{}
	for _, is := range issues {
		out[is.Node+"/"+is.Code] = is
	}
	return out
}

// Every problem of every step is reported, anchored to the step and field,
// instead of stopping at the first one with an error.
func TestCheckSteps_ReportsEveryIssue(t *testing.T) {
	s := &Service{securityValidator: checkValidator(), logger: logger.NewNop(), runnableTools: runnableSet{"subfinder": true}}
	tenant := shared.NewID().String()
	rep, err := s.CheckSteps(context.Background(), ValidateGraphInput{TenantID: tenant, Steps: []AddStepInput{
		{StepKey: "subdomains", Name: "Subdomains", Capabilities: []string{"discover.subdomains"}},
		{StepKey: "shots", Name: "Screenshots", Tool: "gowitness", Capabilities: []string{"scan"}, DependsOn: []string{"subdomains"}},
		{StepKey: "dns", Name: "DNS", Capabilities: []string{"resolve.dns"}, Config: map[string]any{"x": "bad"}, DependsOn: []string{"subdomains"}},
		{StepKey: "ports", Name: "Ports", Tool: "naabu", DependsOn: []string{"dns"}, TimeoutSeconds: 5},
		{StepKey: "bad key", Name: "Bad", Capabilities: []string{"probe.http"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	errs := issueCodes(rep.Errors)
	tool, ok := errs["shots/INVALID_TOOL"]
	if !ok || tool.Field != "tool" || tool.Fix == "" || tool.Message != `step "Screenshots": tool "gowitness" is not installed in this organization` {
		t.Fatalf("unknown tool issue: %+v (all %+v)", tool, rep.Errors)
	}
	if is, ok := errs["dns/INVALID_STEP_SETTING"]; !ok || is.Field != "config" {
		t.Fatalf("setting issue missing: %+v", rep.Errors)
	}
	if _, ok := errs["ports/"+IssueInvalidStep]; !ok {
		t.Fatalf("timeout issue missing: %+v", rep.Errors)
	}
	if _, ok := errs["bad key/INVALID_IDENTIFIER_FORMAT"]; !ok {
		t.Fatalf("key issue missing: %+v", rep.Errors)
	}
	// The refused steps still take part in the graph: nothing depends on a
	// "missing" step.
	for _, is := range rep.Errors {
		if is.Code == stage.IssueUnknownNode {
			t.Fatalf("a refused step was dropped from the graph: %+v", is)
		}
	}

	warns := issueCodes(rep.Warnings)
	if _, ok := warns["dns/"+IssueNoSensorForCap]; !ok {
		t.Fatalf("no-sensor warning for resolve.dns missing: %+v", rep.Warnings)
	}
	if _, ok := warns["ports/"+IssueToolUnavailable]; !ok {
		t.Fatalf("unavailable pinned tool warning missing: %+v", rep.Warnings)
	}
	if _, ok := warns["subdomains/"+IssueNoSensorForCap]; ok {
		t.Fatal("subfinder is online: no warning expected")
	}
	if _, ok := warns["shots/"+IssueToolUnavailable]; ok {
		t.Fatal("an unknown tool is a blocking issue, not also a warning")
	}
}

// A cycle is reported as an issue; nothing panics, and unknown
// availability (no source) gives no warnings.
func TestCheckSteps_CycleAndUnknownAvailability(t *testing.T) {
	s := &Service{securityValidator: checkValidator(), logger: logger.NewNop()}
	rep, err := s.CheckSteps(context.Background(), ValidateGraphInput{TenantID: shared.NewID().String(), Steps: []AddStepInput{
		{StepKey: "a", Name: "A", Capabilities: []string{"probe.http"}, DependsOn: []string{"b"}},
		{StepKey: "b", Name: "B", Capabilities: []string{"crawl.web"}, DependsOn: []string{"a"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, is := range rep.Errors {
		if is.Code == stage.IssueCycle {
			found = true
		}
	}
	if !found {
		t.Fatalf("cycle not reported: %+v", rep.Errors)
	}
	if len(rep.Warnings) != 0 {
		for _, w := range rep.Warnings {
			if w.Code == IssueNoSensorForCap || w.Code == IssueToolUnavailable {
				t.Fatalf("availability warning without a source: %+v", w)
			}
		}
	}
	if _, err := s.CheckSteps(context.Background(), ValidateGraphInput{TenantID: "nope"}); err == nil {
		t.Fatal("a bad tenant id must be an error")
	}
}
