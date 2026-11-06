package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/scan"
	"github.com/openctemio/openctem/server/pkg/domain/scanrun"
	"github.com/openctemio/openctem/server/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tool"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// tenantTools is a tool registry in which each tool belongs to one tenant:
// GetByName answers only the owner (as the tenant-scoped repository does).
type tenantTools struct {
	stubTools
	owner map[string]shared.ID
}

func (s *tenantTools) GetByName(ctx context.Context, tenantID shared.ID, name string) (*tool.Tool, error) {
	if o, ok := s.owner[name]; ok && o != tenantID {
		return nil, shared.ErrNotFound
	}
	return s.stubTools.GetByName(ctx, tenantID, name)
}

func workflowScanOf(tenant shared.ID) *scan.Scan {
	pid := shared.NewID()
	return &scan.Scan{ID: shared.NewID(), TenantID: tenant, ScanType: scan.ScanTypeWorkflow, ScanWorkflowID: &pid}
}

// Another organization's tool never makes a step runnable: for the
// organization without it the step is skipped (TOOL_NOT_INSTALLED) and,
// with nothing else to run, the trigger is NO_RUNNABLE_STEPS; the owner runs
// it.
func TestWorkflowStepSkips_OtherTenantsToolNeverCounts(t *testing.T) {
	ctx := context.Background()
	owner, other := shared.NewID(), shared.NewID()
	tools := &tenantTools{
		stubTools: stubTools{tools: map[string]*tool.Tool{"custom-scan": {Name: "custom-scan", IsActive: true}}},
		owner:     map[string]shared.ID{"custom-scan": owner},
	}
	svc := &Service{toolRepo: tools, logger: logger.NewNop()}
	steps := []*scanworkflow.Step{{StepKey: "custom", Name: "Custom", Tool: "custom-scan"}}
	wf := &scanworkflow.Workflow{Name: "w"}

	_, err := svc.workflowStepSkips(ctx, workflowScanOf(other), wf, steps)
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != CodeNoRunnableSteps || !strings.Contains(de.Message, "custom-scan") {
		t.Fatalf("other tenant: %v, want NO_RUNNABLE_STEPS naming the tool", err)
	}
	skips, err := svc.workflowStepSkips(ctx, workflowScanOf(owner), wf, steps)
	if err != nil || len(skips) != 0 {
		t.Fatalf("owner: skips %v, err %v", skips, err)
	}
}

// Each missing kind maps to its skip code; a step that is not valid (a
// collector as a step tool) still refuses the trigger with its own code.
func TestWorkflowStepSkips_Codes(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	tools := &stubTools{tools: map[string]*tool.Tool{
		"subfinder": {Name: "subfinder", IsActive: true},
		"off":       {Name: "off", IsActive: false},
		"collector": {Name: "collector", IsActive: true, Metadata: map[string]any{"kind": "collector"}},
	}}
	svc := &Service{toolRepo: tools, logger: logger.NewNop()}
	steps := []*scanworkflow.Step{
		{StepKey: "find", Tool: "subfinder"},
		{StepKey: "gone", Tool: "missing"},
		{StepKey: "off", Tool: "off"},
		{StepKey: "dep", Tool: "subfinder", DependsOn: []string{"gone"}},
		{StepKey: "dep2", Tool: "subfinder", DependsOn: []string{"dep"}},
	}
	skips, err := svc.workflowStepSkips(ctx, workflowScanOf(tenant), &scanworkflow.Workflow{Name: "w"}, steps)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"gone": scanrun.FailureToolNotInstalled,
		"off":  scanrun.FailureToolDisabled,
		"dep":  scanrun.FailureDependencySkipped,
		"dep2": scanrun.FailureDependencySkipped,
	}
	if len(skips) != len(want) {
		t.Fatalf("skips = %+v", skips)
	}
	for k, code := range want {
		if skips[k].Code != code || skips[k].Reason == "" {
			t.Errorf("%s: %+v, want %s", k, skips[k], code)
		}
	}

	// Continue-on-failure runs the dependents on the scan's targets.
	skips, _ = svc.workflowStepSkips(ctx, workflowScanOf(tenant),
		&scanworkflow.Workflow{Name: "w", Settings: scanworkflow.Settings{ContinueOnFailedDependency: true}}, steps)
	if _, ok := skips["dep"]; ok {
		t.Errorf("continue on failure skipped a dependent: %+v", skips)
	}

	bad := append(steps, &scanworkflow.Step{StepKey: "col", Tool: "collector"})
	if _, err := svc.workflowStepSkips(ctx, workflowScanOf(tenant), &scanworkflow.Workflow{Name: "w"}, bad); err == nil {
		t.Fatal("a collector step must still refuse the trigger")
	}
}

// The refusal names at most maxNamedMissing steps and never a dependent.
func TestNoRunnableStepsError_NamesMissingSteps(t *testing.T) {
	var steps []*scanworkflow.Step
	skips := map[string]StepSkip{}
	for _, k := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		steps = append(steps, &scanworkflow.Step{StepKey: k})
		skips[k] = StepSkip{Code: scanrun.FailureNoMatchingTool, Reason: "skipped: no tool " + k}
	}
	steps = append(steps, &scanworkflow.Step{StepKey: "z"})
	skips["z"] = StepSkip{Code: scanrun.FailureDependencySkipped, Reason: "dep", Dependency: true}
	err := NoRunnableStepsError("Deep recon", steps, skips)
	msg := err.Error()
	if !strings.Contains(msg, `"Deep recon"`) || !strings.Contains(msg, "a (no tool a)") || !strings.Contains(msg, "2 more") ||
		strings.Contains(msg, "no tool f") || strings.Contains(msg, "dep") {
		t.Fatalf("message %q", msg)
	}
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatal("not a validation refusal")
	}
}
