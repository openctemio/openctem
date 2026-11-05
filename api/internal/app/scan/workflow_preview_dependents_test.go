package scan

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
)

func TestMarkDependentsSkipped(t *testing.T) {
	tpl := &scanworkflow.Workflow{Steps: []*scanworkflow.Step{
		{StepKey: "shots"},
		{StepKey: "report", DependsOn: []string{"shots"}},
		{StepKey: "notify", DependsOn: []string{"report"}},
		{StepKey: "other"},
		{StepKey: "depth", DependsOn: []string{"other"}},
	}}
	nodes := func() []WorkflowPreviewNode {
		return []WorkflowPreviewNode{
			{StepKey: "shots", Skipped: &PreviewError{Code: CodeToolNotInstalled}},
			{StepKey: "report"},
			{StepKey: "notify"},
			{StepKey: "other", Skipped: &PreviewError{Code: CodeDepthSkipped}},
			{StepKey: "depth"},
		}
	}

	n := nodes()
	markDependentsSkipped(tpl, n)
	for _, i := range []int{1, 2} {
		if n[i].Skipped == nil || n[i].Skipped.Code != scanrun.FailureDependencySkipped {
			t.Fatalf("step %s should be DEPENDENCY_SKIPPED, got %+v", n[i].StepKey, n[i].Skipped)
		}
	}
	if n[4].Skipped != nil {
		t.Fatalf("a depth skip must not skip dependents, got %+v", n[4].Skipped)
	}

	// A blocking dependent keeps its own verdict.
	n = nodes()
	n[1].Blocking = &PreviewError{Code: "X"}
	markDependentsSkipped(tpl, n)
	if n[1].Skipped != nil {
		t.Fatal("a blocking node keeps its verdict")
	}

	// A workflow that continues on a failed dependency skips nothing extra.
	tpl.Settings.ContinueOnFailedDependency = true
	n = nodes()
	markDependentsSkipped(tpl, n)
	if n[1].Skipped != nil {
		t.Fatal("continue_on_failed_dependency runs dependents")
	}
}
