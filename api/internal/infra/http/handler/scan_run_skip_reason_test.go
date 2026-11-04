package handler

import (
	"testing"

	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A step nothing here runs is skipped with a code and a reason: the run read
// and the run map both expose them, and a step that ran carries no reason.
func TestStepRun_SkipReasonExposed(t *testing.T) {
	sr := scanrundom.NewStepRun(shared.NewID(), shared.NewID(), "iac", 1, 0)
	sr.SkipWithCode("skipped: tool checkov is not installed in this organization", scanrundom.FailureToolNotInstalled)

	resp := toStepRunResponse(sr)
	if resp.Status != "skipped" || resp.ErrorCode != "TOOL_NOT_INSTALLED" || resp.ErrorClass != "config" ||
		resp.SkipReason != sr.SkipReason {
		t.Fatalf("step run response = %+v", resp)
	}

	n := &RunMapNode{StepKey: "iac"}
	fillNodeFromStepRun(n, sr, false)
	if n.State != mapStateSkipped || n.Reason != "TOOL_NOT_INSTALLED" || n.SkipReason != sr.SkipReason {
		t.Fatalf("map node = %+v", n)
	}

	ran := scanrundom.NewStepRun(shared.NewID(), shared.NewID(), "find", 1, 0)
	ran.Complete(1, nil)
	ran.SkipReason = "stale"
	n = &RunMapNode{StepKey: "find"}
	fillNodeFromStepRun(n, ran, false)
	if n.SkipReason != "" {
		t.Fatalf("a step that ran carries a skip reason: %q", n.SkipReason)
	}
}
