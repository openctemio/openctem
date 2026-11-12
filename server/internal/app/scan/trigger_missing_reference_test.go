package scan

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/scan"
	"github.com/openctemio/openctem/server/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tool"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// A capability step whose fallback lookup answers not-found (no tool has
// the capability: fingerprint.tech, detect.services) is NO_MATCHING_TOOL,
// so an optional step is skipped with the reason. Before, the lookup's
// not-found escaped the planner and the trigger answered "Scan not found".
func TestResolveStepTool_NotFoundLookupIsNoMatchingTool(t *testing.T) {
	tools := &fakeToolLookup{platform: map[string]*tool.Tool{}, capsErr: fmt.Errorf("find: %w", shared.ErrNotFound)}
	step := &scanworkflow.Step{StepKey: "screenshots", Capabilities: []string{"fingerprint.tech"}, RunPolicy: scanworkflow.RunPolicy{Optional: true}}
	_, err := ResolveStepTool(context.Background(), tools, shared.NewID(), step)
	if domainCode(err) != codeNoMatchingTool {
		t.Fatalf("got %v, want %s", err, codeNoMatchingTool)
	}
	if skip, ok := UnsupportedStepSkip(step, err); !ok || skip.Code != codeNoMatchingTool {
		t.Fatal("an optional step without a tool must be skipped")
	}
	// A required step without a tool is skipped the same way (a run goes as
	// far as the tools support).
	required := *step
	required.RunPolicy.Optional = false
	if _, err := ResolveStepTool(context.Background(), tools, shared.NewID(), &required); domainCode(err) != codeNoMatchingTool {
		t.Fatalf("a required step: %v, want NO_MATCHING_TOOL", err)
	} else if _, ok := UnsupportedStepSkip(&required, err); !ok {
		t.Fatal("a required step without a tool must be skipped")
	}
}

// A not-found from a trigger gate below the loaded scan is never the bare
// sentinel the handler answers "Scan not found" with: it becomes
// SCAN_DEPENDENCY_MISSING (recorded as a blocked run), and the workflow's
// own codes are kept.
func TestExplainMissingReference(t *testing.T) {
	s := &Service{logger: logger.NewNop()}
	sc := &scan.Scan{ID: shared.NewID()}

	err := s.explainMissingReference(sc, fmt.Errorf("step x: find tool by capabilities: %w", shared.ErrNotFound))
	if domainCode(err) != CodeScanDependencyMissing || !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("bare not-found: %v", err)
	}
	if code, _, ok := refusal(err); !ok || code != CodeScanDependencyMissing {
		t.Fatalf("not recorded as a blocked run: %q %v", code, ok)
	}

	started := s.explainMissingReference(sc, afterRunCreated(shared.ErrNotFound))
	var rs *runStartError
	if !errors.As(started, &rs) || domainCode(started) != CodeScanDependencyMissing {
		t.Fatalf("after the run exists the error must stay a run-start error: %v", started)
	}

	for _, keep := range []error{errPipelineNotFound, scanworkflow.ErrScanWorkflowNotFound} {
		if got := s.explainMissingReference(sc, keep); got != keep {
			t.Errorf("%v rewritten to %v", keep, got)
		}
	}
	other := shared.NewDomainError("NO_TARGETS", "x", shared.ErrValidation)
	if got := s.explainMissingReference(sc, other); got != other {
		t.Errorf("a non-not-found error was rewritten: %v", got)
	}
}
