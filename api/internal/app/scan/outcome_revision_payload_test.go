package scan

import (
	"testing"

	"github.com/openctemio/ctis/outcome"

	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Both scan command builders name the outcome revision the platform reads,
// so a sensor reports a host an edge protection blocked as edge_blocked (an
// observation of the target) and not as tool_error, a platform-side failure
// that raised the coverage platform-failure alert (prod 2026-11-01). A value
// a scan's config sets does not override it.
func TestCommandPayloadsNameTheOutcomeRevision(t *testing.T) {
	if outcome.Revision < 2 {
		t.Fatalf("outcome revision %d does not carry the edge classes", outcome.Revision)
	}
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{"targets": []string{"a.example.com"}}}
	step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "vulns", Tool: "nuclei", Capabilities: []string{"vulnerability"}}
	p, err := StepCommandPayload(run, step, "nuclei", "sr", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p[PayloadKeyOutcomeRevision] != outcome.Revision {
		t.Fatalf("workflow step payload outcome_revision %v", p[PayloadKeyOutcomeRevision])
	}
	sc := &scan.Scan{ID: shared.NewID(), ScannerName: "nuclei"}
	cfg := map[string]any{PayloadKeyOutcomeRevision: 1}
	if got := (&Service{}).scannerPayload(sc, run, nil, cfg, nil, []string{"a.example.com"}, nil)[PayloadKeyOutcomeRevision]; got != outcome.Revision {
		t.Fatalf("scan payload outcome_revision %v", got)
	}
}
