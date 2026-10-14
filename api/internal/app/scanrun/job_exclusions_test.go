package scanrun

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// exclusionGate answers fixed job exclusions per tenant.
type exclusionGate struct {
	TargetGate
	byTenant map[shared.ID][]string
	err      error
	asked    []string
}

func (g *exclusionGate) JobExclusions(_ context.Context, tenant shared.ID, targets []string) ([]string, error) {
	g.asked = targets
	return g.byTenant[tenant], g.err
}

func stepCommandFixture(gate TargetGate) (*Service, *scanrun.Run, *scanworkflow.Step, *scanrun.StepRun) {
	run := &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID(), Status: scanrun.RunStatusRunning, Context: map[string]any{}}
	step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "ports", Tool: "naabu", StepOrder: 1, Condition: scanworkflow.AlwaysCondition()}
	sr := scanrun.NewStepRun(run.ID, step.ID, step.StepKey, 1, 0)
	return &Service{tools: testTools, targetGate: gate, logger: logger.NewNop()}, run, step, sr
}

func payloadExclusions(t *testing.T, raw []byte) []string {
	t.Helper()
	var p struct {
		Exclusions []string `json:"exclusions"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	return p.Exclusions
}

// A chunk's command carries the exclusions near its ranges, its own
// tenant's only.
func TestStepCommand_CarriesJobExclusions(t *testing.T) {
	gate := &exclusionGate{byTenant: map[shared.ID][]string{}}
	s, run, step, sr := stepCommandFixture(gate)
	gate.byTenant[run.TenantID] = []string{"198.51.100.7/32"}
	gate.byTenant[shared.NewID()] = []string{"203.0.113.0/24"} // another tenant
	chunk := &scanapp.StepTargets{Targets: []string{"198.51.100.0/30", "198.51.100.8/29"}}
	cmd, err := s.stepCommand(context.Background(), testCat, run, step, sr, chunk)
	if err != nil {
		t.Fatal(err)
	}
	if got := payloadExclusions(t, cmd.Payload); !reflect.DeepEqual(got, []string{"198.51.100.7/32"}) {
		t.Fatalf("exclusions = %v", got)
	}
	if !reflect.DeepEqual(gate.asked, chunk.Targets) {
		t.Fatalf("asked for %v, want the chunk's targets", gate.asked)
	}

	// No exclusion near the chunk: no key at all.
	gate.byTenant[run.TenantID] = nil
	cmd, err = s.stepCommand(context.Background(), testCat, run, step, sr, chunk)
	if err != nil {
		t.Fatal(err)
	}
	if got := payloadExclusions(t, cmd.Payload); got != nil {
		t.Fatalf("exclusions = %v, want none", got)
	}
}

// A failed exclusion lookup creates no command (fail closed).
func TestStepCommand_ExclusionLookupFailsClosed(t *testing.T) {
	s, run, step, sr := stepCommandFixture(&exclusionGate{err: errors.New("db down")})
	if cmd, err := s.stepCommand(context.Background(), testCat, run, step, sr, &scanapp.StepTargets{Targets: []string{"198.51.100.0/24"}}); err == nil {
		t.Fatalf("a command was built without its exclusions: %s", cmd.Payload)
	}
}
