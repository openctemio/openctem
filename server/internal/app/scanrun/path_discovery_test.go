package scanrun

import (
	"context"
	"errors"
	"strings"
	"testing"

	scanapp "github.com/openctemio/openctem/server/internal/app/scan"
	"github.com/openctemio/openctem/server/pkg/domain/scanrun"
	"github.com/openctemio/openctem/server/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

type fakePathGate struct {
	on      bool
	fit     int
	refused map[string]string
	err     error
	asked   []string
}

func (g *fakePathGate) PathDiscoveryEnabled(context.Context, shared.ID) (bool, error) {
	return g.on, g.err
}
func (g *fakePathGate) PathDiscoveryFit(context.Context, shared.ID) (int, error) { return g.fit, g.err }
func (g *fakePathGate) PathDiscoveryRefusals(_ context.Context, _ shared.ID, targets []string) (map[string]string, error) {
	g.asked = append(g.asked, targets...)
	return g.refused, g.err
}

func pathStep() *scanworkflow.Step {
	return &scanworkflow.Step{StepKey: "paths", Capabilities: []string{"enumerate.web_paths"}}
}

// SECURITY: a path discovery step keeps only the origins the shared gate lets
// through, at most as many as the daily budget holds; any other step keeps
// all its targets and never asks the gate.
func TestAdmitPathDiscovery_KeepsWhatTheGateAllows(t *testing.T) {
	gate := &fakePathGate{on: true, fit: 2, refused: map[string]string{
		"https://recent.example.com": "path_ran_recently", "https://noscope.example.com": "no_origin_scope_entry"}}
	s := &Service{logger: logger.NewNop(), pathGate: gate}
	run := &scanrun.Run{TenantID: shared.NewID()}
	in := &scanapp.StepTargets{Targets: []string{"https://recent.example.com", "https://a.example.com",
		"https://noscope.example.com", "https://b.example.com", "https://c.example.com"}, Refused: 1, Reason: "x"}
	got, err := s.admitPathDiscovery(context.Background(), run, pathStep(), in, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got.Targets, ",") != "https://a.example.com,https://b.example.com" || got.Refused != 1 {
		t.Fatalf("kept %+v: the refused origins, or the ones past the budget, went through", got)
	}

	other := &scanworkflow.Step{StepKey: "http", Capabilities: []string{"probe.http"}}
	gate.asked = nil
	got, err = s.admitPathDiscovery(context.Background(), run, other, in, nil)
	if err != nil || got != in || len(gate.asked) != 0 {
		t.Fatalf("another step: %v %v asked %v", got, err, gate.asked)
	}
}

// Nothing left is a step without inputs (settled, successors run), never a
// step that dispatches; an unwired gate or a gate error never lets a target
// through.
func TestAdmitPathDiscovery_NothingLeft(t *testing.T) {
	run := &scanrun.Run{TenantID: shared.NewID()}
	in := &scanapp.StepTargets{Targets: []string{"https://recent.example.com"}}

	gate := &fakePathGate{on: true, fit: 5, refused: map[string]string{"https://recent.example.com": "path_ran_recently"}}
	s := &Service{logger: logger.NewNop(), pathGate: gate}
	_, err := s.admitPathDiscovery(context.Background(), run, pathStep(), in, nil)
	var none *noInputsError
	if !errors.As(err, &none) || !strings.Contains(none.summary, "1 path_ran_recently") {
		t.Fatalf("err %v", err)
	}

	gate.refused = nil
	gate.fit = 0
	if _, err := s.admitPathDiscovery(context.Background(), run, pathStep(), in, nil); !errors.As(err, &none) || !strings.Contains(none.summary, "budget") {
		t.Fatalf("spent budget: %v", err)
	}

	if _, err := (&Service{logger: logger.NewNop()}).admitPathDiscovery(context.Background(), run, pathStep(), in, nil); !errors.As(err, &none) {
		t.Fatalf("unwired: %v", err)
	}
	gate.err = errors.New("db down")
	if got, err := s.admitPathDiscovery(context.Background(), run, pathStep(), in, nil); err == nil || got != nil {
		t.Fatalf("a gate error let targets through: %v %v", got, err)
	}
}
