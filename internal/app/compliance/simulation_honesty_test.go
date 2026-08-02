package compliance

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/simulation"
	"github.com/openctemio/api/pkg/logger"
)

// RFC-012 Phase 0: the synthetic BAS path must never present its outcome as a
// verified/live control validation. Every run is flagged simulated+unverified,
// and the detection text must not claim a real "Validated against X".
func newSim(t *testing.T, typ simulation.SimulationType, cfg map[string]any) *simulation.Simulation {
	t.Helper()
	sim, err := simulation.NewSimulation(shared.NewID(), "test-sim", typ)
	if err != nil {
		t.Fatalf("NewSimulation: %v", err)
	}
	if cfg != nil {
		if err := sim.SetConfig(cfg, nil, nil); err != nil {
			t.Fatalf("SetConfig: %v", err)
		}
	}
	return sim
}

func TestExecuteSimulation_AlwaysFlaggedUnverified(t *testing.T) {
	svc := &SimulationService{logger: logger.NewNop()}

	cases := []struct {
		name string
		typ  simulation.SimulationType
		cfg  map[string]any
	}{
		{"atomic_with_source", simulation.SimulationTypeAtomic, map[string]any{"detection_source": "Splunk"}},
		{"atomic_no_source", simulation.SimulationTypeAtomic, nil},
		{"campaign", simulation.SimulationTypeCampaign, nil},
		{"control_test", simulation.SimulationTypeControlTest, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, detection, _, output := svc.executeSimulationTechnique(newSim(t, tc.typ, tc.cfg))

			if output["verified"] != false {
				t.Errorf("output.verified = %v, want false (no live execution)", output["verified"])
			}
			if output["execution_mode"] != "simulated" {
				t.Errorf("output.execution_mode = %v, want simulated", output["execution_mode"])
			}
			if output["disclaimer"] == nil || output["disclaimer"] == "" {
				t.Error("output must carry a disclaimer that no live execution occurred")
			}
			// The old code claimed "Validated against <source>" — a false
			// assurance of a real control test. It must be gone.
			if detection == "Validated against Splunk" {
				t.Errorf("detection still claims real validation: %q", detection)
			}
		})
	}
}

// A configured detection source is an EXPECTATION, not proof — detection_validated
// must be false because nothing was actually exercised.
func TestExecuteSimulation_ConfiguredSourceIsNotValidated(t *testing.T) {
	svc := &SimulationService{logger: logger.NewNop()}
	_, _, _, output := svc.executeSimulationTechnique(
		newSim(t, simulation.SimulationTypeAtomic, map[string]any{"detection_source": "Splunk"}),
	)
	if output["detection_validated"] != false {
		t.Errorf("detection_validated = %v, want false (config presence is not validation)", output["detection_validated"])
	}
}
