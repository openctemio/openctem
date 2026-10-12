package scanworkflow

import (
	"encoding/json"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func specFixture() *Workflow {
	toolID := shared.NewID()
	return &Workflow{
		ID:       shared.NewID(),
		TenantID: shared.NewID(),
		Name:     "recon",
		Settings: Settings{MaxParallelSteps: 2, TimeoutSeconds: 600, SensorPreference: SensorPreferenceAuto},
		Steps: []*Step{
			{ID: shared.NewID(), StepKey: "a", Name: "Subdomains", StepOrder: 1, Tool: "subfinder", ToolID: &toolID,
				Capabilities: []string{"subdomain"}, Config: map[string]any{"rate": float64(10)},
				Condition: AlwaysCondition(), UIPosition: UIPosition{X: 1, Y: 2}},
			{ID: shared.NewID(), StepKey: "b", Name: "Ports", StepOrder: 2, PreferTools: []string{"naabu"},
				DependsOn: []string{"a"}, TimeoutSeconds: 120, MaxRetries: 1, RetryDelaySeconds: 30,
				Condition: Condition{Type: ConditionTypeAlways}},
		},
	}
}

func mustDigest(t *testing.T, w *Workflow) string {
	t.Helper()
	d, err := SpecOf(w).Digest()
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// Moving a node in the builder is not a new version; changing what a step
// does, the settings or the step set is.
func TestSpecDigest(t *testing.T) {
	w := specFixture()
	base := mustDigest(t, w)
	if len(base) != 64 || mustDigest(t, w) != base {
		t.Fatalf("digest is not a stable sha256: %q", base)
	}

	w.Steps[0].UIPosition = UIPosition{X: 500, Y: 500}
	if mustDigest(t, w) != base {
		t.Error("moving a node changed the digest")
	}

	for name, change := range map[string]func(*Workflow){
		"step config":  func(w *Workflow) { w.Steps[0].Config["rate"] = float64(50) },
		"step tool":    func(w *Workflow) { w.Steps[1].Tool = "nmap" },
		"dependencies": func(w *Workflow) { w.Steps[1].DependsOn = nil },
		"settings":     func(w *Workflow) { w.Settings.TimeoutSeconds = 60 },
		"step removed": func(w *Workflow) { w.Steps = w.Steps[:1] },
		"step id":      func(w *Workflow) { w.Steps[0].ID = shared.NewID() },
	} {
		w := specFixture()
		before := mustDigest(t, w)
		change(w)
		if mustDigest(t, w) == before {
			t.Errorf("%s: digest unchanged", name)
		}
	}
}

// A saved version (JSON in the database) gives back the steps the run was
// created with: same ids, keys, tools, config, dependencies and retries.
func TestSpecWorkflow_RoundTrip(t *testing.T) {
	live := specFixture()
	raw, err := json.Marshal(SpecOf(live))
	if err != nil {
		t.Fatal(err)
	}
	var spec Spec
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}

	edited := specFixture()
	edited.ID, edited.TenantID, edited.Name = live.ID, live.TenantID, "renamed"
	edited.Settings = DefaultSettings()
	edited.Steps = nil

	got := spec.Workflow(edited)
	if got.ID != live.ID || got.Name != "renamed" {
		t.Errorf("identity not taken from the live workflow: %s %q", got.ID, got.Name)
	}
	if got.Settings != live.Settings {
		t.Errorf("settings = %+v, want the version's %+v", got.Settings, live.Settings)
	}
	if len(got.Steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(got.Steps))
	}
	a, b := got.Steps[0], got.Steps[1]
	if a.ID != live.Steps[0].ID || a.StepKey != "a" || a.Tool != "subfinder" || a.ToolID == nil ||
		*a.ToolID != *live.Steps[0].ToolID || a.Config["rate"] != float64(10) || a.UIPosition.X != 1 ||
		a.ScanWorkflowID != live.ID {
		t.Errorf("step a = %+v", a)
	}
	if b.ID != live.Steps[1].ID || len(b.DependsOn) != 1 || b.PreferTools[0] != "naabu" ||
		b.TimeoutSeconds != 120 || b.MaxRetries != 1 || b.RetryDelaySeconds != 30 || b.ToolID != nil {
		t.Errorf("step b = %+v", b)
	}
	if edited.Steps != nil {
		t.Error("the live workflow was modified")
	}
}
