package unit

import (
	"strings"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/sensor"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// renderShippedTemplates renders the templates the API ships in
// configs/sensor-templates (and, with a missing dir, the built-in fallbacks).
func renderShippedTemplates(t *testing.T, dir string) *app.RenderedTemplates {
	t.Helper()
	svc := app.NewSensorConfigTemplateService(dir, logger.NewNop())
	tenantID := shared.NewID()
	out, err := svc.Render(app.SensorTemplateData{
		Sensor:  &sensor.Sensor{ID: shared.NewID(), TenantID: &tenantID, Name: "edge-1", Tools: []string{"nuclei"}},
		APIKey:  "rda_test",
		BaseURL: "https://ctem.example.com",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out
}

// The YAML template told operators to edit /app/configs/agent-templates/yaml.tmpl,
// a directory the image no longer ships (RFC-023 moved it to
// configs/sensor-templates; the old one is only a fallback).
func TestSensorConfigTemplates_PointAtTheCurrentTemplateDirectory(t *testing.T) {
	out := renderShippedTemplates(t, "../../configs/sensor-templates")
	if strings.Contains(out.YAML, "agent-templates") {
		t.Errorf("yaml template still points operators at configs/agent-templates:\n%s", out.YAML)
	}
	if !strings.Contains(out.YAML, "configs/sensor-templates/yaml.tmpl") {
		t.Errorf("yaml template should name the file to edit (configs/sensor-templates/yaml.tmpl):\n%s", out.YAML)
	}
}

// RFC-023 contract: the templates render the settings the CURRENT released
// sensor binary reads (agent.yaml keys, AGENT_ID, ./agent, openctemio/agent).
// Updating the comments must not touch them.
func TestSensorConfigTemplates_StillRenderTheReleasedBinarySettings(t *testing.T) {
	for _, dir := range []string{"../../configs/sensor-templates", "/nonexistent-uses-builtins"} {
		out := renderShippedTemplates(t, dir)
		for _, want := range []string{"\nagent:\n", "  agent_id: "} {
			if !strings.Contains(out.YAML, want) {
				t.Errorf("[%s] yaml lost %q", dir, want)
			}
		}
		if !strings.Contains(out.Env, "AGENT_ID=") {
			t.Errorf("[%s] env lost AGENT_ID", dir)
		}
		if !strings.Contains(out.Docker, "openctemio/agent") {
			t.Errorf("[%s] docker lost the openctemio/agent image", dir)
		}
		if !strings.Contains(out.CLI, "./agent") {
			t.Errorf("[%s] cli lost ./agent", dir)
		}
	}
}
