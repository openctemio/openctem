package unit

import (
	"strings"
	"testing"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// renderShippedTemplates renders the templates the API ships in
// configs/sensor-templates (and, with a missing dir, the built-in fallbacks).
func renderShippedTemplates(t *testing.T, dir string) *sensorapp.RenderedTemplates {
	t.Helper()
	svc := sensorapp.NewSensorConfigTemplateService(dir, logger.NewNop())
	tenantID := shared.NewID()
	out, err := svc.Render(sensorapp.SensorTemplateData{
		Sensor: &sensor.Sensor{
			ID: shared.NewID(), TenantID: &tenantID, Name: "edge-1", Tools: []string{"nuclei"},
			Type: sensor.SensorTypeWorker, ExecutionMode: sensor.ExecutionModeDaemon,
		},
		APIKey:  "rda_test0123",
		BaseURL: "https://ctem.example.com",
		Image:   "ghcr.io/openctemio/sensor:v0.4.2",
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

// The templates render the settings the released sensor (v0.4.x, the image
// they pin) reads: the sensor: / sensor_id config keys, SENSOR_* variables,
// the openctemio-sensor binary and the ghcr.io/openctemio/sensor image. The
// pre-rename names (agent:, AGENT_ID, ./agent, openctemio/agent) are gone:
// openctemio/agent was never published, and the old docker command ended
// early at a commented-out line inside its backslash continuation.
func TestSensorConfigTemplates_RenderTheReleasedSensorSettings(t *testing.T) {
	for _, dir := range []string{"../../configs/sensor-templates", "/nonexistent-uses-builtins"} {
		out := renderShippedTemplates(t, dir)
		for _, want := range []string{"\nsensor:\n", "  sensor_id: "} {
			if !strings.Contains(out.YAML, want) {
				t.Errorf("[%s] yaml lacks %q", dir, want)
			}
		}
		if !strings.Contains(out.Env, "SENSOR_TOOLS=") {
			t.Errorf("[%s] env lacks SENSOR_TOOLS", dir)
		}
		if !strings.Contains(out.Docker, "ghcr.io/openctemio/sensor:v0.4.2") {
			t.Errorf("[%s] docker does not run the pinned sensor image", dir)
		}
		if !strings.Contains(out.CLI, "./openctemio-sensor") {
			t.Errorf("[%s] cli lacks ./openctemio-sensor", dir)
		}
		for name, s := range map[string]string{"yaml": out.YAML, "env": out.Env, "docker": out.Docker, "cli": out.CLI} {
			for _, old := range []string{"AGENT_ID", "\nagent:", "openctemio/agent", "./agent "} {
				if strings.Contains(s, old) {
					t.Errorf("[%s] %s still renders the pre-rename %q", dir, name, old)
				}
			}
		}
	}
}
