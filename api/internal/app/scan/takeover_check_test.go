package scan

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A takeover check step runs nuclei with only its takeover templates, as a
// nuclei job (no capability: sensors declare only vuln.templates@1 on
// nuclei). Tags the step sets itself cannot widen the template set; a
// vulnerability templates step keeps its own tags and its capability job.
func TestStepCommandPayload_TakeoverCheckRunsTakeoverTemplatesOnly(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{"targets": []string{"shop.example.com"}}}
	step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "takeover", Capabilities: []string{"check.takeover"},
		Config: map[string]any{"tags": []any{"cve", "exposure"}}}
	p, err := StepCommandPayload(run, step, "nuclei", "sr", nil)
	require.NoError(t, err)
	cfg, _ := p[scanworkflow.PayloadKeyConfig].(map[string]any)
	assert.Equal(t, []string{"takeover"}, cfg["tags"])
	assert.Equal(t, "nuclei", p["scanner"])
	_, named := p[PayloadKeyCapability]
	assert.False(t, named, "a takeover job must run as a nuclei job")
	assert.Equal(t, []any{"cve", "exposure"}, step.Config["tags"], "the step's config is not changed in place")

	vt := &scanworkflow.Step{ID: shared.NewID(), StepKey: "templates", Capabilities: []string{"vuln.templates"},
		Config: map[string]any{"tags": []any{"cve"}}}
	p, err = StepCommandPayload(run, vt, "nuclei", "sr", nil)
	require.NoError(t, err)
	cfg, _ = p[scanworkflow.PayloadKeyConfig].(map[string]any)
	assert.Equal(t, []string{"cve"}, cfg["tags"])
	assert.Equal(t, "vuln.templates@1", p[PayloadKeyCapability])
}

// The takeover check step is ready wherever a sensor runs nuclei, and
// waits like any step where none is online.
func TestWorkflowReadiness_TakeoverCheckOnNuclei(t *testing.T) {
	w := rwf("", rstep("dns", "", "resolve.dns"), rstep("takeover", "", "check.takeover"))
	ready := readinessService(map[string]sensordom.ToolStatus{"dnsx": sensordom.ToolReady, "nuclei": sensordom.ToolReady}, false, false, nil)
	r := readinessOf(t, ready, w)
	require.Equal(t, ReadinessReady, r.State, "%+v", r.Steps)
	assert.Equal(t, "check.takeover", r.Steps[1].Capability)

	offline := readinessService(map[string]sensordom.ToolStatus{"dnsx": sensordom.ToolReady, "nuclei": sensordom.ToolOfflineOnly}, false, false, nil)
	assert.Equal(t, ReadinessWaiting, readinessOf(t, offline, w).Steps[1].State)
}
