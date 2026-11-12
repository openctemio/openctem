package scan

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Web page monitoring dispatches monitor.web_content through coverage: the
// capability resolves to httpx, and an excluded URL, a URL outside every
// scope entry and a URL whose scope entry allows passive work only are
// refused one by one (the fetch is active traffic); nothing is started.
func TestStartCoverage_WebContentRefusedOffScope(t *testing.T) {
	const (
		excluded    = "https://excluded.example.com/app.js"
		notOurs     = "https://not-ours.example.org/"
		passiveOnly = "https://passive-only.example.net/"
	)
	acts := &stubActScope{targets: map[string]string{notOurs: actscope.ReasonOutOfDataScope}}
	gate := &stubGate{ceiling: map[string]scopedom.Tier{passiveOnly: scopedom.TierPassive}}
	svc := &Service{
		scopeExclusions: &stubExclusions{values: map[string]bool{excluded: true}},
		actScope:        acts, attributionGate: gate, logger: logger.NewNop(),
	}
	res, err := svc.StartCoverage(context.Background(), CoverageInput{
		TenantID: shared.NewID(), Capability: string(stage.MonitorWebContent),
		Targets: []string{excluded, notOurs, passiveOnly},
	})
	require.NoError(t, err)
	assert.Equal(t, "httpx", res.Tool)
	assert.Nil(t, res.RunID, "nothing is started")
	assert.Empty(t, res.Kept)
	refused := map[string]bool{}
	for _, r := range res.Refused {
		refused[r.Target] = true
	}
	for _, target := range []string{excluded, notOurs, passiveOnly} {
		assert.True(t, refused[target], "%s must be refused, got %+v", target, res.Refused)
	}
}

// A step that names the capability sends httpx a job for it; a step that
// pins httpx alone is still the HTTP probe.
func TestStepCommandPayload_WebContentNamesTheCapability(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID(), Context: map[string]any{
		scanrun.RunContextKeyDepth: string(scanworkflow.DepthStandard), "targets": []string{"https://example.com/"},
	}}
	step := &scanworkflow.Step{ID: shared.NewID(), StepKey: "watch", Tool: "httpx", Capabilities: []string{"monitor.web_content"}}
	p, err := StepCommandPayload(run, step, "httpx", "sr", nil)
	require.NoError(t, err)
	assert.Equal(t, "monitor.web_content@1", p[PayloadKeyCapability])

	probe := &scanworkflow.Step{ID: shared.NewID(), StepKey: "probe", Tool: "httpx"}
	p, err = StepCommandPayload(run, probe, "httpx", "sr", nil)
	require.NoError(t, err)
	assert.Equal(t, "probe.http@1", p[PayloadKeyCapability])
}
