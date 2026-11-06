package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	covdom "github.com/openctemio/openctem/server/pkg/domain/coverage"
	"github.com/openctemio/openctem/server/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// stubShotSettings answers the screenshot switch per tenant.
type stubShotSettings struct {
	on  map[shared.ID]bool
	err error
}

func (s stubShotSettings) GetEASMSettings(_ context.Context, id string) (*tenant.EASMSettings, error) {
	if s.err != nil {
		return nil, s.err
	}
	for t, v := range s.on {
		if t.String() == id {
			return &tenant.EASMSettings{WebScreenshotsEnabled: v}, nil
		}
	}
	return &tenant.EASMSettings{}, nil
}

// A capability that keeps screenshots is not planned (no run, so the sensor
// never takes the picture) until the organization switches them on; an
// unreadable switch or no reader is off; one organization's switch never
// opens another's.
func TestCoverageReadiness_ScreenshotsSwitch(t *testing.T) {
	ctx := context.Background()
	a, b := shared.NewID(), shared.NewID()
	tool := toolOf(t, "capture.screenshot")
	newSvc := func(cs CoverageSettings) *Service {
		sel := &tenantSelector{asked: map[shared.ID]bool{}, online: map[shared.ID]map[string]bool{
			a: {tool: true, "httpx": true}, b: {tool: true, "httpx": true}}}
		return &Service{sensorSelector: sel, coverageSettings: cs, logger: logger.NewNop()}
	}
	caps := []string{"capture.screenshot", "probe.http"}

	s := newSvc(stubShotSettings{on: map[shared.ID]bool{a: true}})
	ga, gb := s.CoverageReadiness(ctx, a, caps), s.CoverageReadiness(ctx, b, caps)
	assert.Empty(t, ga["capture.screenshot"], "tenant A switched screenshots on")
	assert.Equal(t, covdom.ReadyFeatureOff, gb["capture.screenshot"], "tenant B has them off")
	assert.Empty(t, gb["probe.http"], "other capabilities are not held by the switch")

	// Off is the default.
	assert.Equal(t, covdom.ReadyFeatureOff, newSvc(stubShotSettings{}).CoverageReadiness(ctx, a, caps)["capture.screenshot"])
	// Fail closed: unreadable or no reader.
	assert.Equal(t, covdom.ReadyFeatureOff,
		newSvc(stubShotSettings{err: errors.New("db down")}).CoverageReadiness(ctx, a, caps)["capture.screenshot"])
	assert.Equal(t, covdom.ReadyFeatureOff, newSvc(nil).CoverageReadiness(ctx, a, caps)["capture.screenshot"])
	assert.Equal(t, "screenshots are off for this organization", covdom.ReadinessText(covdom.ReadyFeatureOff))
}

// A workflow step that takes screenshots is held while the organization has
// them off, whichever tenant asks; other steps are never held by the switch.
func TestStepSkipReason_Screenshots(t *testing.T) {
	ctx := context.Background()
	a, b := shared.NewID(), shared.NewID()
	s := &Service{coverageSettings: stubShotSettings{on: map[shared.ID]bool{a: true}}, logger: logger.NewNop()}
	shots := &scanworkflow.Step{StepKey: "s", Capabilities: []string{"capture.screenshot"}}
	pinned := &scanworkflow.Step{StepKey: "p", Tool: "webshot"}
	other := &scanworkflow.Step{StepKey: "o", Capabilities: []string{"probe.http"}}
	assert.Empty(t, s.StepSkipReason(ctx, a, shots))
	assert.Empty(t, s.StepSkipReason(ctx, a, pinned))
	assert.Contains(t, s.StepSkipReason(ctx, b, shots), "screenshots are off for this organization")
	assert.NotEmpty(t, s.StepSkipReason(ctx, b, pinned))
	assert.Empty(t, s.StepSkipReason(ctx, b, other))
	assert.Empty(t, s.StepSkipReason(ctx, b, nil))
	assert.NotEmpty(t, (&Service{logger: logger.NewNop()}).StepSkipReason(ctx, a, shots), "no reader: off")
}
