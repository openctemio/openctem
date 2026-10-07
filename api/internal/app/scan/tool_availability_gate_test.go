package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeAvailability answers per tool, recording the zone it was asked for.
type fakeAvailability struct {
	byTool   map[string]*sensordom.ToolAvailability
	err      error
	lastZone *shared.ID
}

func (f *fakeAvailability) ToolAvailabilityFor(_ context.Context, _ shared.ID, zoneID *shared.ID, name string) (*sensordom.ToolAvailability, error) {
	f.lastZone = zoneID
	if f.err != nil {
		return nil, f.err
	}
	return f.byTool[name], nil
}

// stubSteps serves one pipeline's steps.
type stubSteps struct {
	pipeline.StepRepository
	steps []*pipeline.Step
}

func (s stubSteps) GetByPipelineID(_ context.Context, _ shared.ID) ([]*pipeline.Step, error) {
	return s.steps, nil
}

func asToolUnavailable(t *testing.T, err error) *ToolUnavailableError {
	t.Helper()
	var tu *ToolUnavailableError
	if !errors.As(err, &tu) {
		t.Fatalf("err = %v, want a ToolUnavailableError", err)
	}
	var de *shared.DomainError
	if !errors.As(err, &de) || de.Code != CodeNoSensorForTool || !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("err = %v, want code %s wrapping ErrValidation", err, CodeNoSensorForTool)
	}
	return tu
}

func TestCheckScanToolsDispatchable(t *testing.T) {
	ctx := context.Background()
	tenant := shared.NewID()
	avail := &fakeAvailability{byTool: map[string]*sensordom.ToolAvailability{
		"nuclei":  {Name: "nuclei", Enabled: true, Status: sensordom.ToolReady, SensorsOnline: 1, SensorsTotal: 1},
		"trivy":   {Name: "trivy", Enabled: true, Status: sensordom.ToolOutdated, SensorsOnline: 1, SensorsTotal: 1},
		"checkov": {Name: "checkov", Enabled: true, Status: sensordom.ToolNoSensor},
		"semgrep": {Name: "semgrep", Enabled: true, Status: sensordom.ToolOfflineOnly, SensorsTotal: 2},
		"zap":     {Name: "zap", Enabled: true, Status: sensordom.ToolNoSensor, SensorsExcluded: 1},
		"kics":    {Name: "kics", Status: sensordom.ToolDisabled},
	}}
	tools := &stubTools{tools: map[string]*tool.Tool{
		"tenable_sc": {Name: "tenable_sc", IsActive: true, Metadata: map[string]any{"kind": "connector"}},
	}}
	svc := &Service{toolRepo: tools, toolAvailability: avail, logger: logger.NewNop()}

	single := func(name string) *scan.Scan {
		return &scan.Scan{ID: shared.NewID(), TenantID: tenant, ScanType: scan.ScanTypeSingle, ScannerName: name}
	}

	// Runnable (ready, outdated), unknown, disabled (TOOL_DISABLED owns
	// that) and connector tools pass.
	for _, name := range []string{"nuclei", "trivy", "unknown-tool", "kics", "tenable_sc"} {
		if err := svc.checkScanToolsDispatchable(ctx, single(name)); err != nil {
			t.Errorf("%s: %v, want no refusal", name, err)
		}
	}

	tu := asToolUnavailable(t, svc.checkScanToolsDispatchable(ctx, single("checkov")))
	if tu.Tool != "checkov" || tu.Status != "no_sensor" || !strings.Contains(tu.Domain.Message, "No sensor has checkov") {
		t.Errorf("checkov refusal = %+v (%s)", tu, tu.Domain.Message)
	}
	tu = asToolUnavailable(t, svc.checkScanToolsDispatchable(ctx, single("semgrep")))
	if tu.SensorsTotal != 2 || !strings.Contains(tu.Domain.Message, "No online sensor has semgrep") {
		t.Errorf("semgrep refusal = %+v (%s)", tu, tu.Domain.Message)
	}
	tu = asToolUnavailable(t, svc.checkScanToolsDispatchable(ctx, single("zap")))
	if tu.SensorsExcluded != 1 || !strings.Contains(tu.Domain.Message, "grant or local policy") {
		t.Errorf("zap refusal = %+v (%s)", tu, tu.Domain.Message)
	}

	// A zone-pinned scan is judged in its zone.
	zone := shared.NewID()
	zoned := single("checkov")
	zoned.ScanZoneID = &zone
	tu = asToolUnavailable(t, svc.checkScanToolsDispatchable(ctx, zoned))
	if avail.lastZone == nil || *avail.lastZone != zone || tu.ZoneID != zone.String() ||
		!strings.Contains(tu.Domain.Message, "in the scan's zone") {
		t.Errorf("zoned refusal = %+v (%s), asked zone %v", tu, tu.Domain.Message, avail.lastZone)
	}

	// Workflow: the first step whose tool no sensor may run refuses, named.
	pid := shared.NewID()
	svc.stepRepo = stubSteps{steps: []*pipeline.Step{
		{StepKey: "discover", Tool: "nuclei"},
		{StepKey: "iac", Tool: "checkov"},
	}}
	wf := &scan.Scan{ID: shared.NewID(), TenantID: tenant, ScanType: scan.ScanTypeWorkflow, PipelineID: &pid}
	tu = asToolUnavailable(t, svc.checkScanToolsDispatchable(ctx, wf))
	if tu.Step != "iac" || tu.Tool != "checkov" || !strings.HasPrefix(tu.Domain.Message, `Step "iac": `) {
		t.Errorf("workflow refusal = %+v (%s)", tu, tu.Domain.Message)
	}

	// Availability unreadable: the trigger goes on (sensor checks follow).
	avail.err = errors.New("store down")
	if err := svc.checkScanToolsDispatchable(ctx, single("checkov")); err != nil {
		t.Errorf("unreadable availability refused: %v", err)
	}
	// Not wired: no check.
	if err := (&Service{logger: logger.NewNop()}).checkScanToolsDispatchable(ctx, single("checkov")); err != nil {
		t.Errorf("without the source: %v", err)
	}
}
