package scan

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tool"
)

// fakeTenantTools serves per-tenant tool configs.
type fakeTenantTools struct {
	cfg map[string]*tool.TenantToolConfig // key: tenant|tool
	err error
}

func (f *fakeTenantTools) GetByTenantAndTool(_ context.Context, tenantID, toolID shared.ID) (*tool.TenantToolConfig, error) {
	if f.err != nil {
		return nil, f.err
	}
	if c, ok := f.cfg[tenantID.String()+"|"+toolID.String()]; ok {
		return c, nil
	}
	return nil, shared.ErrNotFound
}

// An organization's "disabled" switch on a tool (tenant_tool_configs.is_enabled
// = false) stops the tool at trigger time and at every step dispatch
// (settings decision B10). Before, the switch was stored but ignored, so a
// disabled tool was still sent to sensors.
func TestTenantDisabledToolIsNotDispatched(t *testing.T) {
	tenantA, tenantB := shared.NewID(), shared.NewID()
	nuclei := &tool.Tool{ID: shared.NewID(), Name: "nuclei", IsActive: true}
	tools := &stubTools{tools: map[string]*tool.Tool{"nuclei": nuclei}}
	cfgs := &fakeTenantTools{cfg: map[string]*tool.TenantToolConfig{
		tenantA.String() + "|" + nuclei.ID.String(): {TenantID: tenantA, ToolID: nuclei.ID, IsEnabled: false},
	}}
	svc := &Service{toolRepo: tools, tenantTools: cfgs}
	ctx := context.Background()

	isDisabled := func(err error) bool {
		var de *shared.DomainError
		return errors.As(err, &de) && de.Code == "TOOL_DISABLED"
	}

	if err := svc.validateSingleScanTool(ctx, tenantA, "nuclei"); !isDisabled(err) {
		t.Fatalf("single scan, tenant A disabled nuclei: err = %v, want TOOL_DISABLED", err)
	}
	if err := svc.validateStepTool(ctx, tenantA, &pipeline.Step{StepKey: "s1", Tool: "nuclei"}); !isDisabled(err) {
		t.Fatalf("workflow step, tenant A: err = %v, want TOOL_DISABLED", err)
	}
	if _, err := svc.FilterStepTargets(ctx, tenantA, "nuclei", map[string]any{"targets": []string{"x"}}); !isDisabled(err) {
		t.Fatalf("step dispatch, tenant A: err = %v, want TOOL_DISABLED", err)
	}

	// Tenant B never touched the switch: the tool runs (no row = enabled).
	if err := svc.validateSingleScanTool(ctx, tenantB, "nuclei"); err != nil {
		t.Fatalf("tenant B: %v", err)
	}
	if _, err := svc.FilterStepTargets(ctx, tenantB, "nuclei", map[string]any{"targets": []string{"x"}}); err != nil {
		t.Fatalf("tenant B dispatch: %v", err)
	}

	// Enabled row: runs.
	cfgs.cfg[tenantA.String()+"|"+nuclei.ID.String()].IsEnabled = true
	if err := svc.validateSingleScanTool(ctx, tenantA, "nuclei"); err != nil {
		t.Fatalf("tenant A re-enabled: %v", err)
	}

	// A lookup failure fails closed.
	cfgs.err = errors.New("db down")
	if err := svc.validateSingleScanTool(ctx, tenantA, "nuclei"); err == nil {
		t.Fatalf("config lookup failure must not dispatch")
	}
}
