package workflow

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	workflowdom "github.com/openctemio/openctem/api/pkg/domain/workflow"
)

type workflowsOff map[string]bool // tenant id -> workflows off

func (m workflowsOff) TenantDisabledModules(_ context.Context, tenantID string) map[string]bool {
	return map[string]bool{"workflows": m[tenantID]}
}

// A tenant with the workflows module off starts no automation from an
// event; another tenant on the same dispatcher still does.
func TestDispatch_WorkflowsModuleOffStartsNothing(t *testing.T) {
	off, on := shared.NewID(), shared.NewID()
	repo := &fakeWorkflowRepo{byTenant: map[shared.ID][]*workflowdom.Workflow{
		off: {newWorkflow(off, workflowdom.TriggerTypeAssetDiscovered, nil)},
		on:  {newWorkflow(on, workflowdom.TriggerTypeAssetDiscovered, nil)},
	}}
	rec := &triggerRecorder{}
	d := newTestDispatcher(repo, rec)
	d.SetModuleGuard(workflowsOff{off.String(): true})

	ctx := context.Background()
	if n := d.dispatchAssetsDiscovered(ctx, off, []*asset.Asset{mkAsset(t, off, "a.example.com", asset.AssetTypeDomain, true)}); n != 0 {
		t.Errorf("tenant with workflows off: %d automations started", n)
	}
	if n := d.dispatchAssetsDiscovered(ctx, on, []*asset.Asset{mkAsset(t, on, "b.example.com", asset.AssetTypeDomain, true)}); n != 1 {
		t.Errorf("tenant with workflows on: %d automations started, want 1", n)
	}
	if len(rec.calls) != 1 || rec.calls[0].TenantID != on {
		t.Fatalf("trigger calls %+v", rec.calls)
	}
}
