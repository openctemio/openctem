package workflow

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	workflowdom "github.com/openctemio/openctem/api/pkg/domain/workflow"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeWorkflowRepo returns the workflows registered for (tenant, trigger type),
// the way the tenant-scoped SQL query does.
type fakeWorkflowRepo struct {
	workflowdom.WorkflowRepository
	byTenant map[shared.ID][]*workflowdom.Workflow
	err      error
}

func (f *fakeWorkflowRepo) ListActiveWithTriggerType(_ context.Context, tenantID shared.ID, tt workflowdom.TriggerType) ([]*workflowdom.Workflow, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []*workflowdom.Workflow
	for _, wf := range f.byTenant[tenantID] {
		if _, ok := triggerConfigFor(wf, tt); ok {
			out = append(out, wf)
		}
	}
	return out, nil
}

func newWorkflow(tenant shared.ID, tt workflowdom.TriggerType, cfg map[string]any) *workflowdom.Workflow {
	return &workflowdom.Workflow{
		ID:       shared.NewID(),
		TenantID: tenant,
		Name:     "wf-" + string(tt),
		IsActive: true,
		Nodes: []*workflowdom.Node{{
			ID:       shared.NewID(),
			NodeType: workflowdom.NodeTypeTrigger,
			Config:   workflowdom.NodeConfig{TriggerType: tt, TriggerConfig: cfg},
		}},
	}
}

type triggerRecorder struct{ calls []TriggerWorkflowInput }

func (r *triggerRecorder) fn(_ context.Context, in TriggerWorkflowInput) error {
	r.calls = append(r.calls, in)
	return nil
}

func newTestDispatcher(repo workflowdom.WorkflowRepository, rec *triggerRecorder) *WorkflowEventDispatcher {
	return &WorkflowEventDispatcher{workflowRepo: repo, logger: logger.NewNop(), triggerFn: rec.fn}
}

func mkAsset(t *testing.T, tenant shared.ID, name string, typ asset.AssetType, public bool) *asset.Asset {
	t.Helper()
	a, err := asset.NewAssetWithTenant(tenant, name, typ, asset.CriticalityMedium)
	if err != nil {
		t.Fatal(err)
	}
	if public {
		a.SetInternetAccessible(true)
		a.SetExposure(asset.ExposurePublic)
	}
	return a
}

func TestDispatchAssetsDiscovered_OneRunPerWorkflowPerBatch(t *testing.T) {
	tenant := shared.NewID()
	wf := newWorkflow(tenant, workflowdom.TriggerTypeAssetDiscovered, nil)
	repo := &fakeWorkflowRepo{byTenant: map[shared.ID][]*workflowdom.Workflow{tenant: {wf}}}
	rec := &triggerRecorder{}
	d := newTestDispatcher(repo, rec)

	assets := []*asset.Asset{
		mkAsset(t, tenant, "a.example.com", asset.AssetTypeDomain, true),
		mkAsset(t, tenant, "10.0.0.1", asset.AssetTypeHost, false),
	}
	if n := d.dispatchAssetsDiscovered(context.Background(), tenant, assets); n != 1 {
		t.Fatalf("triggered = %d, want 1", n)
	}
	if len(rec.calls) != 1 {
		t.Fatalf("trigger calls = %d, want 1", len(rec.calls))
	}
	in := rec.calls[0]
	if in.TenantID != tenant || in.WorkflowID != wf.ID || in.TriggerType != workflowdom.TriggerTypeAssetDiscovered {
		t.Fatalf("unexpected trigger input %+v", in)
	}
	if got := in.TriggerData["asset_count"]; got != 2 {
		t.Fatalf("asset_count = %v, want 2", got)
	}
	if got := in.TriggerData["internet_facing_count"]; got != 1 {
		t.Fatalf("internet_facing_count = %v, want 1", got)
	}
	first := in.TriggerData["asset"].(map[string]any)
	if first["name"] != "a.example.com" || first["internet_facing"] != true {
		t.Fatalf("asset payload = %v", first)
	}
}

func TestDispatchAssetsDiscovered_Filters(t *testing.T) {
	tenant := shared.NewID()
	internetOnly := newWorkflow(tenant, workflowdom.TriggerTypeAssetDiscovered, map[string]any{"internet_facing_only": true})
	hostsOnly := newWorkflow(tenant, workflowdom.TriggerTypeAssetDiscovered, map[string]any{"asset_type_filter": []any{"host"}})
	repo := &fakeWorkflowRepo{byTenant: map[shared.ID][]*workflowdom.Workflow{tenant: {internetOnly, hostsOnly}}}
	rec := &triggerRecorder{}
	d := newTestDispatcher(repo, rec)

	// Only an internal domain: neither internet-facing nor a host.
	d.dispatchAssetsDiscovered(context.Background(), tenant, []*asset.Asset{
		mkAsset(t, tenant, "intranet.corp", asset.AssetTypeDomain, false),
	})
	if len(rec.calls) != 0 {
		t.Fatalf("filters did not apply: %d runs", len(rec.calls))
	}

	d.dispatchAssetsDiscovered(context.Background(), tenant, []*asset.Asset{
		mkAsset(t, tenant, "api.example.com", asset.AssetTypeDomain, true),
	})
	if len(rec.calls) != 1 || rec.calls[0].WorkflowID != internetOnly.ID {
		t.Fatalf("want only the internet-facing workflow, got %d runs", len(rec.calls))
	}
}

func TestDispatchAssetsDiscovered_TenantScoped(t *testing.T) {
	t1, t2 := shared.NewID(), shared.NewID()
	wf2 := newWorkflow(t2, workflowdom.TriggerTypeAssetDiscovered, nil)
	// A (hypothetically) mis-scoped repo returning tenant 2's workflow for
	// tenant 1 must still not run it with tenant 1's assets.
	repo := &fakeWorkflowRepo{byTenant: map[shared.ID][]*workflowdom.Workflow{t1: {wf2}, t2: {wf2}}}
	rec := &triggerRecorder{}
	d := newTestDispatcher(repo, rec)

	d.dispatchAssetsDiscovered(context.Background(), t1, []*asset.Asset{mkAsset(t, t1, "x.example.com", asset.AssetTypeDomain, true)})
	if len(rec.calls) != 0 {
		t.Fatalf("tenant 1 assets triggered tenant 2 workflow")
	}
	d.dispatchAssetsDiscovered(context.Background(), t2, []*asset.Asset{mkAsset(t, t2, "y.example.com", asset.AssetTypeDomain, true)})
	if len(rec.calls) != 1 || rec.calls[0].TenantID != t2 {
		t.Fatalf("tenant 2 workflow not triggered for its own assets")
	}
}

func TestDispatchAssetsDiscovered_PayloadCapped(t *testing.T) {
	tenant := shared.NewID()
	assets := make([]*asset.Asset, 0, maxAssetsInTriggerData+5)
	for i := 0; i < maxAssetsInTriggerData+5; i++ {
		assets = append(assets, mkAsset(t, tenant, "h"+string(rune('a'+i%26))+shared.NewID().String()[:8]+".example.com", asset.AssetTypeDomain, true))
	}
	data := buildAssetsDiscoveredTriggerData(assets)
	if n := len(data["assets"].([]map[string]any)); n != maxAssetsInTriggerData {
		t.Fatalf("listed = %d, want cap %d", n, maxAssetsInTriggerData)
	}
	if data["asset_count"] != len(assets) || data["truncated"] != true {
		t.Fatalf("count/truncated wrong: %v %v", data["asset_count"], data["truncated"])
	}
}

func TestDispatchAssetsDiscovered_RepoErrorIsSwallowed(t *testing.T) {
	rec := &triggerRecorder{}
	d := newTestDispatcher(&fakeWorkflowRepo{err: errors.New("db down")}, rec)
	if n := d.dispatchAssetsDiscovered(context.Background(), shared.NewID(), []*asset.Asset{mkAsset(t, shared.NewID(), "z.example.com", asset.AssetTypeDomain, true)}); n != 0 {
		t.Fatalf("triggered %d on repo error", n)
	}
}

func TestDispatchScanCompleted(t *testing.T) {
	tenant := shared.NewID()
	wf := newWorkflow(tenant, workflowdom.TriggerTypeScanCompleted, nil)
	other := newWorkflow(shared.NewID(), workflowdom.TriggerTypeScanCompleted, nil)
	repo := &fakeWorkflowRepo{byTenant: map[shared.ID][]*workflowdom.Workflow{tenant: {wf, other}}}
	rec := &triggerRecorder{}
	d := newTestDispatcher(repo, rec)

	scanID := shared.NewID()
	run := &scanrun.Run{ID: shared.NewID(), TenantID: tenant, ScanWorkflowID: shared.NewID(), ScanID: &scanID,
		Status: scanrun.RunStatusCompleted, TotalFindings: 7}
	if n := d.dispatchScanCompleted(context.Background(), run); n != 1 {
		t.Fatalf("triggered = %d, want 1 (other-tenant workflow must be skipped)", n)
	}
	scan := rec.calls[0].TriggerData["scan"].(map[string]any)
	if scan["scan_id"] != scanID.String() || scan["total_findings"] != 7 {
		t.Fatalf("scan payload = %v", scan)
	}
}

// A failed or partial run fires only the automations that ask for that
// outcome; without a status_filter only completed runs fire (as before).
func TestDispatchScanCompleted_StatusFilter(t *testing.T) {
	tenant := shared.NewID()
	plain := newWorkflow(tenant, workflowdom.TriggerTypeScanCompleted, nil)
	onFailure := newWorkflow(tenant, workflowdom.TriggerTypeScanCompleted, map[string]any{"status_filter": []any{"failed", "partial"}})
	onAny := newWorkflow(tenant, workflowdom.TriggerTypeScanCompleted, map[string]any{"status_filter": []any{"completed", "partial", "failed"}})
	// research/62 P0-11: a run that times out or is canceled ended too.
	onEnded := newWorkflow(tenant, workflowdom.TriggerTypeScanCompleted, map[string]any{"status_filter": []any{"timeout", "canceled"}})
	repo := &fakeWorkflowRepo{byTenant: map[shared.ID][]*workflowdom.Workflow{tenant: {plain, onFailure, onAny, onEnded}}}

	cases := []struct {
		status scanrun.RunStatus
		want   []*workflowdom.Workflow
	}{
		{scanrun.RunStatusCompleted, []*workflowdom.Workflow{plain, onAny}},
		{scanrun.RunStatusPartial, []*workflowdom.Workflow{onFailure, onAny}},
		{scanrun.RunStatusFailed, []*workflowdom.Workflow{onFailure, onAny}},
		{scanrun.RunStatusCanceled, []*workflowdom.Workflow{onEnded}},
		{scanrun.RunStatusTimeout, []*workflowdom.Workflow{onEnded}},
		{scanrun.RunStatusBlocked, nil},
	}
	for _, tc := range cases {
		rec := &triggerRecorder{}
		d := newTestDispatcher(repo, rec)
		run := &scanrun.Run{ID: shared.NewID(), TenantID: tenant, ScanWorkflowID: shared.NewID(), Status: tc.status}
		if n := d.dispatchScanCompleted(context.Background(), run); n != len(tc.want) {
			t.Errorf("%s: triggered %d, want %d", tc.status, n, len(tc.want))
			continue
		}
		for i, wf := range tc.want {
			if rec.calls[i].WorkflowID != wf.ID {
				t.Errorf("%s: call %d ran %s, want %s", tc.status, i, rec.calls[i].WorkflowID, wf.Name)
			}
			if got := rec.calls[i].TriggerData["scan"].(map[string]any)["status"]; got != string(tc.status) {
				t.Errorf("%s: payload status = %v", tc.status, got)
			}
		}
	}
}
