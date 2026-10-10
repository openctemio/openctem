package automation

import (
	"context"
	"slices"
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// maxAssetsInTriggerData caps the asset list carried in one asset_discovered
// trigger payload. A recon run can create thousands of assets in one batch; the
// run record only needs enough to act on, and asset_count carries the total.
const maxAssetsInTriggerData = 100

// triggerWorkflow starts one workflow run. triggerFn is a test seam; production
// always goes through the WorkflowService (which enforces the per-workflow and
// per-tenant concurrent-run limits).
func (d *WorkflowEventDispatcher) triggerWorkflow(ctx context.Context, input TriggerWorkflowInput) error {
	if d.triggerFn != nil {
		return d.triggerFn(ctx, input)
	}
	_, err := d.service.TriggerWorkflow(ctx, input)
	return err
}

// IsInternetFacing reports whether an asset is reachable from the internet:
// the scanner said so explicitly, or its exposure level is public.
func IsInternetFacing(a *asset.Asset) bool {
	return a.IsInternetAccessible() || a.Exposure() == asset.ExposurePublic
}

// DispatchAssetsDiscovered fires `asset_discovered` for a batch of assets an
// ingest newly created. It matches the signature of
// ingest.AssetsDiscoveredCallback so it can be wired directly.
//
// Each matching workflow is triggered ONCE per batch (not once per asset), with
// the matching assets in the payload. A large recon run therefore starts one
// run per workflow instead of thousands. Runs asynchronously with panic
// recovery so ingest is never blocked or crashed by workflow dispatch.
func (d *WorkflowEventDispatcher) DispatchAssetsDiscovered(_ context.Context, tenantID shared.ID, assets []*asset.Asset) {
	if len(assets) == 0 {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				metrics.RecordPanic("workflow_dispatch")
				d.logger.Error("panic recovered in asset_discovered dispatch",
					"tenant_id", tenantID, "panic", r)
			}
		}()
		dispatchCtx, cancel := context.WithTimeout(context.Background(), dispatchTimeout)
		defer cancel()
		d.dispatchAssetsDiscovered(dispatchCtx, tenantID, assets)
	}()
}

// dispatchAssetsDiscovered is the synchronous body of DispatchAssetsDiscovered.
// It returns the number of workflows triggered.
func (d *WorkflowEventDispatcher) dispatchAssetsDiscovered(ctx context.Context, tenantID shared.ID, assets []*asset.Asset) int {
	ids := make([]shared.ID, 0, len(assets))
	for _, a := range assets {
		if a != nil {
			ids = append(ids, a.ID())
		}
	}
	restricted, ok := d.restrictedAssets(ctx, tenantID, ids)
	if !ok {
		return 0
	}
	if len(restricted) > 0 {
		kept := make([]*asset.Asset, 0, len(assets))
		for _, a := range assets {
			if a != nil && !restricted[a.ID()] {
				kept = append(kept, a)
			}
		}
		assets = kept
	}
	if len(assets) == 0 {
		return 0
	}
	workflows, err := d.findMatchingWorkflows(ctx, tenantID, automationdom.TriggerTypeAssetDiscovered)
	if err != nil {
		d.logger.Error("failed to find asset_discovered workflows", "tenant_id", tenantID, "error", err)
		return 0
	}
	triggered := 0
	for _, wf := range workflows {
		// Defense in depth: the repository query is tenant-scoped already, but
		// a workflow of another tenant must never see this tenant's assets.
		if wf.TenantID != tenantID {
			continue
		}
		cfg, ok := triggerConfigFor(wf, automationdom.TriggerTypeAssetDiscovered)
		if !ok {
			continue
		}
		matched := filterDiscoveredAssets(cfg, assets)
		if len(matched) == 0 {
			continue
		}
		if err := d.triggerWorkflow(ctx, TriggerWorkflowInput{
			TenantID:    tenantID,
			WorkflowID:  wf.ID,
			TriggerType: automationdom.TriggerTypeAssetDiscovered,
			TriggerData: buildAssetsDiscoveredTriggerData(matched),
		}); err != nil {
			d.logger.Error("failed to trigger asset_discovered workflow",
				"workflow_id", wf.ID, "workflow_name", wf.Name, "error", err)
			continue
		}
		triggered++
	}
	d.logger.Info("asset_discovered events dispatched",
		"tenant_id", tenantID,
		"assets_count", len(assets),
		"workflows_matched", len(workflows),
		"workflows_triggered", triggered,
	)
	return triggered
}

// triggerConfigFor returns the trigger node config of the given type. ok is
// false when the workflow has no such trigger node.
func triggerConfigFor(wf *automationdom.Workflow, tt automationdom.TriggerType) (map[string]any, bool) {
	for _, node := range wf.Nodes {
		if node.NodeType == automationdom.NodeTypeTrigger && node.Config.TriggerType == tt {
			return node.Config.TriggerConfig, true
		}
	}
	return nil, false
}

// filterDiscoveredAssets applies the asset_discovered trigger filters:
//
//   - internet_facing_only (bool): keep only internet-facing assets.
//   - asset_type_filter ([]string): keep only these asset types.
//
// No config (or no filter keys) matches every asset.
func filterDiscoveredAssets(cfg map[string]any, assets []*asset.Asset) []*asset.Asset {
	internetOnly, _ := cfg["internet_facing_only"].(bool)
	var types map[string]bool
	if raw, ok := cfg["asset_type_filter"].([]any); ok && len(raw) > 0 {
		types = make(map[string]bool, len(raw))
		for _, t := range raw {
			if s, ok := t.(string); ok {
				types[s] = true
			}
		}
	}
	out := make([]*asset.Asset, 0, len(assets))
	for _, a := range assets {
		if internetOnly && !IsInternetFacing(a) {
			continue
		}
		if types != nil && !types[string(a.Type())] {
			continue
		}
		out = append(out, a)
	}
	return out
}

func assetTriggerSummary(a *asset.Asset) map[string]any {
	return map[string]any{
		"id":               a.ID().String(),
		"name":             a.Name(),
		"type":             string(a.Type()),
		"exposure":         string(a.Exposure()),
		"internet_facing":  IsInternetFacing(a),
		"criticality":      string(a.Criticality()),
		"discovery_source": a.DiscoverySource(),
		"discovery_tool":   a.DiscoveryTool(),
	}
}

// buildAssetsDiscoveredTriggerData builds the run payload. `asset` is the first
// asset (so single-asset templates like {{asset.name}} work), `assets` the
// capped list, and the counts cover the whole batch.
func buildAssetsDiscoveredTriggerData(assets []*asset.Asset) map[string]any {
	listed := assets
	if len(listed) > maxAssetsInTriggerData {
		listed = listed[:maxAssetsInTriggerData]
	}
	summaries := make([]map[string]any, 0, len(listed))
	internetFacing := 0
	for _, a := range assets {
		if IsInternetFacing(a) {
			internetFacing++
		}
	}
	for _, a := range listed {
		summaries = append(summaries, assetTriggerSummary(a))
	}
	return map[string]any{
		"event_type":            string(automationdom.TriggerTypeAssetDiscovered),
		"asset":                 summaries[0],
		"assets":                summaries,
		"asset_count":           len(assets),
		"internet_facing":       internetFacing > 0,
		"internet_facing_count": internetFacing,
		"truncated":             len(assets) > len(listed),
	}
}

// DispatchScanCompleted fires `scan_completed` when a scan run ends
// (completed, partial, failed, timeout or canceled). Each automation picks the outcomes it runs
// on with status_filter (scanOutcomeMatches). Wired as the pipeline service's
// run-settled callback. Async with panic recovery, like every other dispatch
// path.
func (d *WorkflowEventDispatcher) DispatchScanCompleted(_ context.Context, run *scanrun.Run) {
	if run == nil {
		return
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				metrics.RecordPanic("workflow_dispatch")
				d.logger.Error("panic recovered in scan_completed dispatch",
					"run_id", run.ID, "panic", r)
			}
		}()
		dispatchCtx, cancel := context.WithTimeout(context.Background(), dispatchTimeout)
		defer cancel()
		d.dispatchScanCompleted(dispatchCtx, run)
	}()
}

// dispatchScanCompleted is the synchronous body of DispatchScanCompleted. It
// returns the number of workflows triggered.
func (d *WorkflowEventDispatcher) dispatchScanCompleted(ctx context.Context, run *scanrun.Run) int {
	workflows, err := d.findMatchingWorkflows(ctx, run.TenantID, automationdom.TriggerTypeScanCompleted)
	if err != nil {
		d.logger.Error("failed to find scan_completed workflows", "tenant_id", run.TenantID, "error", err)
		return 0
	}
	data := map[string]any{
		"event_type": string(automationdom.TriggerTypeScanCompleted),
		"scan": map[string]any{
			"run_id":           run.ID.String(),
			"scan_workflow_id": run.ScanWorkflowID.String(),
			"status":           string(run.Status),
			"trigger_type":     string(run.TriggerType),
			"total_findings":   run.TotalFindings,
			"completed_at":     completedAt(run),
		},
	}
	if run.ScanID != nil {
		data["scan"].(map[string]any)["scan_id"] = run.ScanID.String()
	}
	// A scan an automation started carries the automation's cause in its run
	// context: "scan finished => run the scan" must not loop.
	var cause *AutomationCause
	if c, ok := automationCauseFromData(run.Context); ok {
		cause = &c
		data = withCause(data, cause)
	}
	triggered := 0
	for _, wf := range workflows {
		if wf.TenantID != run.TenantID {
			continue
		}
		cfg, ok := triggerConfigFor(wf, automationdom.TriggerTypeScanCompleted)
		if !ok || !scanOutcomeMatches(cfg, string(run.Status)) {
			continue
		}
		if reason := loopBlocked(wf, cause, cfg); reason != "" {
			d.logger.Warn("automation not started: loop guard",
				"workflow_id", wf.ID, "workflow_name", wf.Name, "scan_run_id", run.ID,
				"reason", reason)
			continue
		}
		if err := d.triggerWorkflow(ctx, TriggerWorkflowInput{
			TenantID:    run.TenantID,
			WorkflowID:  wf.ID,
			TriggerType: automationdom.TriggerTypeScanCompleted,
			TriggerData: data,
		}); err != nil {
			d.logger.Error("failed to trigger scan_completed workflow",
				"workflow_id", wf.ID, "workflow_name", wf.Name, "error", err)
			continue
		}
		triggered++
	}
	return triggered
}

// scanOutcomes are the run outcomes `scan_completed` reports: every way a
// run ends (research/62 P0-11).
var scanOutcomes = automationdom.ScanOutcomes

// scanOutcomeMatches applies the scan_completed trigger's status_filter
// ([]string of completed, partial, failed). Without one the trigger fires on
// completed runs only, as it always did: an automation written for a
// successful scan never starts on a failed one.
func scanOutcomeMatches(cfg map[string]any, status string) bool {
	if !slices.Contains(scanOutcomes, status) {
		return false
	}
	raw, ok := cfg["status_filter"].([]any)
	if !ok || len(raw) == 0 {
		return status == string(scanrun.RunStatusCompleted)
	}
	for _, v := range raw {
		if s, ok := v.(string); ok && s == status {
			return true
		}
	}
	return false
}

func completedAt(run *scanrun.Run) string {
	if run.CompletedAt != nil {
		return run.CompletedAt.UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}
