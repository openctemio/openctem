package automation

// A run that lists several assets (an asset_discovered batch) is about all of
// them, but its subject is only the first. A reader who may see the subject
// but not every listed asset gets the run with the list cut to the assets they
// may see and with step inputs, outputs and delivery payloads removed (a
// rendered message cannot be split per asset). A scan_completed run has no
// subject; readers limited to their data scope get its scan id, status and
// finding count only.

import (
	"context"
	"slices"

	automationdom "github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const redactedPayloadReason = "not_in_scope"

// runAssetIDs are the assets a run's trigger data lists.
func runAssetIDs(run *automationdom.Run) []shared.ID {
	_, assets := stepSubjects(nil, run.TriggerData)
	return assets
}

func triggerInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}

// redactRunsForScope redacts runs in place for scope and returns the ids of
// the runs it redacted. A nil scope (an internal call) redacts nothing.
func (s *WorkflowService) redactRunsForScope(ctx context.Context, tenantID shared.ID, scope *shared.DataScope, runs []*automationdom.Run) (map[shared.ID]bool, error) {
	if scope == nil {
		return nil, nil
	}
	var all []shared.ID
	for _, run := range runs {
		for _, id := range runAssetIDs(run) {
			if !slices.Contains(all, id) {
				all = append(all, id)
			}
		}
	}
	visible := map[shared.ID]bool{}
	if len(all) > 0 {
		// Without a reader nothing is known to be visible (fail closed).
		if reader, ok := s.runRepo.(automationdom.RunScopeReader); ok {
			var err error
			if visible, err = reader.VisibleAssets(ctx, tenantID, all, scope); err != nil {
				return nil, err
			}
		}
	}
	done := map[shared.ID]bool{}
	for _, run := range runs {
		if redactRun(run, scope, visible) {
			done[run.ID] = true
		}
	}
	return done, nil
}

func redactRun(run *automationdom.Run, scope *shared.DataScope, visible map[shared.ID]bool) bool {
	ids := runAssetIDs(run)
	switch {
	case len(ids) > 0:
		complete := run.TriggerData["truncated"] != true
		if n := triggerInt(run.TriggerData["asset_count"]); n > len(ids) {
			complete = false
		}
		for _, id := range ids {
			if !visible[id] {
				complete = false
			}
		}
		if complete {
			return false
		}
		run.TriggerData = redactAssetTrigger(run.TriggerData, visible)
	case run.TriggerType == automationdom.TriggerTypeScanCompleted && scope.Restricted():
		run.TriggerData = redactScanTrigger(run.TriggerData)
	default:
		return false
	}
	for _, nr := range run.NodeRuns {
		nr.Input, nr.Output = nil, nil
	}
	return true
}

// redactAssetTrigger copies trigger with the asset list cut to visible assets
// and the counts recomputed from them.
func redactAssetTrigger(trigger map[string]any, visible map[shared.ID]bool) map[string]any {
	out := make(map[string]any, len(trigger))
	for k, v := range trigger {
		out[k] = v
	}
	delete(out, "truncated")
	kept := []map[string]any{}
	facing := 0
	collect := func(v any) {
		a, ok := v.(map[string]any)
		if !ok {
			return
		}
		raw, _ := a["id"].(string)
		if id, err := shared.IDFromString(raw); err == nil && visible[id] {
			kept = append(kept, a)
			if b, _ := a["internet_facing"].(bool); b {
				facing++
			}
		}
	}
	switch list := trigger["assets"].(type) {
	case []any:
		for _, v := range list {
			collect(v)
		}
	case []map[string]any:
		for _, v := range list {
			collect(v)
		}
	}
	out["assets"] = kept
	out["asset_count"] = len(kept)
	out["internet_facing"] = facing > 0
	out["internet_facing_count"] = facing
	if len(kept) > 0 {
		out["asset"] = kept[0]
	} else {
		delete(out, "asset")
	}
	out["redacted"] = redactedPayloadReason
	return out
}

// redactScanTrigger keeps the scan id, status and finding count.
func redactScanTrigger(trigger map[string]any) map[string]any {
	scan := map[string]any{}
	if in, ok := trigger["scan"].(map[string]any); ok {
		for _, k := range []string{"run_id", "status", "total_findings"} {
			if v, ok := in[k]; ok {
				scan[k] = v
			}
		}
	}
	return map[string]any{
		"event_type": trigger["event_type"],
		"scan":       scan,
		"redacted":   redactedPayloadReason,
	}
}
