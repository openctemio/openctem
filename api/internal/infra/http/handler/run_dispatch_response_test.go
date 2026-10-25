package handler

import (
	"encoding/json"
	"testing"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
)

// The dispatch report reaches the API both from a freshly built run context
// and from one loaded from JSONB (numbers become float64, lists []any).
func TestToRunDispatchResponse(t *testing.T) {
	fresh := map[string]any{
		"resolved_target_count": 5,
		"excluded_target_count": 1,
		"dispatch_warnings":     []string{"db01 not scanned: hostname did not resolve"},
		"uncovered_targets":     []map[string]string{{"target": "db01", "reason": "hostname did not resolve"}},
		"zone_routing": map[string]any{
			"jobs": 4, "targets_per_job": 1, "unzoned_targets": 0, "uncovered_targets": 1,
			"zones": []map[string]any{{"zone_id": "z", "zone_name": "dc-a", "targets": 2, "jobs": 2, "queued_jobs": 0, "sensor_ids": []string{"s"}}},
		},
		"excluded_targets": []map[string]any{
			{"target": "old.example.com", "rules": []map[string]string{{"kind": "exclusion", "id": "x1", "pattern": "old.example.com"}}},
			{"target": "198.51.100.0/29", "cut": true, "removed_addresses": 1},
		},
		"scan_id": "ignored",
	}
	raw, _ := json.Marshal(fresh)
	var loaded map[string]any
	_ = json.Unmarshal(raw, &loaded)

	for name, ctx := range map[string]map[string]any{"fresh": fresh, "loaded": loaded} {
		got := toRunDispatchResponse(ctx)
		if got == nil {
			t.Fatalf("%s: no dispatch report", name)
		}
		if got.ResolvedTargets != 5 || got.ExcludedTargets != 1 || len(got.Warnings) != 1 ||
			len(got.UncoveredTargets) != 1 || got.UncoveredTargets[0].Target != "db01" {
			t.Errorf("%s: %+v", name, got)
		}
		if len(got.Excluded) != 2 || got.Excluded[0].Rules[0].Pattern != "old.example.com" ||
			!got.Excluded[1].Cut || got.Excluded[1].RemovedAddresses != 1 {
			t.Errorf("%s: excluded %+v", name, got.Excluded)
		}
		if got.ZoneRouting == nil || got.ZoneRouting.Jobs != 4 || len(got.ZoneRouting.Zones) != 1 ||
			got.ZoneRouting.Zones[0].ZoneName != "dc-a" || got.ZoneRouting.Zones[0].SensorIDs[0] != "s" {
			t.Errorf("%s: zone routing %+v", name, got.ZoneRouting)
		}
	}
	if got := toRunDispatchResponse(map[string]any{"scan_id": "x"}); got != nil {
		t.Errorf("run without a dispatch report: %+v", got)
	}
	if got := toRunDispatchResponse(fresh); got.WillScan != nil || got.Skipped != nil {
		t.Errorf("a run without skip groups reports will_scan %v skipped %v", got.WillScan, got.Skipped)
	}
}

// Skip groups recorded by the trigger reach the Dispatch card with the
// number of targets the run dispatched.
func TestToRunDispatchResponse_SkipGroups(t *testing.T) {
	fresh := map[string]any{
		"resolved_target_count": 555,
		"zone_routing":          map[string]any{"jobs": 13, "targets_per_job": 10, "unzoned_targets": 121, "uncovered_targets": 434},
		scansvc.RunContextKeySkipped: []scansvc.SkipGroup{
			{Reason: "unresolved", Tone: scansvc.SkipToneInfo, Count: 434, Targets: []string{"gone.example.com"}},
			{Reason: "not_resolving", Tone: scansvc.SkipToneInfo, Count: 1, Targets: []string{"old.example.com"}},
		},
	}
	raw, _ := json.Marshal(fresh)
	var loaded map[string]any
	_ = json.Unmarshal(raw, &loaded)
	for name, ctx := range map[string]map[string]any{"fresh": fresh, "loaded": loaded} {
		got := toRunDispatchResponse(ctx)
		if got == nil || got.WillScan == nil || *got.WillScan != 121 || len(got.Skipped) != 2 ||
			got.Skipped[0].Count != 434 || got.Skipped[0].Tone != scansvc.SkipToneInfo || got.Skipped[1].Targets[0] != "old.example.com" {
			t.Errorf("%s: %+v", name, got)
		}
	}
	none := map[string]any{"resolved_target_count": 3, scansvc.RunContextKeySkipped: []scansvc.SkipGroup{}}
	if got := toRunDispatchResponse(none); got.WillScan == nil || *got.WillScan != 3 || len(got.Skipped) != 0 {
		t.Errorf("nothing skipped: %+v", got)
	}
}
