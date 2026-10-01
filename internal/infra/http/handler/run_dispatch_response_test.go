package handler

import (
	"encoding/json"
	"testing"
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
		if got.ZoneRouting == nil || got.ZoneRouting.Jobs != 4 || len(got.ZoneRouting.Zones) != 1 ||
			got.ZoneRouting.Zones[0].ZoneName != "dc-a" || got.ZoneRouting.Zones[0].SensorIDs[0] != "s" {
			t.Errorf("%s: zone routing %+v", name, got.ZoneRouting)
		}
	}
	if got := toRunDispatchResponse(map[string]any{"scan_id": "x"}); got != nil {
		t.Errorf("run without a dispatch report: %+v", got)
	}
}
