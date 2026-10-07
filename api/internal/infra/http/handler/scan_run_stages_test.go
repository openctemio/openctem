package handler

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Stage lanes carry counts only, with arrays and maps never null.
func TestToRunStageList(t *testing.T) {
	out := toRunStageList([]scanrun.StagePlan{
		{StageKey: "dns", Stage: "resolve.dns", Tool: "dnsx", Tier: 0, Chained: true, Inputs: 3, Planned: 2,
			Skipped: map[string]int{"unconfirmed": 1}, MaxHop: 1, PlannedAt: time.Unix(0, 0)},
		{StageKey: "ports", Tier: 1},
	})
	raw, _ := json.Marshal(out)
	var back struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Data) != 2 || back.Data[0]["tier"] != "T0" || back.Data[1]["tier"] != "T1" {
		t.Fatalf("lanes = %s", raw)
	}
	if _, ok := back.Data[1]["skipped"].(map[string]any); !ok {
		t.Fatalf("skipped is not an object: %s", raw)
	}
	if empty, _ := json.Marshal(toRunStageList(nil)); string(empty) != `{"data":[]}` {
		t.Fatalf("empty = %s", empty)
	}
}

// Each lane carries its chunk counts and the sensors that took them; a
// queued chunk counts but names no sensor, a platform job names no sensor.
func TestWithSensorShares(t *testing.T) {
	a := shared.NewID()
	out := withSensorShares(toRunStageList([]scanrun.StagePlan{{StageKey: "http"}, {StageKey: "dns"}}),
		[]command.StepSensorShare{
			{StepKey: "http", SensorID: &a, SensorName: "edge-1", Total: 3, Completed: 2, Running: 1},
			{StepKey: "http", Total: 2, Queued: 2},
			{StepKey: "http", Platform: true, Total: 1, Failed: 1},
			{StepKey: "other", Total: 9},
		})
	http := out.Data[0]
	if http.Chunks != (RunStageChunks{Total: 6, Queued: 2, Running: 1, Completed: 2, Failed: 1}) {
		t.Fatalf("chunks = %+v", http.Chunks)
	}
	if len(http.Sensors) != 2 || http.Sensors[0].SensorID != a.String() || http.Sensors[0].SensorName != "edge-1" ||
		!http.Sensors[1].Platform || http.Sensors[1].SensorID != "" {
		t.Fatalf("sensors = %+v", http.Sensors)
	}
	if dns := out.Data[1]; dns.Chunks.Total != 0 || dns.Sensors == nil || len(dns.Sensors) != 0 {
		t.Fatalf("a stage without commands = %+v", dns)
	}
}
