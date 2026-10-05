package handler

import (
	"encoding/json"
	"testing"
	"time"

	pipelinedom "github.com/openctemio/openctem/api/pkg/domain/pipeline"
)

// Stage lanes carry counts only, with arrays and maps never null.
func TestToRunStageList(t *testing.T) {
	out := toRunStageList([]pipelinedom.StagePlan{
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
