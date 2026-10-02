package handler

import (
	"encoding/json"
	"testing"

	"github.com/openctemio/api/pkg/domain/pipeline"
	"github.com/openctemio/api/pkg/domain/shared"
)

// pipeline.Run has exported fields and no json tags, so encoding it directly
// produces PascalCase keys. Every other endpoint in this API emits snake_case,
// so GET /scans/{id}/runs was unusable by any client following our convention —
// which is exactly why it shipped with zero consumers.
//
// This asserts the two shapes really do differ, so the conversion in
// ListScanRuns cannot be quietly removed as redundant.
func TestScanRuns_DomainEntityIsNotWireCompatible(t *testing.T) {
	run := &pipeline.Run{
		ID:          shared.NewID(),
		TenantID:    shared.NewID(),
		PipelineID:  shared.NewID(),
		TriggerType: pipeline.TriggerTypeManual,
		Status:      pipeline.RunStatusRunning,
	}

	raw, err := json.Marshal(run)
	if err != nil {
		t.Fatalf("marshal domain entity: %v", err)
	}
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, snake := asMap["trigger_type"]; snake {
		t.Fatal("domain entity now emits snake_case; the DTO conversion may be redundant — re-check ListScanRuns")
	}
	if _, pascal := asMap["TriggerType"]; !pascal {
		t.Fatalf("expected PascalCase from the domain entity, got keys: %v", keysOf(asMap))
	}
}

// And the DTO the handler converts through must emit what clients expect.
func TestScanRuns_DTOIsSnakeCase(t *testing.T) {
	run := &pipeline.Run{
		ID:          shared.NewID(),
		TenantID:    shared.NewID(),
		PipelineID:  shared.NewID(),
		TriggerType: pipeline.TriggerTypeManual,
		Status:      pipeline.RunStatusRunning,
		TotalSteps:  3,
	}

	raw, err := json.Marshal(toRunResponse(run))
	if err != nil {
		t.Fatalf("marshal DTO: %v", err)
	}
	var asMap map[string]any
	if err := json.Unmarshal(raw, &asMap); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, key := range []string{"id", "tenant_id", "pipeline_id", "trigger_type", "status", "total_steps"} {
		if _, ok := asMap[key]; !ok {
			t.Errorf("DTO is missing %q; clients read that key. Got: %v", key, keysOf(asMap))
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
