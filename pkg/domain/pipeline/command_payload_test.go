package pipeline

import (
	"encoding/json"
	"testing"
)

// The gate. A payload built with the exported key constants must unmarshal into
// StepCommandPayload with every field populated.
//
// This is the check that did not exist when the dispatcher wrote `run_id` and
// the handler read `pipeline_run_id`. Rename either side without the other and
// this fails.
func TestStepCommandPayloadKeysMatchHandlerContract(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		PayloadKeyPipelineRunID: "run-1",
		PayloadKeyStepKey:       "quick_scan",
		PayloadKeyStepRunID:     "steprun-1",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got StepCommandPayload
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got.PipelineRunID != "run-1" {
		t.Errorf("PayloadKeyPipelineRunID (%q) does not feed StepCommandPayload.PipelineRunID; got %q",
			PayloadKeyPipelineRunID, got.PipelineRunID)
	}
	if got.StepKey != "quick_scan" {
		t.Errorf("PayloadKeyStepKey (%q) does not feed StepCommandPayload.StepKey; got %q",
			PayloadKeyStepKey, got.StepKey)
	}
	if got.StepRunID != "steprun-1" {
		t.Errorf("PayloadKeyStepRunID (%q) does not feed StepCommandPayload.StepRunID; got %q",
			PayloadKeyStepRunID, got.StepRunID)
	}
}

// `run_id` was the key that actually shipped, and it is NOT the routing key. A
// payload carrying only that must be recognized as unroutable rather than
// quietly half-working.
func TestStepCommandPayload_RunIDAloneIsNotRoutable(t *testing.T) {
	var got StepCommandPayload
	if err := json.Unmarshal([]byte(`{"run_id":"run-1","scan_id":"scan-1"}`), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.IsRoutable() {
		t.Error("a payload with only run_id must not be considered routable")
	}
}

func TestStepCommandPayload_IsRoutable(t *testing.T) {
	cases := []struct {
		name    string
		payload StepCommandPayload
		want    bool
	}{
		{"both present", StepCommandPayload{PipelineRunID: "r", StepKey: "s"}, true},
		{"missing step key", StepCommandPayload{PipelineRunID: "r"}, false},
		{"missing run id", StepCommandPayload{StepKey: "s"}, false},
		{"empty", StepCommandPayload{}, false},
		// step_run_id is a convenience, not part of routing.
		{"step run id alone", StepCommandPayload{StepRunID: "sr"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.payload.IsRoutable(); got != tc.want {
				t.Errorf("IsRoutable() = %v, want %v", got, tc.want)
			}
		})
	}
}
