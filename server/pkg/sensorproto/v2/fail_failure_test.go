package v2

import (
	"encoding/json"
	"testing"
)

// The fail request carries the sensor's failure class and bounded evidence
// (research/302); a request without them still decodes.
func TestFailRequest_FailureClassDecodes(t *testing.T) {
	var req FailRequest
	body := `{"error_message":"nuclei crashed","error_code":"TOOL_CRASHED","failure":{"class":"infra.tool_crashed",` +
		`"evidence":{"tool":"nuclei","tool_digest":"sha256:ab","exit_code":139,"signal":"SIGSEGV"}}}`
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	if req.Failure == nil || req.Failure.Class != "infra.tool_crashed" || req.Failure.Evidence.Tool != "nuclei" ||
		req.Failure.Evidence.ExitCode == nil || *req.Failure.Evidence.ExitCode != 139 || req.ErrorCode != "TOOL_CRASHED" {
		t.Fatalf("decoded %+v", req)
	}
	var old FailRequest
	if err := json.Unmarshal([]byte(`{"error_message":"boom"}`), &old); err != nil || old.Failure != nil {
		t.Fatalf("old request: %+v %v", old, err)
	}
}
