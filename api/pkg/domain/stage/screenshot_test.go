package stage

import "testing"

// capture.screenshot is routed to the sensor's webshot tool, which takes
// capability jobs and a list of targets; it annotates the web service it
// was given (the web_evidence property): its output is that same service.
func TestCaptureScreenshot_RoutedToWebshot(t *testing.T) {
	st, ok := Lookup(CaptureScreenshot)
	if !ok || !st.Available() || IsPlanned(CaptureScreenshot) {
		t.Fatal("capture.screenshot is not a routed stage")
	}
	if st.Tier != TierActive || st.Tier.Passive() || st.Findings || len(st.Outputs) != 1 || st.Outputs[0] != tHTTPService {
		t.Fatalf("stage: %+v", st)
	}
	if len(st.Inputs) != 1 || st.Inputs[0] != tHTTPService {
		t.Fatalf("inputs: %+v", st.Inputs)
	}
	if st.ID() != "capture.screenshot@1" || st.DefaultTool() != "webshot" {
		t.Fatalf("id %s tool %s", st.ID(), st.DefaultTool())
	}
	if got, err := ForCapabilities([]string{"capture.screenshot"}); err != nil || got.Key != CaptureScreenshot {
		t.Fatalf("capability step: %+v %v", got, err)
	}
	if got, ok := ForStep("webshot", []string{"capture.screenshot"}); !ok || got.Key != CaptureScreenshot {
		t.Fatalf("pinned webshot: %+v", got)
	}
	if !TakesCapabilityJobs(st, "webshot") || !AcceptsTargetList("webshot") {
		t.Fatal("webshot takes capability jobs and a target list")
	}
	if st.ChunkSize != 10 {
		t.Fatal("chunk size is 10")
	}
	if !Heavy(CaptureScreenshot) || HeavyMaxAge(CaptureScreenshot).Hours() != 30*24 {
		t.Fatal("heavy, 30 days")
	}
}
