package stage

import "testing"

// monitor.web_content is routed to httpx for a step or job that names the
// capability; a step that pins httpx alone still runs the HTTP probe, and the
// job names the capability the sensor's httpx declares.
func TestMonitorWebContent_RoutedToHTTPX(t *testing.T) {
	st, ok := Lookup(MonitorWebContent)
	if !ok || !st.Available() || IsPlanned(MonitorWebContent) {
		t.Fatal("monitor.web_content is not a routed stage")
	}
	if st.Tier != TierActive || st.Tier.Passive() || st.Findings || len(st.Outputs) != 0 {
		t.Fatalf("stage: %+v", st)
	}
	if st.ID() != "monitor.web_content@1" || st.DefaultTool() != "httpx" {
		t.Fatalf("id %s tool %s", st.ID(), st.DefaultTool())
	}
	if got, err := ForCapabilities([]string{"monitor.web_content"}); err != nil || got.Key != MonitorWebContent {
		t.Fatalf("capability step: %+v %v", got, err)
	}
	if got, ok := ForStep("httpx", nil); !ok || got.Key != ProbeHTTP {
		t.Fatalf("pinned httpx without a capability: %+v", got)
	}
	if got, ok := ForStep("httpx", []string{"monitor.web_content"}); !ok || got.Key != MonitorWebContent {
		t.Fatalf("pinned httpx naming the capability: %+v", got)
	}
	if !TakesCapabilityJobs(st, "httpx") {
		t.Fatal("a web content job names its capability")
	}
	if IntensityTier("httpx", []string{"monitor.web_content"}, nil) != TierActive {
		t.Log("intensity of httpx by capability is the tool's own")
	}
}
