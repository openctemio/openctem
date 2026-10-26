package command

import (
	"strings"
	"testing"

	"github.com/openctemio/ctis/outcome"
)

func TestFailureClass_MovableAndTargetSide(t *testing.T) {
	movable := []FailureClass{ClassToolUnavailable, ClassToolCrashed, ClassResourceMemory, ClassResourceDisk,
		ClassContentUnavailable, ClassSensorOffline, ClassSensorNetwork, ClassDNSResolver}
	for _, c := range movable {
		if !c.Movable() || c.TargetSide() {
			t.Errorf("%s must be movable", c)
		}
	}
	// A limit every sensor shares, a pool without an endpoint and every
	// fact about the target are never moved.
	for _, s := range []string{"infra.resource.output_limit", "infra.budget_exceeded", "infra.egress.pool_exhausted",
		"target.unreachable", "target.edge_blocked", "target.edge_challenged", "target.rate_limited"} {
		c, ok := ParseFailureClass(s)
		if !ok {
			t.Fatalf("%s did not parse", s)
		}
		if c.Movable() {
			t.Errorf("%s must not be movable", s)
		}
	}
	for _, s := range []string{"", "infra.unknown", "target.", "TOOL_EXIT", "infra.tool_crashed\n"} {
		if c, ok := ParseFailureClass(s); ok && s != "infra.tool_crashed\n" {
			t.Errorf("%q parsed as %q", s, c)
		}
	}
}

func TestSanitizeEvidence_ClosedAndBounded(t *testing.T) {
	bad := 9000
	e := SanitizeEvidence(FailureEvidence{Tool: "nuclei\nforged log line", ToolDigest: "sha256:" + strings.Repeat("a", 64),
		ContentDigest: strings.Repeat("b", 500), Stage: "<script>", Signal: "SIGSEGV", ExitCode: &bad})
	if e.Tool != "" || e.Stage != "" || e.ContentDigest != "" || e.ExitCode != nil {
		t.Fatalf("hostile evidence kept: %+v", e)
	}
	if e.ToolDigest == "" || e.Signal != "SIGSEGV" {
		t.Fatalf("good evidence dropped: %+v", e)
	}
}

func TestInfraClassFromText(t *testing.T) {
	for msg, want := range map[string]FailureClass{
		`exec: "nuclei": executable file not found in $PATH`: ClassToolUnavailable,
		"write /tmp/x: no space left on device":              ClassResourceDisk,
		"fatal error: out of memory":                         ClassResourceMemory,
		"tool crashed: exited without a result":              ClassToolCrashed,
		"failed to fetch content pack":                       ClassContentUnavailable,
	} {
		if got, ok := InfraClassFromText(msg); !ok || got != want {
			t.Errorf("%q: got %q %v, want %q", msg, got, ok, want)
		}
	}
	// A target fact or an unknown text is not an infrastructure failure.
	for _, msg := range []string{"scan failed", "connection refused by the target", "waf blocked the request", "429 too many requests", ""} {
		if got, ok := InfraClassFromText(msg); ok {
			t.Errorf("%q classified as %q", msg, got)
		}
	}
}

func TestAggregateInfraCauses_NamesEveryCause(t *testing.T) {
	msg := AggregateInfraCauses([]InfraAttempt{
		{SensorID: "11111111-0000-0000-0000-000000000000", Class: ClassToolCrashed, Tool: "nuclei"},
		{SensorID: "22222222-0000-0000-0000-000000000000", Class: ClassResourceDisk},
	})
	for _, want := range []string{"2 sensor attempt", "11111111", "nuclei crashed", "22222222", "ran out of disk space", "none about the target"} {
		if !strings.Contains(msg, want) {
			t.Errorf("%q lacks %q", msg, want)
		}
	}
	if strings.Contains(msg, "Max dispatch") {
		t.Error("generic text")
	}
}

// SensorSide: only the sensor's own network or resolver is handed out
// again; facts about the target, edge answers, rate limits, tool errors and
// the sensor's own egress refusal never are.
func TestSensorSide_OnlyTheSensorsOwnFaults(t *testing.T) {
	cases := []struct {
		name string
		o    outcome.Target
		want bool
	}{
		{"sensor network fault", outcome.Target{Target: "a", State: outcome.Failed, Class: outcome.SensorNetworkFault, Cause: outcome.CauseSensor}, true},
		{"sensor network fault, implied cause", outcome.Target{Target: "a", State: outcome.Failed, Class: outcome.SensorNetworkFault}, true},
		{"proxy pool gap", outcome.Target{Target: "a", State: outcome.Failed, Class: outcome.SensorNetworkFault, Cause: outcome.CauseSensor, Reason: "proxy_unavailable"}, true},
		{"resolver failed, own resolver", outcome.Target{Target: "a", State: outcome.Failed, Class: outcome.ResolverFailed, Cause: outcome.CauseSensor}, true},
		{"resolver failed, ambiguous", outcome.Target{Target: "a", State: outcome.Failed, Class: outcome.ResolverFailed}, false},
		{"unreachable", outcome.Target{Target: "a", State: outcome.Failed, Class: outcome.Unreachable, Cause: outcome.CauseTarget}, false},
		{"unreachable claimed sensor-side", outcome.Target{Target: "a", State: outcome.Failed, Class: outcome.Unreachable, Cause: outcome.CauseSensor}, false},
		{"timeout", outcome.Target{Target: "a", State: outcome.Failed, Class: outcome.Timeout}, false},
		{"name gone", outcome.Target{Target: "a", State: outcome.Failed, Class: outcome.NameGone}, false},
		{"edge blocked", outcome.Target{Target: "a", State: outcome.Failed, Class: outcome.EdgeBlocked, Cause: outcome.CauseTarget}, false},
		{"edge blocked claimed sensor-side", outcome.Target{Target: "a", State: outcome.Failed, Class: outcome.EdgeBlocked, Cause: outcome.CauseSensor}, false},
		{"edge challenged", outcome.Target{Target: "a", State: outcome.Failed, Class: outcome.EdgeChallenged}, false},
		{"rate limited", outcome.Target{Target: "a", State: outcome.Failed, Class: outcome.RateLimited}, false},
		{"tool error", outcome.Target{Target: "a", State: outcome.Failed, Class: outcome.ToolError}, false},
		{"egress refused", outcome.Target{Target: "a", State: outcome.Failed, Class: outcome.EgressRefused}, false},
		{"done", outcome.Target{Target: "a", State: outcome.Done}, false},
		{"unfinished", outcome.Target{Target: "a", State: outcome.Unfinished}, false},
	}
	for _, c := range cases {
		if got := SensorSide(c.o); got != c.want {
			t.Errorf("%s: SensorSide = %v, want %v", c.name, got, c.want)
		}
	}
}
