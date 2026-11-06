package unit

import (
	"strings"
	"testing"
)

// Sensor protocol v1 (/api/v1/agent/*) and the /api/v1/agents management
// redirect are retired (RFC-029, 2026-10-05). No route registration may mount
// anything under either prefix again: a v1 route would be a second, older
// sensor-key surface beside /api/v2/sensor, outside the v2 edge chain.
// internal/infra/http/routes TestSensorV2Control_ProtocolV1RoutesAreGone adds
// the runtime side: with a valid sensor key the old paths answer 404 and a
// queued command is left untouched.
func TestSensorProtocolV1IsNotMounted(t *testing.T) {
	routes := parseRoutes(t)
	if len(routes) == 0 {
		t.Fatal("no routes parsed; the collector is broken")
	}
	for _, r := range routes {
		if r.path == "/api/v1/agent" || strings.HasPrefix(r.path, "/api/v1/agent/") ||
			r.path == "/api/v1/agents" || strings.HasPrefix(r.path, "/api/v1/agents/") {
			t.Errorf("%s %s (%s): protocol v1 is retired; sensors use /api/v2/sensor", r.method, r.path, r.pos)
		}
	}
}
