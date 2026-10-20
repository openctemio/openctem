package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scanrun"
)

// The reach outcome of a completed command (sensor-supplied) shapes the
// step's outcome: none reached fails it, some unreached ends it partial,
// none reported keeps today's behavior.
func TestWithReach(t *testing.T) {
	list := json.RawMessage(`[{"target":"192.0.2.7","class":"timeout"},{"target":"evil\n\u001b[2J","class":"no_route"},{"target":"x","class":"reached"}]`)

	p := withReach(scanrun.Partial{}, json.RawMessage(`{"v":1,"targets":2,"reached":0,"unreached":2,"classes":{"timeout":1,"no_route":1}}`), list, 2)
	if p.Tried != 2 {
		t.Fatalf("targets tried = %d, want 2", p.Tried)
	}
	if !p.AllUnreached || p.Unreached != 2 || !strings.HasPrefix(p.UnreachableMessage, "No target was reachable from the sensor (2 target(s)") {
		t.Fatalf("all unreached: %+v", p)
	}
	if strings.ContainsAny(p.UnreachableMessage, "\n\x1b") {
		t.Fatalf("sensor text not cleaned: %q", p.UnreachableMessage)
	}

	p = withReach(scanrun.Partial{Gaps: 1}, json.RawMessage(`{"targets":5,"reached":4,"unreached":1}`), list, 1)
	if p.AllUnreached || p.Unreached != 1 || p.Gaps != 1 || !strings.Contains(p.UnreachedSummary, "1 of 5 target(s)") {
		t.Fatalf("some unreached: %+v", p)
	}

	for _, raw := range []string{``, `null`, `"x"`, `{"reached":0,"unreached":5}`} {
		if p := withReach(scanrun.Partial{}, json.RawMessage(raw), list, 9); p.Unreached != 0 || p.AllUnreached {
			t.Fatalf("%q changed the outcome: %+v", raw, p)
		}
	}
	// Every target reached: unchanged.
	if p := withReach(scanrun.Partial{}, json.RawMessage(`{"targets":3,"reached":3,"unreached":0}`), nil, 0); p.Unreached != 0 || p.AllUnreached {
		t.Fatalf("all reached: %+v", p)
	}
}
