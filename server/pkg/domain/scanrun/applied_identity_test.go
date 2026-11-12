package scanrun

import (
	"encoding/json"
	"strings"
	"testing"
)

// What a sensor reports it sent with is parsed defensively: one object or a
// list, bounded, single-line, unknown carriers dropped, and a value whose
// name looks like a secret is masked again whatever the sensor sent.
func TestParseAppliedIdentity(t *testing.T) {
	raw := json.RawMessage(`{"tool":"nuclei","user_agent":"ua/2\r\nX-Injected: 1","user_agent_source":"job_locked",
		"user_agent_pool":3,"required":true,"carrier":"forwarder",
		"headers":[{"name":"X-Scan","value":"corp","source":"job","applied":true},
		           {"name":"X-Api-Token","value":"s3cr3t","source":"sensor","applied":false,"reason":"locked by the job"}],
		"query":{"name":"scan","value":"corp-1","applied":true}}`)
	got := ParseAppliedIdentity(raw)
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	a := got[0]
	if a.Tool != "nuclei" || strings.ContainsAny(a.UserAgent, "\r\n") || a.UserAgentPool != 3 || !a.Required || a.Carrier != "forwarder" {
		t.Fatalf("parsed %+v", a)
	}
	if len(a.Headers) != 2 || a.Headers[0].Value != "corp" || a.Headers[1].Value != MaskedIdentityValue || a.Headers[1].Applied {
		t.Fatalf("headers %+v", a.Headers)
	}
	if a.Query == nil || a.Query.Value != "corp-1" || !a.Query.Applied {
		t.Fatalf("query %+v", a.Query)
	}

	// A list, an unknown carrier, an out-of-range pool and junk entries.
	list := json.RawMessage(`[{"tool":"httpx","carrier":"magic","user_agent_pool":99999,"query":{"name":"session","value":"abc","applied":true}}, 7, "x"]`)
	got = ParseAppliedIdentity(list)
	if len(got) != 1 || got[0].Carrier != "" || got[0].UserAgentPool != 0 || got[0].Query.Value != MaskedIdentityValue {
		t.Fatalf("list %+v", got)
	}

	// Bounds: too many entries or headers are cut; oversized input is ignored.
	var many []map[string]any
	for i := 0; i < 50; i++ {
		hs := make([]map[string]any, 40)
		for j := range hs {
			hs[j] = map[string]any{"name": "X-H", "value": "v", "applied": true}
		}
		many = append(many, map[string]any{"tool": "t", "headers": hs})
	}
	b, _ := json.Marshal(many)
	if got := ParseAppliedIdentity(b); len(got) != 0 {
		t.Fatalf("oversized input parsed: %d", len(got))
	}
	b, _ = json.Marshal(many[:3])
	got = ParseAppliedIdentity(b)
	if len(got) != 3 || len(got[0].Headers) != MaxAppliedHeaders {
		t.Fatalf("bounded %d %d", len(got), len(got[0].Headers))
	}
	for _, bad := range []string{``, `null`, `{`, `"str"`, `{}`} {
		if got := ParseAppliedIdentity(json.RawMessage(bad)); len(got) != 0 {
			t.Errorf("%q gave %+v", bad, got)
		}
	}
	if (SensorSettings{SentWith: []AppliedIdentity{{Tool: "t"}}}).IsZero() {
		t.Fatal("settings with sent_with reported as empty")
	}
}
