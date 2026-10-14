package command

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/openctemio/ctis/politeness"
)

func payloadKeys(t *testing.T, payload json.RawMessage) ([]string, bool) {
	t.Helper()
	var p struct {
		HostKeys *[]string `json:"host_keys"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.HostKeys == nil {
		return nil, false
	}
	return *p.HostKeys, true
}

// Every creation path's payload shape gets the keys the sensor would
// compute from it (research/130: the live quick scan's nuclei commands had
// none, so the sensor refused what the platform offered).
func TestAssignHostKeys_EveryPayloadShape(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]any
		targets []string
		network string
	}{
		{"quick scan / single scanner", map[string]any{"scanner": "nuclei", "targets": []string{"https://a.example.com/x", "b.example.com"}, "scan_run_id": "r"}, []string{"https://a.example.com/x", "b.example.com"}, ""},
		{"zone fan-out", map[string]any{"scanner": "naabu", "targets": []string{"203.0.113.7", "203.0.113.0/28"}}, []string{"203.0.113.7", "203.0.113.0/28"}, ""},
		{"validate (one target)", map[string]any{"target": "https://c.example.com:8443/login"}, []string{"https://c.example.com:8443/login"}, ""},
		{"retest (target and targets)", map[string]any{"target": "d.example.com", "targets": []string{"e.example.com"}}, []string{"d.example.com", "e.example.com"}, ""},
		{"private network", map[string]any{"targets": []string{"10.0.0.5"}, "network_id": "0b9e2c1a-1111-2222-3333-444455556666"}, []string{"10.0.0.5"}, "0b9e2c1a-1111-2222-3333-444455556666"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(tc.payload)
			cmd := &Command{Payload: raw}
			if err := AssignHostKeys(cmd); err != nil {
				t.Fatal(err)
			}
			want := politeness.Keys(tc.targets, tc.network)
			if len(want) == 0 || !slices.Equal(cmd.HostKeys, want) {
				t.Fatalf("keys = %v, want %v", cmd.HostKeys, want)
			}
			sent, ok := payloadKeys(t, cmd.Payload)
			if !ok || !slices.Equal(sent, want) {
				t.Fatalf("payload host_keys = %v (%v), want %v", sent, ok, want)
			}
			// The rest of the payload is kept.
			var back map[string]any
			_ = json.Unmarshal(cmd.Payload, &back)
			for k := range tc.payload {
				if _, ok := back[k]; !ok {
					t.Fatalf("payload lost %q", k)
				}
			}
		})
	}
}

func TestAssignHostKeys_CallerAndPayloadKeysWin(t *testing.T) {
	// A scan run's passive stage: the caller sets no keys and the payload
	// says none ([]): it holds nothing, though it names a target.
	raw, _ := json.Marshal(map[string]any{"targets": []string{"a.example.com"}, "host_keys": []string{}})
	cmd := &Command{Payload: raw}
	if err := AssignHostKeys(cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.HostKeys != nil {
		t.Fatalf("passive payload got keys %v", cmd.HostKeys)
	}

	// Keys the caller set are written into the payload as they are.
	raw, _ = json.Marshal(map[string]any{"targets": []string{"a.example.com"}})
	cmd = &Command{Payload: raw, HostKeys: []string{"a.example.com", "in:x"}}
	if err := AssignHostKeys(cmd); err != nil {
		t.Fatal(err)
	}
	if sent, _ := payloadKeys(t, cmd.Payload); !slices.Equal(sent, []string{"a.example.com", "in:x"}) {
		t.Fatalf("payload host_keys = %v", sent)
	}

	// Payload keys are bounded like the sensor bounds them.
	long := make([]byte, maxHostKeyLen+1)
	for i := range long {
		long[i] = 'a'
	}
	raw, _ = json.Marshal(map[string]any{"host_keys": []string{"b", "", string(long), "a", "a"}})
	cmd = &Command{Payload: raw}
	if err := AssignHostKeys(cmd); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cmd.HostKeys, []string{"a", "b"}) {
		t.Fatalf("bounded keys = %v", cmd.HostKeys)
	}

	raw, _ = json.Marshal(map[string]any{"host_keys": "not a list"})
	if err := AssignHostKeys(&Command{Payload: raw}); err == nil {
		t.Fatal("malformed payload host_keys accepted")
	}
}

func TestAssignHostKeys_NoTargetsLeavesPayload(t *testing.T) {
	for _, raw := range []string{`{"connector_id":"x"}`, `{"targets":[]}`, `[]`, `"x"`, ``, `null`} {
		cmd := &Command{Payload: json.RawMessage(raw)}
		if err := AssignHostKeys(cmd); err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		if cmd.HostKeys != nil || string(cmd.Payload) != raw {
			t.Fatalf("%s: keys %v payload %s", raw, cmd.HostKeys, cmd.Payload)
		}
	}
}

func TestNewFollowUp_HoldsOnlyRemainingHosts(t *testing.T) {
	targets := []string{"a.example.com", "b.example.com", "203.0.113.7", "203.0.113.8"}
	raw, _ := json.Marshal(map[string]any{"scanner": "httpx", "targets": targets})
	parent := &Command{Type: CommandTypeScan, Priority: CommandPriorityNormal, Payload: raw}
	if err := AssignHostKeys(parent); err != nil {
		t.Fatal(err)
	}
	fu, err := NewFollowUp(parent, []string{"b.example.com", "203.0.113.8"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	want := politeness.Keys([]string{"b.example.com", "203.0.113.8"}, "")
	if !slices.Equal(fu.HostKeys, want) {
		t.Fatalf("follow-up keys = %v, want %v", fu.HostKeys, want)
	}
	if sent, _ := payloadKeys(t, fu.Payload); !slices.Equal(sent, want) {
		t.Fatalf("follow-up payload keys = %v", sent)
	}

	// A passive parent's follow-up holds nothing either.
	raw, _ = json.Marshal(map[string]any{"targets": targets, "host_keys": []string{}})
	fu, err = NewFollowUp(&Command{Type: CommandTypeScan, Priority: CommandPriorityNormal, Payload: raw}, []string{"a.example.com"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(fu.HostKeys) != 0 {
		t.Fatalf("passive follow-up keys = %v", fu.HostKeys)
	}
	if sent, ok := payloadKeys(t, fu.Payload); !ok || len(sent) != 0 {
		t.Fatalf("passive follow-up payload keys = %v (%v)", sent, ok)
	}
}
