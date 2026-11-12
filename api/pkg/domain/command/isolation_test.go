package command

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestJobTool(t *testing.T) {
	for _, c := range []struct {
		name string
		cmd  *Command
		want string
	}{
		{"scan scanner", &Command{Type: CommandTypeScan, Payload: json.RawMessage(`{"scanner":" Nuclei "}`)}, "nuclei"},
		{"scan preferred tool", &Command{Type: CommandTypeScan, Payload: json.RawMessage(`{"preferred_tool":"httpx"}`)}, "httpx"},
		{"retest", &Command{Type: CommandTypeRetest, Payload: json.RawMessage(`{"scanner":"nuclei"}`)}, "nuclei"},
		{"validate", &Command{Type: CommandTypeValidate, Payload: json.RawMessage(`{"executor_kind":"Nuclei"}`)}, "nuclei"},
		{"no tool", &Command{Type: CommandTypeScan, Payload: json.RawMessage(`{"targets":["a"]}`)}, ""},
		{"nil", nil, ""},
	} {
		if got := JobTool(c.cmd); got != c.want {
			t.Errorf("%s: tool %q, want %q", c.name, got, c.want)
		}
	}
}

func TestRequireFeature(t *testing.T) {
	read := func(c *Command) []string {
		var p struct {
			F []string `json:"required_features"`
		}
		if err := json.Unmarshal(c.Payload, &p); err != nil {
			t.Fatal(err)
		}
		return p.F
	}
	c := &Command{Payload: json.RawMessage(`{"scanner":"x","big":12345678901234567890,"required_features":["net.confined@1"]}`)}
	if err := RequireFeature(c, "isolation.strong@1"); err != nil {
		t.Fatal(err)
	}
	if got := read(c); !slices.Equal(got, []string{"net.confined@1", "isolation.strong@1"}) {
		t.Fatalf("features %v: the list only grows", got)
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(c.Payload, &m)
	if string(m["big"]) != "12345678901234567890" {
		t.Fatalf("numbers are kept as written: %s", m["big"])
	}
	// Idempotent.
	if err := RequireFeature(c, "isolation.strong@1"); err != nil || len(read(c)) != 2 {
		t.Fatalf("second call: %v %v", err, read(c))
	}
	// A payload without the key gets one; a non-object is refused.
	d := &Command{Payload: json.RawMessage(`{"scanner":"x"}`)}
	if err := RequireFeature(d, "isolation.strong@1"); err != nil || !slices.Equal(read(d), []string{"isolation.strong@1"}) {
		t.Fatalf("new key: %v %v", err, read(d))
	}
	if err := RequireFeature(&Command{Payload: json.RawMessage(`[1]`)}, "x"); err == nil {
		t.Fatal("a payload that is not an object must be refused")
	}
}
