package command

import (
	"encoding/json"
	"slices"
	"testing"
)

func denyOf(t *testing.T, payload json.RawMessage) ([]string, bool) {
	t.Helper()
	var p struct {
		WebScope map[string]json.RawMessage `json:"web_scope"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	_, leaked := p.WebScope["deny_paths_wildcard"]
	var list []string
	_ = json.Unmarshal(p.WebScope["deny_paths"], &list)
	return list, leaked
}

// SECURITY: a sensor that reads "*" deny segments is sent the written form;
// every other sensor the cut form (which blocks the whole subtree, never
// less). The platform-only key never reaches a sensor, either way, and the
// rest of the payload is untouched.
func TestWebScopeDelivery(t *testing.T) {
	payload := json.RawMessage(`{"scanner":"nuclei","n":12345678901234567890,"web_scope":{"deny_paths":["/tenants/"],"deny_paths_wildcard":["/tenants/*/admin"],"methods":["GET"]}}`)
	cut, err := webScopeDelivery(payload, false)
	if err != nil {
		t.Fatal(err)
	}
	if d, leaked := denyOf(t, cut); !slices.Equal(d, []string{"/tenants/"}) || leaked {
		t.Fatalf("older sensor: %v leaked=%v", d, leaked)
	}
	wild, err := webScopeDelivery(payload, true)
	if err != nil {
		t.Fatal(err)
	}
	if d, leaked := denyOf(t, wild); !slices.Equal(d, []string{"/tenants/*/admin"}) || leaked {
		t.Fatalf("newer sensor: %v leaked=%v", d, leaked)
	}
	var m map[string]json.RawMessage
	_ = json.Unmarshal(wild, &m)
	if string(m["n"]) != "12345678901234567890" || string(m["scanner"]) != `"nuclei"` {
		t.Fatalf("the rest of the payload changed: %s", wild)
	}
	// Without the key: unchanged bytes.
	plain := json.RawMessage(`{"web_scope":{"deny_paths":["/admin"]}}`)
	if got, err := webScopeDelivery(plain, true); err != nil || string(got) != string(plain) {
		t.Fatalf("%s %v", got, err)
	}
	// A web scope that cannot be read: refused, never delivered with the key.
	if _, err := webScopeDelivery(json.RawMessage(`{"web_scope":"x","deny_paths_wildcard":1}`), true); err == nil {
		t.Fatal("an unreadable web scope was delivered")
	}
}
