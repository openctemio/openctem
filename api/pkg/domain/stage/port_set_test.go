package stage

import "testing"

// The platform names the port set of a port scan that names none; a scan
// that sets ports or top_n keeps it; other stages and tools that take no
// top_n are untouched; the input map is never changed.
func TestDefaultPortSet(t *testing.T) {
	ports, _ := Lookup(ScanPorts)
	hosts, _ := Lookup(DiscoverHosts)

	in := map[string]any{"rate": 500}
	got := ports.DefaultPortSet("naabu", in)
	if got["top_ports"] != DefaultTopPorts || got["rate"] != 500 {
		t.Fatalf("naabu without ports = %v, want top_ports %d", got, DefaultTopPorts)
	}
	if _, changed := in["top_ports"]; changed {
		t.Fatal("the input config was changed")
	}
	if got := ports.DefaultPortSet("naabu", nil); got["top_ports"] != DefaultTopPorts {
		t.Fatalf("nil config = %v", got)
	}
	for _, cfg := range []map[string]any{{"ports": "full"}, {"ports": "22,443"}, {"top_ports": 100}} {
		if got := ports.DefaultPortSet("naabu", cfg); got != nil {
			t.Errorf("config %v replaced by %v", cfg, got)
		}
	}
	if got := ports.DefaultPortSet("naabu", map[string]any{"ports": nil}); got["top_ports"] != DefaultTopPorts {
		t.Errorf("a null ports setting names no ports: %v", got)
	}
	if got := hosts.DefaultPortSet("naabu", nil); got != nil {
		t.Errorf("host discovery got a port set: %v", got)
	}
	if got := ports.DefaultPortSet("acme-scanner", nil); got != nil {
		t.Errorf("a tool the stage does not map got %v", got)
	}
	// A declared tool: its descriptor's keys.
	keyOf := func(p string) (string, bool) {
		k, ok := map[string]string{"top_n": "top", "ports": "port_list"}[p]
		return k, ok
	}
	if got := WithDefaultPortSet(ports, keyOf, nil); got["top"] != DefaultTopPorts {
		t.Errorf("declared tool = %v", got)
	}
	if got := WithDefaultPortSet(ports, keyOf, map[string]any{"port_list": "80"}); got != nil {
		t.Errorf("declared tool with its ports = %v", got)
	}
	noTop := func(p string) (string, bool) { return map[string]string{"ports": "p"}[p], p == "ports" }
	if got := WithDefaultPortSet(ports, noTop, nil); got != nil {
		t.Errorf("a tool that takes no top_n = %v", got)
	}
	if got := WithDefaultPortSet(ports, nil, nil); got != nil {
		t.Errorf("no key map = %v", got)
	}
}
