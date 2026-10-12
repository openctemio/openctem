package ingest

import (
	"fmt"
	"testing"

	"github.com/openctemio/ctis"
)

func ipAsset(value string, ports ...ctis.PortInfo) ctis.Asset {
	return ctis.Asset{ID: "ip", Type: ctis.AssetTypeIPAddress, Value: value,
		Technical: &ctis.AssetTechnical{IPAddress: &ctis.IPAddressTechnical{Ports: ports}}}
}

// research/22 P0-6: open ports on an address become open_port assets; the
// sensor's port list is hostile input (bad numbers, closed or filtered
// states, duplicates, non-address values, floods are bounded).
func TestExpandOpenPorts(t *testing.T) {
	rep := &ctis.Report{Tool: &ctis.Tool{Name: "naabu"}, Assets: []ctis.Asset{
		ipAsset("203.0.113.5",
			ctis.PortInfo{Port: 80, Protocol: "TCP", State: "open", Service: "http"},
			ctis.PortInfo{Port: 80, Protocol: "tcp"},   // duplicate
			ctis.PortInfo{Port: 443},                   // protocol defaults to tcp
			ctis.PortInfo{Port: 0},                     // invalid
			ctis.PortInfo{Port: 70000},                 // invalid
			ctis.PortInfo{Port: 22, State: "closed"},   // not open
			ctis.PortInfo{Port: 25, State: "filtered"}, // not open
		),
		ipAsset("not-an-ip", ctis.PortInfo{Port: 80}), // a name is never expanded
		ipAsset("2001:db8::1", ctis.PortInfo{Port: 8443}, ctis.PortInfo{Port: 9000}),
		{ID: "p", Type: ctis.AssetTypeOpenPort, Value: "[2001:db8::1]:9000:tcp"}, // already reported
	}}
	added := expandOpenPorts(rep)
	got := map[string]ctis.Properties{}
	for _, a := range rep.Assets {
		if a.Type == ctis.AssetTypeOpenPort {
			got[a.Value] = a.Properties
		}
	}
	for _, want := range []string{"203.0.113.5:80/tcp", "203.0.113.5:443/tcp", "[2001:db8::1]:8443/tcp"} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s in %v", want, got)
		}
	}
	if added != 3 {
		t.Fatalf("added = %d, want 3 (%v)", added, got)
	}
	p := got["203.0.113.5:80/tcp"]
	if p["port"] != 80 || p["protocol"] != "tcp" || p["service"] != "http" || p["host"] != "203.0.113.5" || p["discovery_tool"] != "naabu" {
		t.Fatalf("properties = %v", p)
	}
	if expandOpenPorts(rep) != 0 {
		t.Fatal("expanding twice added port assets again")
	}
}

func TestExpandOpenPorts_Bounded(t *testing.T) {
	var ports []ctis.PortInfo
	for i := 1; i <= 5000; i++ {
		ports = append(ports, ctis.PortInfo{Port: i})
	}
	rep := &ctis.Report{Assets: []ctis.Asset{ipAsset("198.51.100.1", ports...)}}
	if n := expandOpenPorts(rep); n != maxPortsPerHost {
		t.Fatalf("one host expanded to %d ports, want %d", n, maxPortsPerHost)
	}
	rep = &ctis.Report{}
	for h := 0; h < 20; h++ {
		rep.Assets = append(rep.Assets, ipAsset(fmt.Sprintf("198.51.100.%d", h+1), ports[:maxPortsPerHost]...))
	}
	if n := expandOpenPorts(rep); n != maxPortsPerReport {
		t.Fatalf("report expanded to %d ports, want %d", n, maxPortsPerReport)
	}
}

func TestIsPortScanReport(t *testing.T) {
	for name, want := range map[string]bool{"naabu": true, "Nmap": true, "masscan": true, "httpx": false, "nuclei": false} {
		if got := isPortScanReport(&ctis.Report{Tool: &ctis.Tool{Name: name}}); got != want {
			t.Errorf("%s: %v", name, got)
		}
	}
	if isPortScanReport(&ctis.Report{}) || isPortScanReport(nil) {
		t.Fatal("a report without a tool is not a port scan")
	}
}
