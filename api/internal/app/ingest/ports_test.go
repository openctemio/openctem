package ingest

import (
	"fmt"
	"testing"

	"github.com/openctemio/ctis/v2"
)

func svcAsset(id, value string, state ctis.PortState) ctis.Asset {
	a := ctis.Asset{ID: id, Type: ctis.AssetTypeService, Value: value}
	if state != "" {
		a.Technical = &ctis.AssetTechnical{Service: &ctis.ServiceTechnical{State: state}}
	}
	return a
}

// Open ports come from the service assets of the report: a port scanner's
// output is hostile input (closed or filtered states, duplicates, non-address
// hosts, floods are bounded).
func TestServicePortsByHost(t *testing.T) {
	rep := &ctis.Report{Tool: &ctis.Tool{Name: "naabu"}, Assets: []ctis.Asset{
		svcAsset("s1", "203.0.113.5:80/tcp", ctis.PortOpen),
		svcAsset("s2", "203.0.113.5:443/tcp", ""), // unset state counts as open
		svcAsset("s3", "203.0.113.5:80/tcp", ""),  // duplicate
		svcAsset("s4", "203.0.113.5:22/tcp", ctis.PortClosed),
		svcAsset("s5", "203.0.113.5:25/tcp", ctis.PortFiltered),
		svcAsset("s6", "[2001:db8::1]:8443/tcp", ""),
		svcAsset("s7", "[2001:db8::1]:53/udp", ""),
		svcAsset("s8", "example.com:80/tcp", ""), // a name is not an address
		{ID: "ip", Type: ctis.AssetTypeIPAddress, Value: "203.0.113.5"},
	}}
	got := servicePortsByHost(rep)
	v4 := got["203.0.113.5"]
	if len(v4) != 2 || v4[0] != (reportPort{80, "tcp"}) || v4[1] != (reportPort{443, "tcp"}) {
		t.Fatalf("v4 ports = %v (closed, filtered and duplicate ports must be skipped)", v4)
	}
	v6 := got["2001:db8::1"]
	if len(v6) != 2 || v6[0] != (reportPort{8443, "tcp"}) || v6[1] != (reportPort{53, "udp"}) {
		t.Fatalf("v6 ports = %v", v6)
	}
	if _, ok := got["example.com"]; ok {
		t.Fatalf("a name must not be grouped: %v", got)
	}
	if len(servicePortsByHost(nil)) != 0 {
		t.Fatal("nil report must give no ports")
	}
}

func TestServicePortsByHost_Bounded(t *testing.T) {
	rep := &ctis.Report{}
	for i := 1; i <= maxPortsPerHost+500; i++ {
		rep.Assets = append(rep.Assets, svcAsset(fmt.Sprintf("s%d", i), fmt.Sprintf("198.51.100.1:%d/tcp", i), ""))
	}
	if n := len(servicePortsByHost(rep)["198.51.100.1"]); n != maxPortsPerHost {
		t.Fatalf("one host listed %d ports, want %d", n, maxPortsPerHost)
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
