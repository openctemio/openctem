package sensor

import (
	"encoding/json"
	"testing"
)

func portScanJob(t *testing.T, payload string) Job {
	t.Helper()
	return JobOf("scan", json.RawMessage(payload))
}

func TestJobOf_PortScanFields(t *testing.T) {
	j := portScanJob(t, `{"scanner":"naabu","capability":"scan.ports@1","targets":["203.0.113.5"],"scanner_config":{"top_ports":"1000"}}`)
	if !j.PortScan || j.Ports != "" || j.TopPorts != "1000" {
		t.Fatalf("job %+v", j)
	}
	j = portScanJob(t, `{"scanner":"naabu","capability":"scan.ports@1","scanner_config":{"ports":"22,80"}}`)
	if j.Ports != "22,80" {
		t.Fatalf("scanner_config ports not read: %+v", j)
	}
	if portScanJob(t, `{"scanner":"nuclei","capability":"scan.web@1"}`).PortScan {
		t.Fatal("a web scan read as a port scan")
	}
}

func TestPortScanFill_IntersectsTheDefaultListWithPortsAllow(t *testing.T) {
	r := enforced(LocalPolicySummary{TargetsAllow: 1, Ports: "22,80,443-445,9000-9200"})
	job := portScanJob(t, `{"scanner":"naabu","capability":"scan.ports@1","targets":["203.0.113.5"]}`)
	got, ok := PortScanFill(r, job)
	if !ok || got != "22,80,443-445,9100" {
		t.Fatalf("fill = %q, %v", got, ok)
	}
	if NoAllowedPorts(r, job) || Accepts(r, job, DispatchOptions{}) != nil {
		t.Fatal("a port scan with allowed ports was refused")
	}

	// More than the top 100: every port is asked, so the fill is the allow list.
	job = portScanJob(t, `{"scanner":"naabu","capability":"scan.ports@1","targets":["203.0.113.5"],"config":{"top_ports":"1000"}}`)
	if got, ok := PortScanFill(r, job); !ok || got != "22,80,443-445,9000-9200" {
		t.Fatalf("top 1000 fill = %q, %v", got, ok)
	}
}

func TestPortScanFill_NoAllowedPortRefusesTheJob(t *testing.T) {
	r := enforced(LocalPolicySummary{TargetsAllow: 1, Ports: "60000-60010"})
	job := portScanJob(t, `{"scanner":"naabu","capability":"scan.ports@1","targets":["203.0.113.5"]}`)
	if _, ok := PortScanFill(r, job); ok {
		t.Fatal("filled ports the policy does not allow")
	}
	if !NoAllowedPorts(r, job) {
		t.Fatal("NoAllowedPorts = false")
	}
	ref := Accepts(r, job, DispatchOptions{})
	if ref == nil || ref.Rule != RulePortsAllow || ref.Layer != RefusalLayerLocal {
		t.Fatalf("refusal = %+v", ref)
	}
}

func TestPortScanFill_NothingToDecide(t *testing.T) {
	scan := portScanJob(t, `{"scanner":"naabu","capability":"scan.ports@1","targets":["203.0.113.5"]}`)
	named := portScanJob(t, `{"scanner":"naabu","capability":"scan.ports@1","targets":["203.0.113.5"],"config":{"ports":"22"}}`)
	web := portScanJob(t, `{"scanner":"nuclei","capability":"scan.web@1","targets":["203.0.113.5"]}`)
	for name, tc := range map[string]struct {
		r   *LocalPolicyReport
		job Job
	}{
		"no report":       {nil, scan},
		"absent policy":   {&LocalPolicyReport{State: LocalPolicyAbsent}, scan},
		"no ports.allow":  {enforced(LocalPolicySummary{TargetsAllow: 1}), scan},
		"named list":      {enforced(LocalPolicySummary{TargetsAllow: 1, Ports: "top-100"}), scan},
		"job names ports": {enforced(LocalPolicySummary{TargetsAllow: 1, Ports: "22"}), named},
		"not a port scan": {enforced(LocalPolicySummary{TargetsAllow: 1, Ports: "60000"}), web},
	} {
		if _, ok := PortScanFill(tc.r, tc.job); ok {
			t.Errorf("%s: filled", name)
		}
		if NoAllowedPorts(tc.r, tc.job) {
			t.Errorf("%s: refused", name)
		}
	}
}

func TestIntersectPortLists(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"1-100", "50-60,55-70,99-200", "50-70,99-100"},
		{"80", "81", ""},
		{"1-65535", "443", "443"},
		{"bad", "1", ""},
	} {
		if got := intersectPortLists(tc.a, tc.b); got != tc.want {
			t.Errorf("%s ∩ %s = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}
