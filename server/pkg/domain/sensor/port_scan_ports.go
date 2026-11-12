package sensor

// Ports of a port scan on a sensor whose local policy lists ports.allow
// (docs/architecture/sensor-local-policy.md, "Port scans"). Such a sensor
// refuses a port-scan job that names no ports, because the tool would run
// its own default list, which the policy cannot check. The platform fills
// the job's ports, at delivery, with the ports the scan would probe that
// the policy allows; when there are none, the job is not sent. The sensor
// stays the enforcer: this only avoids jobs it would refuse.

import (
	"slices"
	"strconv"
	"strings"
)

// CapabilityScanPorts is the capability of a port scan ("scan.ports@1").
const CapabilityScanPorts = "scan.ports"

// DefaultPortScanPorts is the list a port scan that names no ports probes:
// the 100 most common TCP ports, the default list of the port scanners the
// platform runs. A scan that asks for more than 100 top ports, or for all
// ports, probes 1-65535.
const DefaultPortScanPorts = "7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427," +
	"443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900," +
	"2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666," +
	"5800,5900,6000-6001,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9999-10000,32768,49152-49157"

// allPorts is every TCP port.
const allPorts = "1-65535"

// NoAllowedPortsDetail is the reason a port scan is not sent to a sensor
// whose local policy allows none of the ports it would probe.
const NoAllowedPortsDetail = "the sensor's local policy allows none of the ports the port scan would probe"

// requestedPorts is the list a port-scan job without a ports setting
// probes: the default list, or every port for a top-N above 100 or "full".
func requestedPorts(job Job) string {
	t := strings.ToLower(strings.TrimSpace(job.TopPorts))
	if t == "full" || t == "all" {
		return allPorts
	}
	if n, err := strconv.Atoi(strings.TrimPrefix(t, "top-")); err == nil && n > 100 {
		return allPorts
	}
	return DefaultPortScanPorts
}

// policyPortsFor is the sensor's port allow list when it decides job: a
// port scan with no ports setting, on a sensor that enforces a local
// policy with a readable ports.allow. "" otherwise.
func policyPortsFor(r *LocalPolicyReport, job Job) string {
	if !job.PortScan || job.Ports != "" || !r.Enforced() || r.Summary == nil {
		return ""
	}
	p := strings.TrimSpace(r.Summary.Ports)
	if _, ok := parsePortList(p); !ok {
		return ""
	}
	return p
}

// PortScanFill returns the ports to set on job for a sensor whose last
// report is r: the requested ports its ports.allow allows, as a list
// ("22,80,443-445"). ok is false when there is nothing to fill: the job is
// not a port scan without ports, the sensor lists no readable ports.allow,
// or no requested port is allowed (NoAllowedPorts).
func PortScanFill(r *LocalPolicyReport, job Job) (string, bool) {
	allowed := policyPortsFor(r, job)
	if allowed == "" {
		return "", false
	}
	out := intersectPortLists(requestedPorts(job), allowed)
	return out, out != ""
}

// NoAllowedPorts reports whether job is a port scan without ports for which
// the sensor's ports.allow allows none of the requested ports: the job must
// not be sent to that sensor.
func NoAllowedPorts(r *LocalPolicyReport, job Job) bool {
	allowed := policyPortsFor(r, job)
	return allowed != "" && intersectPortLists(requestedPorts(job), allowed) == ""
}

// intersectPortLists returns the ports in both lists, as sorted ranges; ""
// when they share none or either cannot be read.
func intersectPortLists(a, b string) string {
	ra, ok := parsePortList(a)
	if !ok {
		return ""
	}
	rb, ok := parsePortList(b)
	if !ok {
		return ""
	}
	ra, rb = mergeRanges(ra), mergeRanges(rb)
	var parts []string
	for i, j := 0, 0; i < len(ra) && j < len(rb); {
		lo, hi := max(ra[i].lo, rb[j].lo), min(ra[i].hi, rb[j].hi)
		switch {
		case lo == hi:
			parts = append(parts, strconv.Itoa(lo))
		case lo < hi:
			parts = append(parts, strconv.Itoa(lo)+"-"+strconv.Itoa(hi))
		}
		if ra[i].hi < rb[j].hi {
			i++
		} else {
			j++
		}
	}
	return strings.Join(parts, ",")
}

// mergeRanges sorts rs and joins the ranges that overlap or touch.
func mergeRanges(rs []portRange) []portRange {
	sorted := slices.Clone(rs)
	slices.SortFunc(sorted, func(x, y portRange) int { return x.lo - y.lo })
	out := make([]portRange, 0, len(sorted))
	for _, r := range sorted {
		if n := len(out); n > 0 && r.lo <= out[n-1].hi+1 {
			out[n-1].hi = max(out[n-1].hi, r.hi)
			continue
		}
		out = append(out, r)
	}
	return out
}
