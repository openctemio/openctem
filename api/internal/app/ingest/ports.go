package ingest

// Port and service results surfaced (research/22 P0-6, bug 22c B6).
//
// A port scanner (naabu, nmap, masscan, rustscan) reports an IP address with
// the open ports it found. Those ports used to land only in the address's
// properties: no service row, no port_open exposure, no relationship and no
// history, so a newly opened port was recorded and never surfaced. Now:
//
//   - each open port becomes an open_port service asset "<ip>:<port>"
//     (expandOpenPorts adds it to the report, so it goes through the same
//     exclusions, attribution and scope rules as any reported asset, and the
//     exposure bridge projects it to port_open);
//   - the address gets an `exposes` edge to each port, and a host name the
//     scanner reported gets a `resolves_to` edge to the address when the
//     tenant already has that name as a domain or subdomain asset (a sensor
//     report never creates a name here);
//   - a port is closed only when the port scan that found it open scans the
//     same range of the address again without it (per-source set
//     reconciliation, attribute_sets.go, RFC-069): its asset goes inactive
//     with a "disappeared" history entry and its port_open exposure is
//     resolved. A partial scan never closes a port outside its range. A
//     port that comes back is reopened.
//
// Architecture: docs/architecture/easm.md.

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/capability"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
)

// Bounds on what one report may expand into port assets.
const (
	maxPortsPerHost   = 1000
	maxPortsPerReport = 10000
)

// portScanTools are the scanners whose report for an address lists every
// port they found open on it, so a port missing from it is closed.
var portScanTools = []string{"naabu", "nmap", "masscan", "rustscan"}

// isPortScanReport reports whether the report comes from a port scanner:
// its bound capability is scan.ports (set by the output binding from the
// command's tool, never taken from the sensor alone), or, for a report
// without one, its tool is a known port scanner.
func isPortScanReport(report *ctis.Report) bool {
	if report == nil {
		return false
	}
	if id, _, ok := capability.ParseRef(report.Metadata.Capability); ok && id == string(stage.ScanPorts) {
		return true
	}
	if report.Tool == nil {
		return false
	}
	for _, t := range portScanTools {
		if tooldom.SameTool(report.Tool.Name, t) {
			return true
		}
	}
	return false
}

// portAssetName is the reported name of the open_port asset of host, port
// and protocol ("203.0.113.5:443/tcp", "[2001:db8::1]:443/tcp").
func portAssetName(host string, port int, proto string) string {
	return net.JoinHostPort(host, fmt.Sprint(port)) + "/" + proto
}

// portKey is the name an open_port asset is stored under (the inventory's
// normalization: "host:port:proto"), used to match report ports to assets.
func portKey(name string) string {
	return asset.NormalizeName(name, asset.AssetTypeService, "open_port")
}

// openPortsOf returns the open ports an IP address asset of the report lists
// (state open or unset), deduplicated, at most maxPortsPerHost.
func openPortsOf(a *ctis.Asset) []ctis.PortInfo {
	if a == nil || a.Type != ctis.AssetTypeIPAddress || a.Technical == nil || a.Technical.IPAddress == nil {
		return nil
	}
	seen := map[string]bool{}
	out := make([]ctis.PortInfo, 0, len(a.Technical.IPAddress.Ports))
	for _, p := range a.Technical.IPAddress.Ports {
		if p.Port <= 0 || p.Port > 65535 {
			continue
		}
		if st := strings.ToLower(strings.TrimSpace(p.State)); st != "" && st != "open" {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(p.Protocol))
		if proto == "" {
			proto = "tcp"
		}
		key := fmt.Sprintf("%d/%s", p.Port, proto)
		if seen[key] {
			continue
		}
		seen[key] = true
		p.Protocol = proto
		out = append(out, p)
		if len(out) >= maxPortsPerHost {
			break
		}
	}
	return out
}

// reportHost is the address an IP asset of the report names.
func reportHost(a *ctis.Asset) string {
	h := strings.TrimSpace(a.Value)
	if h == "" {
		h = strings.TrimSpace(a.Name)
	}
	if net.ParseIP(h) == nil {
		return ""
	}
	return h
}

// expandOpenPorts adds an open_port asset for every open port an IP address
// asset of the report lists, unless the report already has one of that name.
// It returns how many it added.
func expandOpenPorts(report *ctis.Report) int {
	if report == nil {
		return 0
	}
	present := map[string]bool{}
	for i := range report.Assets {
		if report.Assets[i].Type == ctis.AssetTypeOpenPort {
			present[portKey(getAssetName(&report.Assets[i]))] = true
		}
	}
	tool := ""
	if report.Tool != nil {
		tool = report.Tool.Name
	}
	added := 0
	n := len(report.Assets)
	for i := 0; i < n && added < maxPortsPerReport; i++ {
		ip := &report.Assets[i]
		host := reportHost(ip)
		if host == "" {
			continue
		}
		for _, p := range openPortsOf(ip) {
			name := portAssetName(host, p.Port, p.Protocol)
			if present[portKey(name)] {
				continue
			}
			present[portKey(name)] = true
			props := ctis.Properties{
				"host":           host,
				"port":           p.Port,
				"protocol":       p.Protocol,
				"discovery_tool": tool,
			}
			if p.Service != "" {
				props["service"] = p.Service
			}
			if p.Version != "" {
				props["version"] = p.Version
			}
			report.Assets = append(report.Assets, ctis.Asset{
				ID:           "port-" + strings.NewReplacer(":", "-", "/", "-", "[", "", "]", "").Replace(name),
				Type:         ctis.AssetTypeOpenPort,
				Value:        name,
				Name:         name,
				Criticality:  ip.Criticality,
				Confidence:   ip.Confidence,
				DiscoveredAt: ip.DiscoveredAt,
				Properties:   props,
			})
			added++
			if added >= maxPortsPerReport {
				break
			}
		}
	}
	return added
}

// portHost is one address of the report and the ports seen open on it now.
type portHost struct {
	host, hostname string
	ports          map[string]bool // port asset keys (portKey)
}

// surfacePorts links the report's addresses to their ports and names.
// Which ports stay open is decided per source by set reconciliation
// (attribute_sets.go): a port closes when the port scan that found it scans
// the same range of the address again without it. Best effort: the assets
// are stored; a failure here is logged.
func (p *AssetProcessor) surfacePorts(ctx context.Context, tenantID shared.ID, report *ctis.Report,
	existingMap map[string]*asset.Asset, mayChange func(shared.ID) bool,
) {
	hosts := make([]portHost, 0, len(report.Assets))
	for i := range report.Assets {
		a := &report.Assets[i]
		host := reportHost(a)
		if host == "" {
			continue
		}
		hp := portHost{host: host, ports: map[string]bool{}}
		if a.Technical != nil && a.Technical.IPAddress != nil {
			hp.hostname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a.Technical.IPAddress.Hostname), "."))
		}
		for _, port := range openPortsOf(a) {
			hp.ports[portKey(portAssetName(host, port.Port, port.Protocol))] = true
		}
		hosts = append(hosts, hp)
	}
	if len(hosts) == 0 {
		return
	}
	p.linkPorts(ctx, tenantID, hosts, existingMap)
}

// linkPorts creates address → port `exposes` edges and host name → address
// `resolves_to` edges, between assets that exist.
func (p *AssetProcessor) linkPorts(ctx context.Context, tenantID shared.ID, hosts []portHost, existingMap map[string]*asset.Asset) {
	if p.relRepo == nil {
		return
	}
	var rels []*asset.Relationship
	var hostnames []string
	for _, h := range hosts {
		if h.hostname != "" && h.hostname != h.host {
			hostnames = append(hostnames, h.hostname)
		}
	}
	names := map[string]*asset.Asset{}
	if len(hostnames) > 0 {
		found, err := p.repo.GetByNames(ctx, tenantID, hostnames)
		if err != nil {
			p.logger.Warn("ingest: host names not resolved for resolves_to", "error", err)
		} else {
			names = found
		}
	}
	for _, h := range hosts {
		ipAsset, ok := existingMap[h.host]
		if !ok {
			continue
		}
		for name := range h.ports {
			portAsset, ok := existingMap[name]
			if !ok {
				continue
			}
			if rel, err := asset.NewRelationship(tenantID, ipAsset.ID(), portAsset.ID(), asset.RelTypeExposes); err == nil {
				rel.SetDescription(fmt.Sprintf("%s exposes %s", h.host, name))
				_ = rel.SetDiscoveryMethod(asset.DiscoveryAutomatic)
				rels = append(rels, rel)
			}
		}
		if n, ok := names[h.hostname]; ok && n != nil && n.TenantID() == tenantID &&
			(n.Type() == asset.AssetTypeDomain || n.Type() == asset.AssetTypeSubdomain) {
			if rel, err := asset.NewRelationship(tenantID, n.ID(), ipAsset.ID(), asset.RelTypeResolvesTo); err == nil {
				rel.SetDescription(fmt.Sprintf("%s resolves to %s", h.hostname, h.host))
				_ = rel.SetDiscoveryMethod(asset.DiscoveryAutomatic)
				rel.Verify()
				rels = append(rels, rel)
			}
		}
	}
	if len(rels) == 0 {
		return
	}
	if _, err := p.relRepo.CreateBatchIgnoreConflicts(ctx, rels); err != nil {
		p.logger.Warn("ingest: port relationships not created", "error", err)
	}
}
