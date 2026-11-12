package ingest

// Port and service results surfaced (research/22 P0-6, bug 22c B6).
//
// A port scanner (naabu, nmap, masscan, rustscan) reports, in CTIS 2.0, an
// IP address and one `service` asset per open port ("<ip>:<port>/<transport>",
// linked from the address by an `exposes` relationship). Each is stored as an
// open_port service asset and goes through the same exclusions, attribution
// and scope rules as any reported asset; the exposure bridge projects it to
// port_open. Then:
//
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
	"strconv"
	"strings"

	"github.com/openctemio/contract/capability"
	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/stage"
	tooldom "github.com/openctemio/openctem/server/pkg/domain/tool"
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
	if id, _, ok := capability.ParseRef(reportCapability(report)); ok && id == string(stage.ScanPorts) {
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

// portAssetName is the CTIS 2.0 value of the service asset of host, port
// and transport ("203.0.113.5:443/tcp", "[2001:db8::1]:443/tcp").
func portAssetName(host string, port int, proto string) string {
	return net.JoinHostPort(host, strconv.Itoa(port)) + "/" + proto
}

// portKey is the name an open_port asset is stored under (the inventory's
// normalization: "host:port:proto"), used to match report ports to assets.
func portKey(name string) string {
	return asset.NormalizeName(name, asset.AssetTypeService, "open_port")
}

// reportPort is one open port a service asset of the report names.
type reportPort struct {
	Port      int
	Transport string
}

// servicePortsByHost groups the report's service assets by the address in
// their value: the open ports (state open or unset) each address exposes,
// deduplicated, at most maxPortsPerHost per address.
func servicePortsByHost(report *ctis.Report) map[string][]reportPort {
	out := map[string][]reportPort{}
	if report == nil {
		return out
	}
	seen := map[string]bool{}
	for i := range report.Assets {
		a := &report.Assets[i]
		if a.Type != ctis.AssetTypeService {
			continue
		}
		if a.Technical != nil && a.Technical.Service != nil {
			if st := a.Technical.Service.State; st != "" && st != ctis.PortOpen {
				continue
			}
		}
		host, port, transport, ok := splitServiceValue(a.Value)
		if !ok || net.ParseIP(host) == nil {
			continue
		}
		key := host + " " + strconv.Itoa(port) + "/" + transport
		if seen[key] || len(out[host]) >= maxPortsPerHost {
			continue
		}
		seen[key] = true
		out[host] = append(out[host], reportPort{Port: port, Transport: transport})
	}
	return out
}

// splitServiceValue parses a CTIS 2.0 service value "host:port/transport"
// ("[v6]:port/transport").
func splitServiceValue(v string) (host string, port int, transport string, ok bool) {
	hp, tr, found := strings.Cut(strings.TrimSpace(v), "/")
	if !found || tr == "" {
		return "", 0, "", false
	}
	h, ps, err := net.SplitHostPort(hp)
	if err != nil {
		return "", 0, "", false
	}
	n, err := strconv.Atoi(ps)
	if err != nil || n <= 0 || n > 65535 {
		return "", 0, "", false
	}
	return h, n, strings.ToLower(tr), true
}

// reportHost is the address an IP asset of the report names.
func reportHost(a *ctis.Asset) string {
	h := strings.TrimSpace(a.Value)
	if net.ParseIP(h) == nil {
		return ""
	}
	return h
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
	existingMap map[string]*asset.Asset, mayChange func(shared.ID) bool, mayAlterStored func(*asset.Asset) bool,
) {
	byHost := servicePortsByHost(report)
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
		for _, port := range byHost[host] {
			hp.ports[portKey(portAssetName(host, port.Port, port.Transport))] = true
		}
		hosts = append(hosts, hp)
	}
	if len(hosts) == 0 {
		return
	}
	p.linkPorts(ctx, tenantID, hosts, existingMap, mayChange, mayAlterStored)
}

// linkPorts creates address → port `exposes` edges and host name → address
// `resolves_to` edges, between assets that exist. An edge changes its source
// (RFC-040 §5.3), so it is added only when this report may change that
// source: an address outside a bound command's targets or that the
// uploading actor may not change gains no port edge, and a stored host name
// outside them gains no resolves_to edge. mayChange decides the report's own
// assets; mayAlterStored decides a stored name the report only mentions.
func (p *AssetProcessor) linkPorts(ctx context.Context, tenantID shared.ID, hosts []portHost,
	existingMap map[string]*asset.Asset, mayChange func(shared.ID) bool, mayAlterStored func(*asset.Asset) bool,
) {
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
		if !ok || (mayChange != nil && !mayChange(ipAsset.ID())) {
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
				// Seen now: a rescan refreshes when the edge was last seen.
				rel.Verify()
				rels = append(rels, rel)
			}
		}
		if n, ok := names[h.hostname]; ok && n != nil && n.TenantID() == tenantID &&
			(n.Type() == asset.AssetTypeDomain || n.Type() == asset.AssetTypeSubdomain) &&
			(mayAlterStored == nil || mayAlterStored(n)) {
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
