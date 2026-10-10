package ingest

// Set-valued asset attributes reconciled per source (RFC-069 §13): the IP
// addresses, technologies and open ports a report states about an asset are
// recorded as its source's observation, with the coverage the source looked
// at. Only the same source observing the same coverage again without an
// element removes it; a partial observation never removes what lies
// outside it. The asset shows the union of the trusted, fresh sources
// (internal/app/asset/attribute_sets.go).

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tooldom "github.com/openctemio/openctem/api/pkg/domain/tool"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SetReconciler records set observations and applies the sets they decide.
type SetReconciler interface {
	ReconcileSets(ctx context.Context, tenantID shared.ID, obs []asset.SetObservation) ([]asset.SetChange, error)
}

// dnsResolverTools report every address a name resolves to: their report
// is the whole set for that name.
var dnsResolverTools = []string{"dnsx", "massdns", "puredns", "shuffledns"}

// techFingerprintTools report every technology they detect on the asset:
// their report is the whole set for that asset.
var techFingerprintTools = []string{"httpx", "wappalyzer", "webanalyze", "whatweb"}

func toolIn(name string, list []string) bool {
	for _, t := range list {
		if tooldom.SameTool(name, t) {
			return true
		}
	}
	return false
}

// setCoverageFor is what an observation of attr from this report covered.
// Only an active check by a tool that reports the whole set covers it; any
// other report (an import, a feed, a tool that sees part of a set) only
// adds sightings, which leave through the TTL.
func setCoverageFor(attr asset.SetAttribute, kind asset.SourceKind, tool string, report *ctis.Report, b Binding) asset.SetCoverage {
	sightings := asset.SetCoverage{Mode: asset.CoverageSightings}
	if kind != asset.SourceKindScan {
		return sightings
	}
	switch attr {
	case asset.SetAttrIPAddresses:
		if toolIn(tool, dnsResolverTools) {
			return asset.SetCoverage{Mode: asset.CoverageFull}
		}
	case asset.SetAttrTechnologies:
		if toolIn(tool, techFingerprintTools) {
			return asset.SetCoverage{Mode: asset.CoverageFull}
		}
	case asset.SetAttrOpenPorts:
		if isPortScanReport(report) {
			return asset.PortScanCoverage(b.JobPorts, b.JobTopPorts)
		}
	}
	return sightings
}

// technologiesOf is the technologies a report asset states, or nil when it
// states none (not reporting is not "none").
func technologiesOf(a *ctis.Asset) ([]string, bool) {
	var out []string
	found := false
	for _, key := range []string{"technologies", "technology"} {
		if v, ok := a.Properties[key]; ok {
			found = true
			out = append(out, stringList(v)...)
		}
	}
	return out, found
}

// ipAddressesOf is the addresses a report asset states a name resolves to,
// without the asset's own address.
func ipAddressesOf(a *ctis.Asset) ([]string, bool) {
	found := false
	for _, k := range asset.AddressPropertyKeys() {
		if _, ok := a.Properties[k]; ok {
			found = true
			break
		}
	}
	if !found {
		return nil, false
	}
	self := strings.TrimSpace(a.Value)
	var out []string
	for _, ip := range asset.IPAddresses(a.Properties) {
		if ip != self {
			out = append(out, ip)
		}
	}
	return out, true
}

// recordSets records the IP addresses, technologies and open ports the
// report states about the assets it may change, and applies the sets they
// decide. Best-effort: a failure is logged and never fails the report.
func (s *Service) recordSets(ctx context.Context, tenantID shared.ID, scope *alterScope,
	src attributeSource, observedAt time.Time, report *ctis.Report, b Binding, assetMap map[string]shared.ID,
) {
	if s.sets == nil || report == nil || len(assetMap) == 0 {
		return
	}
	tool := src.name
	if report.Tool != nil && report.Tool.Name != "" {
		tool = report.Tool.Name
	}
	created := createdPortElements(scope)
	var obs []asset.SetObservation
	add := func(id shared.ID, attr asset.SetAttribute, elems []string, cov asset.SetCoverage, made []string) {
		obs = append(obs, asset.SetObservation{
			AssetID: id, Attribute: attr, Kind: src.kind, Name: src.name, SourceRun: src.run,
			ObservedAt: observedAt, Coverage: cov, Elements: elems, Created: made,
		})
	}
	for i := range report.Assets {
		a := &report.Assets[i]
		id, ok := assetMap[a.ID]
		if !ok || id.IsZero() || !scope.allowedAsset(id) {
			continue
		}
		if ips, ok := ipAddressesOf(a); ok {
			add(id, asset.SetAttrIPAddresses, ips, setCoverageFor(asset.SetAttrIPAddresses, src.kind, tool, report, b), nil)
		}
		if techs, ok := technologiesOf(a); ok {
			add(id, asset.SetAttrTechnologies, techs, setCoverageFor(asset.SetAttrTechnologies, src.kind, tool, report, b), nil)
		}
		if host := reportHost(a); host != "" && a.Type == ctis.AssetTypeIPAddress {
			ports := openPortsOf(a)
			elems := make([]string, 0, len(ports))
			for _, p := range ports {
				elems = append(elems, strconv.Itoa(p.Port)+"/"+p.Protocol)
			}
			cov := setCoverageFor(asset.SetAttrOpenPorts, src.kind, tool, report, b)
			if len(ports) >= maxPortsPerHost {
				cov = asset.SetCoverage{Mode: asset.CoverageSightings} // truncated: not the whole set
			}
			if len(elems) > 0 || cov.Mode != asset.CoverageSightings {
				add(id, asset.SetAttrOpenPorts, elems, cov, created[portHostKey(host)])
			}
		}
		if len(obs) >= maxAttributeObservationsPerReport {
			break
		}
	}
	if len(obs) == 0 {
		return
	}
	if _, err := s.sets.ReconcileSets(ctx, tenantID, obs); err != nil {
		s.logger.Warn("asset set attributes not reconciled", "tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
	}
}

// portHostKey is the host part of an open_port asset's stored name for an
// address.
func portHostKey(host string) string {
	k := portKey(portAssetName(host, 1, "tcp"))
	if i := strings.LastIndex(k, ":"); i > 0 {
		if j := strings.LastIndex(k[:i], ":"); j > 0 {
			return k[:j]
		}
	}
	return host
}

// createdPortElements are the open ports ("443/tcp") whose open_port asset
// this ingest created, by host part of the stored name.
func createdPortElements(scope *alterScope) map[string][]string {
	out := map[string][]string{}
	if scope == nil {
		return out
	}
	for _, sa := range scope.seen {
		if !sa.created || sa.typ.Type != asset.AssetTypeService || sa.typ.SubType != "open_port" {
			continue
		}
		i := strings.LastIndex(sa.name, ":")
		if i <= 0 {
			continue
		}
		j := strings.LastIndex(sa.name[:i], ":")
		if j <= 0 {
			continue
		}
		e, err := asset.NormalizeSetElement(asset.SetAttrOpenPorts, sa.name[j+1:i]+"/"+sa.name[i+1:])
		if err != nil {
			continue
		}
		out[sa.name[:j]] = append(out[sa.name[:j]], e)
	}
	return out
}

// keepReconciledSets keeps, in props merged from a report into an existing
// asset, the existing asset's IP addresses and technologies: the report's
// values are recorded as its source's observation and the asset shows what
// set reconciliation resolves, not what the latest report said.
func keepReconciledSets(existing, merged map[string]any) {
	if ips := asset.IPAddresses(existing); len(ips) > 0 {
		list := make([]any, 0, len(ips))
		for _, ip := range ips {
			list = append(list, ip)
		}
		merged[asset.PropKeyIPAddresses] = list
	} else {
		delete(merged, asset.PropKeyIPAddresses)
	}
	if v, ok := existing["technologies"]; ok {
		merged["technologies"] = v
	} else {
		delete(merged, "technologies")
	}
}
