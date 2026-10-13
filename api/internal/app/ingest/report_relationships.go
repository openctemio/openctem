package ingest

// Report relationships (docs/architecture/sensors.md, "Collector sensors"): the typed
// edges a report states between its own assets (CTIS `relationships`), and
// the placement an inventory collector reports as properties (a virtual
// machine's hypervisor host, the addresses of a host), stored as asset
// relationships so the graph and attack paths can follow them.
//
// Every edge stays inside the tenant: both ends are assets this ingest
// persisted in the tenant or found there by a tenant-scoped lookup. An edge
// changes its source asset, so it is added only when the report may change
// that source (an existing asset outside a bound command's targets, or any
// existing asset of an unsolicited report, adds nothing). An edge that the
// relationship registry does not allow for the two stored types is dropped,
// never guessed. Writing an edge again only refreshes when it was last seen.

import (
	"context"
	"fmt"
	"strings"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	// propHypervisorHost is the property in which an inventory collector
	// names the hypervisor host a virtual machine runs on.
	propHypervisorHost = "esxi_host"
	// maxAddressEdgesPerHost bounds the address edges one host adds: a
	// hostile report cannot make one asset fan out to every address.
	maxAddressEdgesPerHost = 32
)

// plannedEdge is one relationship to store, by persisted asset.
type plannedEdge struct {
	src, dst *asset.Asset
	relType  asset.RelationshipType
	desc     string
}

// mapReportRelationship turns a CTIS relationship between two stored assets
// into the platform's (type, source, target), or ok=false when there is no
// fitting type. A subdomain_of edge is stored parent first (contains), as
// the registry keeps one direction for hierarchy; an address hosted by a
// host is stored as the host containing the address.
func mapReportRelationship(t ctis.RelationshipType, from, to *asset.Asset) (asset.RelationshipType, *asset.Asset, *asset.Asset, bool) {
	switch t {
	case ctis.RelSubdomainOf:
		return asset.RelTypeContains, to, from, true
	case ctis.RelResolvesTo:
		return asset.RelTypeResolvesTo, from, to, true
	case ctis.RelCnameOf:
		return asset.RelTypeCnameOf, from, to, true
	case ctis.RelExposes:
		return asset.RelTypeExposes, from, to, true
	case ctis.RelServesCertificate:
		return asset.RelTypeServesCertificate, from, to, true
	case ctis.RelHostedBy:
		if from.Type() == asset.AssetTypeIPAddress {
			return asset.RelTypeContains, to, from, true
		}
		return asset.RelTypeRunsOn, from, to, true
	}
	return "", nil, nil, false
}

// edgeAllowed reports whether the registry allows relType between the two
// stored assets.
func edgeAllowed(relType asset.RelationshipType, src, dst *asset.Asset) bool {
	return asset.RelationshipAllowed(relType,
		asset.TypeRef{Type: src.Type(), SubType: src.SubType()},
		asset.TypeRef{Type: dst.Type(), SubType: dst.SubType()})
}

// storedReportAssets maps each report asset id to the asset this ingest
// stored it as (created or matched), in the tenant.
func storedReportAssets(tenantID shared.ID, report *ctis.Report, existingMap map[string]*asset.Asset,
	assetMap map[string]shared.ID,
) map[string]*asset.Asset {
	out := make(map[string]*asset.Asset, len(assetMap))
	for i := range report.Assets {
		ca := &report.Assets[i]
		id, ok := assetMap[ca.ID]
		if !ok || ca.ID == "" {
			continue
		}
		rt := resolveCTISAssetType(ca)
		name := asset.NormalizeName(getAssetName(ca), rt.normType, rt.normSubType)
		if a, ok := existingMap[name]; ok && a.ID() == id && a.TenantID() == tenantID {
			out[ca.ID] = a
		}
	}
	return out
}

// planReportRelationships plans the edges of report.Relationships whose
// source the report may change.
func planReportRelationships(report *ctis.Report, stored map[string]*asset.Asset, mayChange func(shared.ID) bool) []plannedEdge {
	out := make([]plannedEdge, 0, min(len(report.Relationships), ctis.MaxRelationships))
	for i, rel := range report.Relationships {
		if i >= ctis.MaxRelationships {
			break
		}
		from, to := stored[rel.FromRef], stored[rel.ToRef]
		if from == nil || to == nil || from.ID() == to.ID() {
			continue
		}
		relType, src, dst, ok := mapReportRelationship(rel.Type, from, to)
		if !ok || !mayChange(src.ID()) || !edgeAllowed(relType, src, dst) {
			continue
		}
		out = append(out, plannedEdge{src: src, dst: dst, relType: relType,
			desc: fmt.Sprintf("%s %s %s (reported)", shortName(src.Name()), relType, shortName(dst.Name()))})
	}
	return out
}

// placementLookups are the names a report's placement properties point at
// outside the report: hypervisor hosts and addresses.
func placementLookups(report *ctis.Report, stored map[string]*asset.Asset, mayChange func(shared.ID) bool) (hosts, ips []string) {
	seenHost, seenIP := map[string]bool{}, map[string]bool{}
	for i := range report.Assets {
		ca := &report.Assets[i]
		a := stored[ca.ID]
		if a == nil || a.Type() != asset.AssetTypeHost || !mayChange(a.ID()) {
			continue
		}
		if h := hypervisorHostName(ca); h != "" && !seenHost[h] {
			seenHost[h] = true
			hosts = append(hosts, h)
		}
		for n, ip := range asset.IPAddresses(ca.Properties) {
			if n >= maxAddressEdgesPerHost {
				break
			}
			if v := asset.NormalizeName(ip, asset.AssetTypeIPAddress, ""); v != "" && !seenIP[v] {
				seenIP[v] = true
				ips = append(ips, v)
			}
		}
	}
	return hosts, ips
}

// hypervisorHostName is the normalized name of the host a reported virtual
// machine runs on, or "".
func hypervisorHostName(ca *ctis.Asset) string {
	v, _ := ca.Properties[propHypervisorHost].(string)
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	return asset.NormalizeName(v, asset.AssetTypeHost, "")
}

// planPlacementEdges plans a virtual machine's runs_on edge to its
// hypervisor host and a host's contains edges to the address assets of its
// addresses. byName holds the tenant's assets by name (the report's own and
// those found by the tenant-scoped lookup); addresses are linked only when
// an address asset already exists, never created from a host's properties.
func planPlacementEdges(tenantID shared.ID, report *ctis.Report, stored map[string]*asset.Asset,
	byName map[string]*asset.Asset, mayChange func(shared.ID) bool,
) []plannedEdge {
	var out []plannedEdge
	for i := range report.Assets {
		ca := &report.Assets[i]
		a := stored[ca.ID]
		if a == nil || a.Type() != asset.AssetTypeHost || !mayChange(a.ID()) {
			continue
		}
		if h := hypervisorHostName(ca); h != "" {
			if hv := byName[h]; hv != nil && hv.TenantID() == tenantID && hv.ID() != a.ID() &&
				edgeAllowed(asset.RelTypeRunsOn, a, hv) {
				out = append(out, plannedEdge{src: a, dst: hv, relType: asset.RelTypeRunsOn,
					desc: fmt.Sprintf("%s runs on hypervisor host %s", shortName(a.Name()), shortName(hv.Name()))})
			}
		}
		for n, ip := range asset.IPAddresses(ca.Properties) {
			if n >= maxAddressEdgesPerHost {
				break
			}
			addr := byName[asset.NormalizeName(ip, asset.AssetTypeIPAddress, "")]
			if addr == nil || addr.TenantID() != tenantID || addr.Type() != asset.AssetTypeIPAddress ||
				!edgeAllowed(asset.RelTypeContains, a, addr) {
				continue
			}
			out = append(out, plannedEdge{src: a, dst: addr, relType: asset.RelTypeContains,
				desc: fmt.Sprintf("%s has address %s", shortName(a.Name()), addr.Name())})
		}
	}
	return out
}

// createReportRelationships stores the report's typed relationships and the
// placement edges of its hosts (best effort, like the other derived edges).
func (p *AssetProcessor) createReportRelationships(ctx context.Context, tenantID shared.ID, report *ctis.Report,
	existingMap map[string]*asset.Asset, assetMap map[string]shared.ID, mayChange func(shared.ID) bool,
) {
	stored := storedReportAssets(tenantID, report, existingMap, assetMap)
	if len(stored) == 0 {
		return
	}
	edges := planReportRelationships(report, stored, mayChange)

	hosts, ips := placementLookups(report, stored, mayChange)
	if len(hosts)+len(ips) > 0 {
		byName := make(map[string]*asset.Asset, len(hosts)+len(ips))
		var missing []string
		for _, n := range append(hosts, ips...) {
			if a, ok := existingMap[n]; ok {
				byName[n] = a
			} else {
				missing = append(missing, n)
			}
		}
		if len(missing) > 0 {
			found, err := p.repo.GetByNames(ctx, tenantID, missing)
			if err != nil {
				p.logger.Warn("placement edges: asset lookup failed", "error", logger.SanitizeError(err))
			}
			for n, a := range found {
				byName[n] = a
			}
		}
		edges = append(edges, planPlacementEdges(tenantID, report, stored, byName, mayChange)...)
	}
	if len(edges) == 0 {
		return
	}

	seen := map[[2]shared.ID]asset.RelationshipType{}
	rels := make([]*asset.Relationship, 0, len(edges))
	for _, e := range edges {
		key := [2]shared.ID{e.src.ID(), e.dst.ID()}
		if t, ok := seen[key]; ok && t == e.relType {
			continue
		}
		rel, err := asset.NewRelationship(tenantID, e.src.ID(), e.dst.ID(), e.relType)
		if err != nil {
			continue
		}
		seen[key] = e.relType
		rel.SetDescription(e.desc)
		_ = rel.SetDiscoveryMethod(asset.DiscoveryAutomatic)
		rel.Verify()
		rels = append(rels, rel)
	}
	created, err := p.relRepo.CreateBatchIgnoreConflicts(ctx, rels)
	if err != nil {
		p.logger.Warn("failed to create report relationships", "total", len(rels), "error", logger.SanitizeError(err))
		return
	}
	if created > 0 {
		p.logger.Info("created report relationships", "created", created, "skipped", len(rels)-created)
	}
}
