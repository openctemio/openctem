package asset

import (
	"fmt"
	"net"
	"strings"

	assetdom "github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
)

// relationship_inference.go derives high-value asset-graph edges (Exposes,
// RunsOn) from data scanners already ingest, so the attack-path / exposure-
// chain / reachability engines have edges beyond DNS to traverse.
//
// The four graph engines (path_scoring, exposure_chains, reachability oracle,
// threat-model) only traverse the "attack-path" relationship types. Ingest,
// however, only ever creates `contains` (domain→subdomain) and `resolves_to`
// (domain→IP). On real data that means the engines reach the directly-exposed
// asset and stop. This file adds the host↔service hops those engines need,
// inferred purely from asset type + network properties that port/HTTP/vuln
// scanners already populate.
//
// Design rules (correctness-first — these edges drive prioritization):
//   - Only UNAMBIGUOUS matches are auto-applied. A host-key that maps to a
//     single container asset → auto edge (high confidence). A key that maps to
//     several candidate containers → emitted as a suggestion for human review,
//     never auto-applied (a wrong edge would mis-prioritize).
//   - Edges are directed for inward attack traversal: a container (host /
//     ip_address) `exposes` the service listening on it; an application
//     `runs_on` the host it is co-located with.
//   - The function is pure (no IO) so it is exhaustively unit-testable and the
//     controller/service layer owns loading + persistence.

// GraphAsset is the minimal projection of an asset the inference needs. The
// service layer builds these from *pkg/domain/asset.Asset (Type/SubType/Name/
// Properties); tests build them directly.
type GraphAsset struct {
	ID      shared.ID
	Type    assetdom.AssetType
	SubType string
	Name    string
	Props   map[string]any
}

// InferredEdge is a single derived relationship. Confidence carries the domain
// confidence level; Reason is a human-readable justification stored on the
// relationship / suggestion.
type InferredEdge struct {
	SourceID   shared.ID
	TargetID   shared.ID
	Type       assetdom.RelationshipType
	Confidence assetdom.RelationshipConfidence
	Reason     string
}

// InferenceResult splits derived edges into those safe to auto-apply and those
// that must go through the suggestion (human-review) path.
type InferenceResult struct {
	// AutoEdges are unambiguous, high-confidence edges the caller may create
	// directly (idempotently) in the relationships table.
	AutoEdges []InferredEdge
	// Suggestions are ambiguous / lower-confidence edges to persist via the
	// relationship-suggestion mechanism for an operator to approve or dismiss.
	Suggestions []InferredEdge
}

// InferGraphEdges derives Exposes / RunsOn edges from a tenant's asset set.
//
// Edge types & rules:
//
//	Exposes  (container → service):  a `service` asset (open_port from Naabu,
//	         http_service from HTTPX, live-host service) names its host via
//	         properties.host / properties.ip (or, for HTTP services, its Name).
//	         When exactly one host/ip_address asset matches that key, that
//	         container `exposes` the service — the entry-point edge chains need.
//
//	RunsOn   (application → host):    an `application` asset (website/api/…)
//	         co-located with a host/ip_address by shared ip/hostname `runs_on`
//	         that host — the public-service→host hop.
//
// A host-key matching multiple containers is ambiguous → suggestion, not auto.
func InferGraphEdges(assets []GraphAsset) InferenceResult {
	res := InferenceResult{}

	// Build the container index: key (name / ip / hostname, lower-cased) →
	// set of container asset IDs. Only host & ip_address assets are
	// containers — the nodes a service/app can sit "on".
	index := make(map[string]map[shared.ID]bool)
	addKey := func(key string, id shared.ID) {
		key = normalizeHostKey(key)
		if key == "" {
			return
		}
		if index[key] == nil {
			index[key] = make(map[shared.ID]bool)
		}
		index[key][id] = true
	}
	for i := range assets {
		a := &assets[i]
		if !isHostContainer(a.Type) {
			continue
		}
		addKey(a.Name, a.ID)
		if a.Type == assetdom.AssetTypeHost {
			for _, ip := range stringSliceProp(a.Props, "ip_addresses") {
				addKey(ip, a.ID)
			}
			addKey(stringProp(a.Props, "hostname"), a.ID)
		}
	}

	for i := range assets {
		a := &assets[i]
		switch {
		case isServiceLike(a.Type, a.SubType):
			inferExposes(a, index, &res)
		case isApplicationLike(a.Type):
			inferRunsOn(a, index, &res)
		}
	}
	return res
}

// inferExposes emits `container --Exposes--> service` edges. Each host-key of
// the service is resolved against the container index; unique matches become
// auto edges, ambiguous ones become suggestions.
func inferExposes(svc *GraphAsset, index map[string]map[shared.ID]bool, res *InferenceResult) {
	matched := make(map[shared.ID]bool)   // unique container matches → auto
	ambiguous := make(map[shared.ID]bool) // multi-candidate matches → suggest
	for _, key := range serviceHostKeys(svc) {
		ids := index[normalizeHostKey(key)]
		switch len(ids) {
		case 0:
			continue
		case 1:
			for id := range ids {
				matched[id] = true
			}
		default:
			for id := range ids {
				ambiguous[id] = true
			}
		}
	}
	for cid := range matched {
		if cid == svc.ID {
			continue
		}
		res.AutoEdges = append(res.AutoEdges, InferredEdge{
			SourceID:   cid,
			TargetID:   svc.ID,
			Type:       assetdom.RelTypeExposes,
			Confidence: assetdom.ConfidenceHigh,
			Reason:     fmt.Sprintf("Host exposes service %s (matched on network address)", svc.Name),
		})
	}
	for cid := range ambiguous {
		if cid == svc.ID || matched[cid] {
			continue
		}
		res.Suggestions = append(res.Suggestions, InferredEdge{
			SourceID:   cid,
			TargetID:   svc.ID,
			Type:       assetdom.RelTypeExposes,
			Confidence: assetdom.ConfidenceLow,
			Reason:     fmt.Sprintf("Possible host for service %s (address matched multiple assets)", svc.Name),
		})
	}
}

// inferRunsOn emits `application --RunsOn--> host` edges from shared network
// identity. Unique matches auto-apply; multi-candidate matches suggest.
func inferRunsOn(app *GraphAsset, index map[string]map[shared.ID]bool, res *InferenceResult) {
	matched := make(map[shared.ID]bool)
	ambiguous := make(map[shared.ID]bool)
	for _, key := range applicationHostKeys(app) {
		ids := index[normalizeHostKey(key)]
		switch len(ids) {
		case 0:
			continue
		case 1:
			for id := range ids {
				matched[id] = true
			}
		default:
			for id := range ids {
				ambiguous[id] = true
			}
		}
	}
	for hid := range matched {
		if hid == app.ID {
			continue
		}
		res.AutoEdges = append(res.AutoEdges, InferredEdge{
			SourceID:   app.ID,
			TargetID:   hid,
			Type:       assetdom.RelTypeRunsOn,
			Confidence: assetdom.ConfidenceHigh,
			Reason:     fmt.Sprintf("Application %s runs on host (matched on network address)", app.Name),
		})
	}
	for hid := range ambiguous {
		if hid == app.ID || matched[hid] {
			continue
		}
		res.Suggestions = append(res.Suggestions, InferredEdge{
			SourceID:   app.ID,
			TargetID:   hid,
			Type:       assetdom.RelTypeRunsOn,
			Confidence: assetdom.ConfidenceLow,
			Reason:     fmt.Sprintf("Possible host for application %s (address matched multiple assets)", app.Name),
		})
	}
}

// serviceHostKeys returns the candidate host identifiers a service asset
// carries. Naabu open_port assets set properties.host (an IP or hostname);
// HTTPX / live-host services set properties.ip and name themselves by
// hostname. The Name is only trusted for non-open_port services because an
// open_port's Name is "ip:port/proto" (not a clean host key).
func serviceHostKeys(svc *GraphAsset) []string {
	keys := make([]string, 0, 3)
	if h := stringProp(svc.Props, "host"); h != "" {
		keys = append(keys, h)
	}
	if ip := stringProp(svc.Props, "ip"); ip != "" {
		keys = append(keys, ip)
	}
	if svc.SubType != "open_port" && isCleanHostKey(svc.Name) {
		keys = append(keys, svc.Name)
	}
	return keys
}

// applicationHostKeys returns candidate host identifiers for an application
// asset: explicit ip/hostname/host properties plus a clean hostname Name.
func applicationHostKeys(app *GraphAsset) []string {
	keys := make([]string, 0, 4)
	for _, k := range []string{"ip", "hostname", "host"} {
		if v := stringProp(app.Props, k); v != "" {
			keys = append(keys, v)
		}
	}
	if isCleanHostKey(app.Name) {
		keys = append(keys, app.Name)
	}
	return keys
}

// isHostContainer reports whether the type is a node a service/app can sit on.
func isHostContainer(t assetdom.AssetType) bool {
	return t == assetdom.AssetTypeHost || t == assetdom.AssetTypeIPAddress
}

// isServiceLike reports whether the asset is a network service worth an
// Exposes edge. Naabu/HTTPX assets normalize to the `service` core type;
// crawled URLs (sub_type discovered_url) are excluded — they are page
// endpoints, not listening services, and linking every crawled URL to a host
// would flood the graph with low-value edges.
func isServiceLike(t assetdom.AssetType, subType string) bool {
	if subType == "discovered_url" {
		return false
	}
	return t == assetdom.AssetTypeService || t == assetdom.AssetTypeHTTPService || t == assetdom.AssetTypeOpenPort
}

// isApplicationLike reports whether the asset is an application worth a RunsOn
// edge. Handles both the consolidated `application` core type and the legacy
// website/web_application/api/mobile_app types (in case a tenant predates
// consolidation).
func isApplicationLike(t assetdom.AssetType) bool {
	switch t {
	case assetdom.AssetTypeApplication, assetdom.AssetTypeWebsite,
		assetdom.AssetTypeWebApplication, assetdom.AssetTypeAPI, assetdom.AssetTypeMobileApp:
		return true
	default:
		return false
	}
}

// normalizeHostKey lower-cases and trims a host key for stable map lookups.
func normalizeHostKey(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// isCleanHostKey reports whether s is a plausible bare host identifier (IP or
// hostname) — not a URL, port-suffixed address, or free text. Used to decide
// whether an asset's Name can be trusted as a host key.
func isCleanHostKey(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, "/\\ @") {
		return false
	}
	if net.ParseIP(s) != nil {
		return true
	}
	// Reject ip:port and other colon-bearing forms; require a dotted hostname.
	if strings.Contains(s, ":") {
		return false
	}
	return strings.Contains(s, ".")
}

// stringProp reads a string property, tolerating absent/typed values.
func stringProp(props map[string]any, key string) string {
	if props == nil {
		return ""
	}
	if v, ok := props[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// stringSliceProp reads a string-slice property, tolerating both []string and
// []any (the shape produced by JSON unmarshaling of JSONB).
func stringSliceProp(props map[string]any, key string) []string {
	if props == nil {
		return nil
	}
	switch v := props[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
