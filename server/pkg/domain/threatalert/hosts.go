package threatalert

import (
	"net/url"
	"strings"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// A host that serves several ports has one service asset per port, each named
// by its URL ("http://host", "https://host"). They are different assets and
// stay so; a reader of an alert, though, thinks in hosts. GroupByHost is the
// one place that folds an alert's assets into one row per host.
//
// The host of a service is read from its name. A stored relationship from a
// service to the asset that exposes it exists only when a report carried one,
// and a service can be exposed by several assets (an address and a name), so
// it cannot identify the row.

// HostService is one affected asset inside a host row.
type HostService struct {
	AssetView
	// Label names the service within its host: the scheme, an explicit
	// non-default port and the path ("http", "https:8443", "https/app").
	// Empty for an asset that is not named by a URL.
	Label string
}

// HostRow is the affected assets of one host in one tier.
type HostRow struct {
	// Host is the row's title: the host of the services, or the name of an
	// asset that is not named by a URL.
	Host string
	// AssetID is set when the row is one asset not named by a URL (the title
	// links to it). Services link to their own assets.
	AssetID *shared.ID
	// InternetFacing: any of the services is.
	InternetFacing bool
	// Criticality is the highest of the services.
	Criticality string
	// Products and Versions are the distinct values of the services, in
	// order of appearance.
	Products []string
	Versions []string
	// Services keeps every asset of the row with its own finding and task.
	Services []HostService
}

// HostGroup is the host rows of one tier.
type HostGroup struct {
	Kind  MatchKind
	Hosts []HostRow
}

// GroupByHost folds affected assets into one row per host within each tier:
// confirmed, likely, possible, tiers without an asset left out. Assets named
// by a URL of the same host (scheme and default port ignored, case-insensitive)
// in the same organization share a row; any other asset is a row of its own.
// Rows and services keep the order of the assets given. No asset is dropped.
func GroupByHost(assets []AssetView) []HostGroup {
	type rowKey struct {
		tenant shared.ID
		kind   MatchKind
		host   string
	}
	groups := make([]HostGroup, 0, 3)
	groupAt := map[MatchKind]int{}
	for _, k := range []MatchKind{MatchConfirmed, MatchLikely, MatchPossible} {
		groupAt[k] = len(groups)
		groups = append(groups, HostGroup{Kind: k})
	}
	rowAt := map[rowKey]int{}
	for _, a := range assets {
		gi, ok := groupAt[a.Kind]
		if !ok {
			gi = len(groups)
			groupAt[a.Kind] = gi
			groups = append(groups, HostGroup{Kind: a.Kind})
		}
		g := &groups[gi]
		host, label, isService := serviceOfName(a.Name)
		if !isService {
			id := a.AssetID
			g.Hosts = append(g.Hosts, HostRow{Host: a.Name, AssetID: &id})
		} else {
			key := rowKey{a.TenantID, a.Kind, host}
			if _, seen := rowAt[key]; !seen {
				rowAt[key] = len(g.Hosts)
				g.Hosts = append(g.Hosts, HostRow{Host: host})
			}
		}
		ri := len(g.Hosts) - 1
		if isService {
			ri = rowAt[rowKey{a.TenantID, a.Kind, host}]
		}
		row := &g.Hosts[ri]
		row.InternetFacing = row.InternetFacing || a.InternetFacing
		if criticalityRank(a.Criticality) > criticalityRank(row.Criticality) || row.Criticality == "" {
			row.Criticality = a.Criticality
		}
		row.Products = appendDistinct(row.Products, a.Product)
		row.Versions = appendDistinct(row.Versions, a.Version)
		row.Services = append(row.Services, HostService{AssetView: a, Label: label})
	}
	out := groups[:0]
	for _, g := range groups {
		if len(g.Hosts) > 0 {
			out = append(out, g)
		}
	}
	return out
}

// defaultPorts are the ports a scheme implies; they are not part of a
// service's label.
var defaultPorts = map[string]string{"http": "80", "https": "443"}

// serviceOfName reads a URL-named asset: its host (lower case, an IPv6
// literal in brackets) and the service's label within that host. ok is false
// for a name that is not an absolute URL with a host.
func serviceOfName(name string) (host, label string, ok bool) {
	name = strings.TrimSpace(name)
	if !strings.Contains(name, "://") {
		return "", "", false
	}
	u, err := url.Parse(name)
	if err != nil || u.Scheme == "" {
		return "", "", false
	}
	host = strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return "", "", false
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	label = strings.ToLower(u.Scheme)
	if p := u.Port(); p != "" && p != defaultPorts[label] {
		label += ":" + p
	}
	label += strings.TrimRight(u.EscapedPath(), "/")
	if u.RawQuery != "" {
		label += "?" + u.RawQuery
	}
	return host, label, true
}

func criticalityRank(c string) int {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	}
	return 0
}

func appendDistinct(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, have := range list {
		if have == v {
			return list
		}
	}
	return append(list, v)
}
