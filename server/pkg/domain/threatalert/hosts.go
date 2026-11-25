package threatalert

import (
	"fmt"
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
		key    string
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
		// One row per host key (HostKey): the counts of an alert are the
		// number of these rows.
		key := rowKey{a.TenantID, a.Kind, HostKey(a.Asset)}
		ri, seen := rowAt[key]
		if !seen {
			ri = len(g.Hosts)
			rowAt[key] = ri
			if isService {
				g.Hosts = append(g.Hosts, HostRow{Host: host})
			} else {
				id := a.AssetID
				g.Hosts = append(g.Hosts, HostRow{Host: a.Name, AssetID: &id})
			}
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

// maxHostKey bounds a stored host key.
const maxHostKey = 300

// HostKey identifies the host row an affected asset belongs to within one
// organization: the host of an asset named by a URL ("h:" and the host), or
// the asset itself for any other asset ("a:" and its id). Every place that
// counts or compares the hosts of an alert uses this key: the rows of
// GroupByHost, CountHosts, HostsGrew and the key stored with each alert
// asset, which the scoped list and digest counts read.
func HostKey(a Asset) string {
	host, _, ok := serviceOfName(a.Name)
	if !ok {
		return "a:" + a.AssetID.String()
	}
	key := "h:" + host
	if len(key) > maxHostKey {
		key = key[:maxHostKey]
	}
	return key
}

// HostCounts is how many hosts an alert affects. Confirmed, Likely and
// Possible count the host rows of each tier, as GroupByHost lists them (a
// host with services in two tiers is a row in each). InternetFacing and
// Critical count each host once, whatever its tiers: hosts with a service
// that is internet-facing, hosts with a service of criticality "critical".
type HostCounts struct {
	Confirmed      int
	Likely         int
	Possible       int
	InternetFacing int
	Critical       int
}

// Total is the number of host rows over the three tiers.
func (c HostCounts) Total() int { return c.Confirmed + c.Likely + c.Possible }

// CountHosts counts the hosts of one organization's affected assets.
func CountHosts(assets []Asset) HostCounts {
	type tierKey struct {
		kind MatchKind
		key  string
	}
	var c HostCounts
	rows := make(map[tierKey]bool, len(assets))
	internet, critical := map[string]bool{}, map[string]bool{}
	for _, a := range assets {
		key := HostKey(a)
		if tk := (tierKey{a.Kind, key}); !rows[tk] {
			rows[tk] = true
			switch a.Kind {
			case MatchConfirmed:
				c.Confirmed++
			case MatchLikely:
				c.Likely++
			default:
				c.Possible++
			}
		}
		if a.InternetFacing {
			internet[key] = true
		}
		if strings.EqualFold(a.Criticality, levelCritical) {
			critical[key] = true
		}
	}
	c.InternetFacing, c.Critical = len(internet), len(critical)
	return c
}

func tierRank(k MatchKind) int {
	switch k {
	case MatchConfirmed:
		return 3
	case MatchLikely:
		return 2
	case MatchPossible:
		return 1
	}
	return 0
}

// HostsGrew reports whether an alert reaches further than it did: a host
// that was not affected before, or a host whose strongest tier is stronger
// than before (possible to likely or confirmed, likely to confirmed). One
// more service on a host already known at that tier or a stronger one is not
// growth.
func HostsGrew(before, now []Asset) bool {
	was := make(map[string]int, len(before))
	for _, a := range before {
		key := HostKey(a)
		was[key] = max(was[key], tierRank(a.Kind))
	}
	for _, a := range now {
		if tierRank(a.Kind) > was[HostKey(a)] {
			return true
		}
	}
	return false
}

// HostNames names up to limit of the hosts of the assets, each once, in the
// order given: the host of an asset named by a URL, the name of any other.
func HostNames(assets []Asset, limit int) []string {
	names := make([]string, 0, limit)
	seen := map[string]bool{}
	for _, a := range assets {
		if len(names) >= limit {
			break
		}
		key := HostKey(a)
		if seen[key] {
			continue
		}
		seen[key] = true
		name := a.Name
		if host, _, ok := serviceOfName(a.Name); ok {
			name = host
		}
		if n := PlainText(name, 80); n != "" {
			names = append(names, n)
		}
	}
	return names
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Sentence says the counts in the words the console uses, zero parts left
// out: "3 hosts confirmed, 1 likely, 2 possibly affected, 2 internet-facing".
// The first tier named carries the word "host".
func (c HostCounts) Sentence() string {
	var parts []string
	tier := func(n int, word string) {
		if n == 0 {
			return
		}
		if len(parts) == 0 {
			parts = append(parts, fmt.Sprintf("%d %s %s", n, plural(n, "host", "hosts"), word))
			return
		}
		parts = append(parts, fmt.Sprintf("%d %s", n, word))
	}
	tier(c.Confirmed, "confirmed")
	tier(c.Likely, "likely")
	tier(c.Possible, "possibly affected")
	if len(parts) == 0 {
		return "no hosts affected"
	}
	if c.InternetFacing > 0 {
		parts = append(parts, fmt.Sprintf("%d internet-facing", c.InternetFacing))
	}
	return strings.Join(parts, ", ")
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

// Criticality and severity level names, as stored on assets and vulnerabilities.
const (
	levelCritical = "critical"
	levelHigh     = "high"
	levelMedium   = "medium"
)

func criticalityRank(c string) int {
	switch strings.ToLower(strings.TrimSpace(c)) {
	case levelCritical:
		return 4
	case levelHigh:
		return 3
	case levelMedium:
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
