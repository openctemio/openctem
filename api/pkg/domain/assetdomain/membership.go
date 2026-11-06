// Package assetdomain decides which DNS names an asset belongs to, so
// findings can be filtered by domain over every asset kind (a name, the
// addresses it resolves to, the services on them, certificates, web
// applications), not only by the asset's own name.
//
// Design and rules: docs/architecture/asset-domain-membership.md. The rules
// read only evidence the platform already holds (the asset's name and
// properties, and its resolves_to, exposes and runs_on edges). An address is
// a member only when a name resolves to it and it is not a CDN, WAF, SaaS
// hosting or shared cloud front end (edgeaddr), and not shared hosting (names
// of three or more registrable domains resolve to it): otherwise one
// organization's filter would list another's assets.
package assetdomain

import (
	"net/netip"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/edgeaddr"
)

// Limits.
const (
	// MaxNamesPerAsset caps the names one asset contributes (a certificate
	// with thousands of SANs); the first ones in sorted order are kept.
	MaxNamesPerAsset = 500
	// sharedHostingDomains is the number of registrable domains whose names
	// resolve to one address from which it counts as shared hosting (the
	// same rule as the EASM suggestions).
	sharedHostingDomains = 3
)

// Evidence is what the membership of one asset is derived from.
type Evidence struct {
	// Type is the stored asset type (assets.asset_type).
	Type string
	Name string
	// Props are the asset's properties; only the name-bearing keys are read.
	Props map[string]any
	// Resolvers are the names of the assets with a resolves_to edge to this
	// one (the names that resolve to this address).
	Resolvers []string
	// Hosts are the assets this one runs on or is exposed by (its runs_on
	// targets and exposes sources), with their own Resolvers. They carry no
	// Hosts of their own: membership follows one host hop.
	Hosts []Evidence
}

// Names returns the normalised DNS names the asset belongs to, sorted and
// without duplicates. classifier may be nil (no address is then treated as
// shared by its range; shared hosting still is).
func Names(e Evidence, classifier *edgeaddr.Classifier) []string {
	set := map[string]bool{}
	addNames(set, e, classifier)
	for _, h := range e.Hosts {
		h.Hosts = nil
		addNames(set, h, classifier)
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	if len(out) > MaxNamesPerAsset {
		out = out[:MaxNamesPerAsset]
	}
	return out
}

func addNames(set map[string]bool, e Evidence, classifier *edgeaddr.Classifier) {
	for _, n := range OwnNames(e) {
		set[n] = true
	}
	if len(e.Resolvers) == 0 || !addressLike(e) || sharedAddress(e, classifier) {
		return
	}
	for _, r := range e.Resolvers {
		if n, ok := dnsName(r); ok {
			set[n] = true
		}
	}
}

// OwnNames are the names an asset carries itself, by type. Types with no
// network name (repositories, identities, containers, cloud accounts,
// buckets) have none.
func OwnNames(e Evidence) []string {
	var raw []string
	switch e.Type {
	case "domain", "subdomain":
		raw = append(raw, e.Name)
	case "host":
		raw = append(raw, e.Name)
		raw = append(raw, props(e.Props, "hostname", "fqdn")...)
	case "certificate":
		raw = append(raw, e.Name)
		raw = append(raw, props(e.Props, "subject_cn", "sans", "san")...)
	case "service", "application":
		raw = append(raw, asset.HostOf(e.Name))
		for _, u := range props(e.Props, "url", "base_url", "host", "hostname") {
			raw = append(raw, asset.HostOf(u))
		}
	case "network":
		raw = append(raw, props(e.Props, "dns_name")...)
	case "database":
		raw = append(raw, asset.HostOf(e.Name))
		for _, u := range props(e.Props, "endpoint") {
			raw = append(raw, asset.HostOf(u))
		}
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		if n, ok := dnsName(r); ok {
			out = append(out, n)
		}
	}
	return out
}

// Keys are the membership keys of a set of names: each name itself, and
// "*.s" for every parent s of it down to its registrable domain (never a
// public suffix). The filter "x" matches the keys x and *.x; "*.x" matches
// *.x only.
func Keys(names []string) []string {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
		for s := n; ; {
			i := strings.IndexByte(s, '.')
			if i < 0 {
				break
			}
			s = s[i+1:]
			if !strings.Contains(s, ".") {
				break
			}
			if suffix, _ := publicsuffix.PublicSuffix(s); suffix == s {
				break
			}
			set["*."+s] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// dnsName normalises a name and drops a wildcard label ("*.x" is x). It
// refuses addresses, URLs and non-DNS text.
func dnsName(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, "*.") {
		s = s[2:]
	}
	n, ok := NormalizeDNSName(s)
	if !ok || !strings.Contains(n, ".") {
		return "", false
	}
	if suffix, _ := publicsuffix.PublicSuffix(n); suffix == n {
		return "", false
	}
	return n, true
}

// addressLike reports whether names resolve to this asset: an address, or
// a host or network asset named by an address or a provider host.
func addressLike(e Evidence) bool {
	switch e.Type {
	case "ip_address", "host", "network":
		return true
	}
	return false
}

// sharedAddress reports whether the asset is a provider's shared front end
// (CDN or WAF edge, SaaS hosting, cloud shared) or shared hosting.
func sharedAddress(e Evidence, classifier *edgeaddr.Classifier) bool {
	if classifier != nil {
		name := strings.TrimSpace(e.Name)
		if _, err := netip.ParseAddr(name); err == nil {
			cdn := firstProp(e.Props, "cdn")
			org := firstProp(e.Props, "asn_org")
			if classifier.Address(name, cdn, org).Shared() {
				return true
			}
		} else if n, ok := NormalizeDNSName(name); ok && classifier.Host(n).Shared() {
			return true
		}
	}
	roots := map[string]bool{}
	for _, r := range e.Resolvers {
		n, ok := dnsName(r)
		if !ok {
			continue
		}
		root, err := publicsuffix.EffectiveTLDPlusOne(n)
		if err != nil {
			continue
		}
		roots[root] = true
		if len(roots) >= sharedHostingDomains {
			return true
		}
	}
	return false
}

// props returns the string values of the given keys: a string, or the
// strings of an array.
func props(p map[string]any, keys ...string) []string {
	var out []string
	for _, k := range keys {
		switch v := p[k].(type) {
		case string:
			out = append(out, v)
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok {
					out = append(out, s)
				}
			}
		case []string:
			out = append(out, v...)
		}
	}
	return out
}

func firstProp(p map[string]any, key string) string {
	if v := props(p, key); len(v) > 0 {
		return v[0]
	}
	return ""
}

// QueueResult is one batch of the membership queue.
type QueueResult struct {
	// Claimed is the queued assets taken.
	Claimed int
	// Refreshed is the assets whose membership was rewritten (claimed ones
	// and their dependents).
	Refreshed int
	// Deferred is the dependents queued again because the batch was full.
	Deferred int
}
