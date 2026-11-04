package softwarematch

// Shared third-party hosting (research note 422): a version match on a host
// served by a provider's shared front ends (a CDN or WAF edge, SaaS hosting,
// site builders) is about the provider's software, not the organization's. The
// matcher still records it, attributed to the provider and capped in
// priority, so the organization sees it as context on its name instead of
// as its own critical vulnerability.

import (
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/edgeaddr"
)

// HostFacts is what the tenant's inventory holds about where a matched asset
// is served from.
type HostFacts struct {
	// Name is the asset's name; Host its probed host when it has one.
	Name, Host string
	// CNAME is the asset's CNAME target, Addresses the addresses it
	// resolves to.
	CNAME     string
	Addresses []string
	// ASNOrg and CDN are the network holder and CDN the asset's record
	// names (address and service assets).
	ASNOrg, CDN string
	// NameCNAMEs are the CNAME targets of the tenant's names that resolve
	// to this address ("" for a name without one): an address that every
	// name reaches through one provider's host is that provider's front end.
	NameCNAMEs []string
}

// HostedBy returns the provider whose shared front end serves the asset, or
// "" when the asset may be the organization's own. Unknown is never read as
// shared: an address no provider data knows stays the organization's.
func HostedBy(c *edgeaddr.Classifier, f HostFacts) string {
	if c == nil {
		return ""
	}
	host := hostOnly(f.Host)
	if host == "" {
		host = hostOnly(f.Name)
	}
	if host == "" {
		return ""
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if r := c.Address(a.String(), f.CDN, f.ASNOrg); r.Shared() {
			return r.Provider
		}
		return viaNames(c, f.NameCNAMEs)
	}
	var cnames []string
	if f.CNAME != "" {
		cnames = []string{f.CNAME}
	}
	if r := c.Name(host, cnames, f.Addresses); r.Shared() {
		return r.Provider
	}
	if f.CDN != "" {
		if r := c.Address("", f.CDN, ""); r.Shared() {
			return r.Provider
		}
	}
	return ""
}

// viaNames attributes an address to a provider when at least one of the
// tenant's names resolves to it and every one of them does so through the same
// provider's host suffix.
func viaNames(c *edgeaddr.Classifier, cnames []string) string {
	provider := ""
	for _, cn := range cnames {
		r := c.Host(cn)
		if cn == "" || !r.Shared() {
			return ""
		}
		if provider != "" && provider != r.Provider {
			return ""
		}
		provider = r.Provider
	}
	return provider
}

// hostOnly reads the host of a name, URL or "host:port[/transport]" value.
func hostOnly(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil {
			return ""
		}
		v = u.Host
	}
	if i := strings.Index(v, "/"); i >= 0 {
		v = v[:i]
	}
	if h, _, err := net.SplitHostPort(v); err == nil {
		v = h
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(v, "[]"), "."))
}
