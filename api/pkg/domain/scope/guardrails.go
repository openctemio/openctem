package scope

// Platform guardrails on scope (RFC-054 §8, owner decision S2). They protect
// third parties from a malicious or careless tenant, so they are operator
// settings only: nothing a tenant sends turns them off.
//
//   - no entry may be, or wildcard, a public suffix (the ICANN and private
//     sections of the Public Suffix List, embedded through
//     golang.org/x/net/publicsuffix: no network call);
//   - government and military names, shared-provider apexes as wildcard
//     roots, the whole address space, link-local and cloud metadata
//     addresses, and the operator's own names and ranges are denied;
//   - public CIDRs larger than the operator's caps are refused (private
//     ranges are gated by scan zones).

import (
	_ "embed"
	"math/big"
	"net/netip"
	"net/url"
	"slices"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"

	"golang.org/x/net/publicsuffix"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Guardrail refusal codes.
var (
	ErrPublicSuffix = shared.NewDomainError("PUBLIC_SUFFIX", "the pattern is, or covers, a public suffix shared by many organizations", shared.ErrValidation)
	ErrDenyList     = shared.NewDomainError("DENY_LIST", "the platform does not allow this target; contact support", shared.ErrValidation)
	ErrCIDRTooLarge = shared.NewDomainError("CIDR_TOO_LARGE", "the public address range is larger than the platform allows", shared.ErrValidation)
	// ErrSharedCodeHost refuses a whole-host repository entry on a code host
	// many organizations share: name a namespace (host/namespace/*).
	ErrSharedCodeHost = shared.NewDomainError("SHARED_CODE_HOST", "this code host is shared by many organizations: name your namespace, such as github.com/your-org/*", shared.ErrValidation)
)

//go:embed public_code_hosts.txt
var publicCodeHostsData string

// builtinPublicCodeHosts are the code hosts in public_code_hosts.txt.
var builtinPublicCodeHosts = parseHostList(publicCodeHostsData)

func parseHostList(data string) []string {
	var out []string
	for _, line := range strings.Split(data, "\n") {
		line = strings.ToLower(strings.TrimSpace(line))
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// Default CIDR caps (RFC-054 §8.3).
const (
	DefaultMaxPublicCIDRv4 = 16
	DefaultMaxPublicCIDRv6 = 32
)

// sharedProviderApexes may not be wildcard roots: everything under them
// belongs to the provider's other customers. An exact name under one (the
// tenant's own app) stays allowed. Most are also private PSL entries.
var sharedProviderApexes = []string{
	"amazonaws.com", "cloudfront.net", "elasticbeanstalk.com", "awsapprunner.com",
	"azurewebsites.net", "azureedge.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "azurefd.net", "windows.net",
	"appspot.com", "googleusercontent.com", "web.app", "firebaseapp.com", "run.app", "cloudfunctions.net",
	"herokuapp.com", "herokudns.com", "github.io", "githubusercontent.com", "gitlab.io",
	"vercel.app", "netlify.app", "pages.dev", "workers.dev", "cloudflare.net", "cloudflare.com",
	"fastly.net", "fastlylb.net", "akamaiedge.net", "akamai.net", "edgekey.net", "edgesuite.net",
	"myshopify.com", "blogspot.com", "wordpress.com", "wixsite.com", "squarespace.com",
}

// governmentSLDs are second-level labels used for government and military
// names under a country code (gov.vn, gov.uk, go.jp, gob.mx, gouv.fr, ...).
var governmentSLDs = map[string]bool{"gov": true, "mil": true, "gouv": true, "gob": true, "go": true, "govt": true}

// deniedNames are government names that do not follow the SLD pattern.
var deniedNames = []string{"gc.ca", "bund.de", "admin.ch", "europa.eu", "gv.at"}

// builtinDeniedPrefixes are addresses no tenant may target: the whole space,
// "this network", loopback, link-local (cloud metadata lives there) and the
// metadata addresses outside it.
var builtinDeniedPrefixes = []string{
	"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "100.100.100.200/32", "192.0.0.192/32",
	"::/128", "::1/128", "fe80::/10", "fd00:ec2::254/128",
}

// Guardrails are the platform's scope guardrails.
type Guardrails struct {
	MaxPublicCIDRv4 int
	MaxPublicCIDRv6 int
	deniedSuffixes  []string
	deniedPrefixes  []netip.Prefix
	// codeHosts are the code hosts many organizations share
	// (public_code_hosts.txt plus the operator's).
	codeHosts []string
}

// NewGuardrails builds the guardrails with the operator's caps (0: default)
// and extra denied names and ranges (SCOPE_DENY_EXTRA). An extra entry that
// is neither a name nor a range is reported in bad.
func NewGuardrails(maxV4, maxV6 int, extra []string) (g Guardrails, bad []string) {
	g.MaxPublicCIDRv4, g.MaxPublicCIDRv6 = maxV4, maxV6
	if g.MaxPublicCIDRv4 <= 0 || g.MaxPublicCIDRv4 > 32 {
		g.MaxPublicCIDRv4 = DefaultMaxPublicCIDRv4
	}
	if g.MaxPublicCIDRv6 <= 0 || g.MaxPublicCIDRv6 > 128 {
		g.MaxPublicCIDRv6 = DefaultMaxPublicCIDRv6
	}
	g.deniedSuffixes = append(g.deniedSuffixes, deniedNames...)
	g.codeHosts = append(g.codeHosts, builtinPublicCodeHosts...)
	for _, p := range builtinDeniedPrefixes {
		g.deniedPrefixes = append(g.deniedPrefixes, netip.MustParsePrefix(p))
	}
	for _, e := range extra {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			g.deniedPrefixes = append(g.deniedPrefixes, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			g.deniedPrefixes = append(g.deniedPrefixes, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		if _, n := splitDomainWildcard(e); n != "" && strings.Contains(n, ".") {
			g.deniedSuffixes = append(g.deniedSuffixes, n)
			continue
		}
		bad = append(bad, e)
	}
	return g, bad
}

// DefaultGuardrails are the built-in guardrails with the default caps.
func DefaultGuardrails() Guardrails {
	g, _ := NewGuardrails(0, 0, nil)
	return g
}

// WithPublicCodeHosts adds the operator's shared code hosts
// (SCOPE_PUBLIC_CODE_HOSTS_EXTRA) to the built-in list. Blank entries are
// ignored.
func (g Guardrails) WithPublicCodeHosts(extra []string) Guardrails {
	hosts := slices.Clone(g.codeHosts)
	for _, h := range extra {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	g.codeHosts = hosts
	return g
}

// PublicCodeHost reports whether host is a code host many organizations
// share, where a repository entry must name at least a namespace.
func (g Guardrails) PublicCodeHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return slices.Contains(g.codeHosts, host)
}

// CheckPattern refuses a scope entry the platform does not allow
// (PUBLIC_SUFFIX, DENY_LIST, CIDR_TOO_LARGE, SHARED_CODE_HOST). Other types
// pass.
func (g Guardrails) CheckPattern(t TargetType, pattern string) error {
	switch t {
	case TargetTypeRepository:
		host := RepositoryPatternHost(pattern)
		if g.deniedHost(host) {
			return ErrDenyList
		}
		if RepositoryHostWide(pattern) && g.PublicCodeHost(host) {
			return ErrSharedCodeHost
		}
	case TargetTypeDomain, TargetTypeSubdomain, TargetTypeEmailDomain:
		wild, host := splitDomainWildcard(pattern)
		return g.checkHost(host, wild)
	case TargetTypeURL, TargetTypeAPI, TargetTypeWebsite:
		if h := urlHost(pattern); h != "" {
			wild, host := splitDomainWildcard(h)
			if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
				return g.checkSet(ipSet{lo: a.Unmap(), hi: a.Unmap()})
			}
			return g.checkHost(host, wild)
		}
	case TargetTypeIPAddress, TargetTypeIPRange, TargetTypeCIDR:
		set, ok := parseIPSet(pattern)
		if !ok {
			return nil // ValidatePattern refuses it
		}
		return g.checkSet(set)
	}
	return nil
}

func (g Guardrails) checkHost(host string, wildcard bool) error {
	if host == "" {
		return nil
	}
	if !strings.Contains(host, ".") {
		return ErrPublicSuffix // a bare top-level label
	}
	if g.deniedHost(host) {
		return ErrDenyList
	}
	if ps, _ := publicsuffix.PublicSuffix(host); ps == host {
		return ErrPublicSuffix
	}
	if wildcard {
		for _, a := range sharedProviderApexes {
			if host == a {
				return ErrPublicSuffix
			}
		}
	}
	return nil
}

func (g Guardrails) checkSet(set ipSet) error {
	for _, p := range g.deniedPrefixes {
		if set.overlaps(ipSet{lo: p.Addr(), hi: lastAddr(p)}) {
			return ErrDenyList
		}
	}
	if set.lo.IsPrivate() && set.hi.IsPrivate() {
		return nil // private ranges are gated by scan zones
	}
	bits := 32
	maxBits := g.MaxPublicCIDRv4
	if !set.lo.Is4() {
		bits, maxBits = 128, g.MaxPublicCIDRv6
	}
	// Refuse when the range holds more addresses than a /maxBits.
	size := new(big.Int).Sub(new(big.Int).SetBytes(set.hi.AsSlice()), new(big.Int).SetBytes(set.lo.AsSlice()))
	size.Add(size, big.NewInt(1))
	limit := new(big.Int).Lsh(big.NewInt(1), uint(bits-maxBits)) //nolint:gosec // bits-maxBits is 0..128
	if size.Cmp(limit) > 0 {
		return ErrCIDRTooLarge
	}
	return nil
}

// deniedHost reports whether host is, or is under, a government or military
// name or an operator-denied name.
func (g Guardrails) deniedHost(host string) bool {
	labels := strings.Split(host, ".")
	n := len(labels)
	last := labels[n-1]
	if last == "gov" || last == "mil" {
		return true
	}
	if n >= 2 && len(last) == 2 && governmentSLDs[labels[n-2]] {
		return true
	}
	for _, s := range g.deniedSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// Denies reports whether a dispatch target (name, address, CIDR, URL or
// host:port) is one the platform does not allow probed. The dispatch side of
// the deny list; entries are checked with CheckPattern.
func (g Guardrails) Denies(target string) bool {
	v := strings.TrimSpace(target)
	if h := urlHost(v); h != "" {
		v = h
	}
	// A service in any name form ("203.0.113.5:443:tcp",
	// "203.0.113.5:443/tcp", "[2001:db8::1]:443/tcp") is denied by its host.
	if h, _, _, ok := asset.SplitServiceName(v); ok {
		v = h
	}
	if set, ok := parseIPSet(strings.Trim(v, "[]")); ok {
		return g.checkSet(set) == ErrDenyList //nolint:errorlint // sentinel identity
	}
	if ap, err := netip.ParseAddrPort(v); err == nil {
		a := ap.Addr().Unmap()
		return g.checkSet(ipSet{lo: a, hi: a}) == ErrDenyList //nolint:errorlint // sentinel identity
	}
	_, host := splitDomainWildcard(v)
	if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host[i:], "]") {
		host = host[:i]
	}
	if i := strings.IndexAny(host, "/?#"); i >= 0 {
		host = host[:i]
	}
	if host == "" || !strings.Contains(host, ".") {
		return false
	}
	return g.deniedHost(host)
}

// urlHost is the host of a URL ("" when s is not one).
func urlHost(s string) string {
	if !strings.Contains(s, "://") {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
