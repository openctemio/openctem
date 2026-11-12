package assetdomain

import (
	"errors"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// The asset_domain filter of findings (docs/architecture/asset-domain-membership.md):
// "x" is the name x and every name under it; "*.x" is only the names under
// x. Values are matched against the precomputed membership keys of assets
// (asset_domain_memberships.key), never as a pattern.

var (
	errDomainEmpty  = errors.New("not a domain name")
	errDomainSuffix = errors.New("a public suffix (such as com or com.vn) is not a domain of the organization; give a registrable name")
)

// NormalizeDomainFilter checks an asset_domain value and returns it in the
// form the membership keys use: lower case, no trailing dot, IDNA A-labels
// (punycode), an optional leading "*." kept. A bare public suffix is refused.
func NormalizeDomainFilter(v string) (string, error) {
	v = strings.TrimSpace(v)
	wild := false
	if rest, ok := strings.CutPrefix(v, "*."); ok {
		wild, v = true, rest
	}
	name, ok := NormalizeDNSName(v)
	if !ok || !strings.Contains(name, ".") {
		return "", errDomainEmpty
	}
	if suffix, _ := publicsuffix.PublicSuffix(name); suffix == name {
		return "", errDomainSuffix
	}
	if wild {
		return "*." + name, nil
	}
	return name, nil
}

// DomainFilterKeys are the membership keys a normalised asset_domain value
// matches: "*.x" only the key "*.x" (names under x); "x" also the key "x"
// (the name x itself).
func DomainFilterKeys(v string) []string {
	if strings.HasPrefix(v, "*.") {
		return []string{v}
	}
	return []string{v, "*." + v}
}

// NormalizeDNSName returns a host name lower-cased, without a trailing dot,
// in IDNA A-label form, or false when it is not a DNS name (an address, a
// URL, a label with characters a host name cannot hold). Underscore labels
// (_dmarc, SRV names) are kept.
func NormalizeDNSName(s string) (string, bool) {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if s == "" || len(s) > 253 {
		return "", false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return "", false
	}
	ascii, err := idnaProfile.ToASCII(s)
	if err != nil {
		return "", false
	}
	for _, label := range strings.Split(ascii, ".") {
		if label == "" || len(label) > 63 {
			return "", false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return "", false
			}
		}
	}
	return ascii, true
}

// idnaProfile maps Unicode names to A-labels without the strict STD3 rules,
// so underscore labels stay valid; NormalizeDNSName checks the characters.
var idnaProfile = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(false))
