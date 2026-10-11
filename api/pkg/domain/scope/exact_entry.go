package scope

import (
	"net/netip"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
)

// ExactEntryFor is the exact scope entry that covers one probe target (an
// asset name, a URL, a service, an address or a network): the name itself,
// the host of a URL or service, the address, or the network. Never a
// wildcard. ok is false for what needs no entry: internal names and private
// addresses (scan zones gate them), text that names no host (a repository
// path, an identifier) and anything that is not a valid name or address.
// Design: docs/rfcs/RFC-054-scope-model.md §14.
func ExactEntryFor(target string) (TargetType, string, bool) {
	t := strings.TrimSpace(target)
	if t == "" || strings.Contains(t, "*") || InternalName(t) || !NeedsAuthority(t) {
		return "", "", false
	}
	if p, err := netip.ParsePrefix(strings.Trim(t, "[]")); err == nil {
		p = p.Masked()
		if p.Bits() == p.Addr().BitLen() {
			return TargetTypeIPAddress, p.Addr().String(), true
		}
		return TargetTypeCIDR, p.String(), true
	}
	if a, err := netip.ParseAddr(strings.Trim(asset.HostOf(t), "[]")); err == nil {
		return TargetTypeIPAddress, a.Unmap().String(), true
	}
	h := probeHost(t)
	if h == "" || ValidatePattern(TargetTypeDomain, h) != nil {
		return "", "", false
	}
	return TargetTypeDomain, h, true
}
