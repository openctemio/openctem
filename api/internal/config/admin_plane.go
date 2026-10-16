package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// AdminPlaneConfig is where the platform administration console may be
// reached from (RFC-022 revision 20, the admin plane).
type AdminPlaneConfig struct {
	// AllowedCIDRs are the client networks that may reach /api/v1/admin.
	// ADMIN_ALLOWED_CIDRS (comma-separated CIDRs or addresses); default
	// DefaultAdminAllowedCIDRs, private networks only. "0.0.0.0/0,::/0"
	// allows every network, an explicit choice for an internet-facing console.
	AllowedCIDRs []string

	// ListenAddr is the console's own listener (ADMIN_LISTEN_ADDR, e.g.
	// ":8081"). Set, the console API is served only there and the main
	// listener answers 404 for it; empty (the default), it shares the main
	// listener.
	ListenAddr string

	// allowed is AllowedCIDRs parsed by validateAdminPlane.
	allowed []netip.Prefix
}

// DefaultAdminAllowedCIDRs are loopback, the RFC 1918 ranges and IPv6 unique
// local addresses: an operator on the host, a VPN or the internal network.
var DefaultAdminAllowedCIDRs = []string{
	"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7",
}

// AllowedPrefixes returns the parsed console allow-list: the one Validate
// parsed, else AllowedCIDRs parsed now, else (unparseable or unset) the
// private-network default. It never returns an empty list.
func (c AdminPlaneConfig) AllowedPrefixes() []netip.Prefix {
	if len(c.allowed) > 0 {
		return c.allowed
	}
	if p, err := ParseAdminAllowedCIDRs(c.AllowedCIDRs); err == nil {
		return p
	}
	p, _ := ParseAdminAllowedCIDRs(DefaultAdminAllowedCIDRs)
	return p
}

// AllowsEveryNetwork reports whether the allow-list covers every address,
// for a startup notice.
func (c AdminPlaneConfig) AllowsEveryNetwork() bool {
	var v4, v6 bool
	for _, p := range c.allowed {
		if p.Bits() == 0 {
			v4, v6 = v4 || p.Addr().Is4(), v6 || p.Addr().Is6()
		}
	}
	return v4 && v6
}

// ParseAdminAllowedCIDRs parses CIDRs or single addresses (taken as /32 or
// /128). An empty list is an error: it would lock the console out for good.
func ParseAdminAllowedCIDRs(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(e)
		if err != nil {
			return nil, fmt.Errorf("ADMIN_ALLOWED_CIDRS: %q is not a CIDR or an IP address", e)
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ADMIN_ALLOWED_CIDRS: no network listed")
	}
	return out, nil
}

func (c *Config) validateAdminPlane() error {
	if c.AdminPlane.ListenAddr != "" && c.AdminPlane.ListenAddr == c.Server.Addr() {
		return fmt.Errorf("ADMIN_LISTEN_ADDR must differ from the main listener (%s)", c.Server.Addr())
	}
	if len(c.AdminPlane.AllowedCIDRs) == 0 {
		c.AdminPlane.AllowedCIDRs = DefaultAdminAllowedCIDRs
	}
	p, err := ParseAdminAllowedCIDRs(c.AdminPlane.AllowedCIDRs)
	if err != nil {
		return err
	}
	c.AdminPlane.allowed = p
	return nil
}
