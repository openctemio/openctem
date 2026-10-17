package config

import (
	"fmt"
	"net"
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

	// ListenAllowAllInterfaces lets ListenAddr be any address: every
	// interface, a public IP or a hostname. Off (the default), only a
	// loopback or private IP is accepted.
	// ADMIN_LISTEN_ALLOW_ALL_INTERFACES
	ListenAllowAllInterfaces bool

	// Plane is what this process serves (OPENCTEM_PLANE, RFC-022 revision
	// 21): PlaneAll (the default, one process for everything), PlaneTenant
	// (never the console) or PlaneAdmin (only the console API). A hosted
	// deployment runs the same image twice, as tenant and as admin.
	Plane string

	// allowed is AllowedCIDRs parsed by validateAdminPlane.
	allowed []netip.Prefix
}

// The planes a process can serve (OPENCTEM_PLANE).
const (
	// PlaneAll serves everything in one process (self-host).
	PlaneAll = "all"
	// PlaneTenant never registers the console routes and holds no console
	// database credentials; it runs the background work.
	PlaneTenant = "tenant"
	// PlaneAdmin serves only the console API (and the health probe) on its
	// main listener, with the console database role, and runs no
	// background work.
	PlaneAdmin = "admin"
)

// ServesConsole reports whether this process serves the console API.
func (c AdminPlaneConfig) ServesConsole() bool { return c.Plane != PlaneTenant }

// ServesTenant reports whether this process serves the tenant, sensor and
// public routes and runs the background work.
func (c AdminPlaneConfig) ServesTenant() bool { return c.Plane != PlaneAdmin }

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
// /128), separated by commas or spaces. An empty list is an error: it would lock the console out for good.
func ParseAdminAllowedCIDRs(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	// Commas or spaces: the gateway's OPENCTEM_ADMIN_ALLOWED_CIDRS is
	// space-separated, so one value can feed both.
	var fields []string
	for _, e := range entries {
		fields = append(fields, strings.Fields(e)...)
	}
	for _, e := range fields {
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
	// The console's CSRF token is signed with a key every replica must share
	// (the session-signing secret). Without one each process draws its own
	// random key, and a token issued by one replica fails on the next.
	if c.IsProduction() && c.Auth.JWTSecret == "" {
		return fmt.Errorf("the platform console needs a secret shared by every replica for its CSRF tokens: " +
			"set AUTH_JWT_SECRET (or APP_ENCRYPTION_KEY, from which it is derived)")
	}
	if err := c.validatePlane(); err != nil {
		return err
	}
	if c.AdminPlane.ListenAddr != "" {
		if c.AdminPlane.ListenAddr == c.Server.Addr() {
			return fmt.Errorf("ADMIN_LISTEN_ADDR must differ from the main listener (%s)", c.Server.Addr())
		}
		if err := checkAdminListenAddr(c.AdminPlane.ListenAddr, c.AdminPlane.ListenAllowAllInterfaces); err != nil {
			return err
		}
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

// checkAdminListenAddr accepts only a loopback or private IP (10/8,
// 172.16/12, 192.168/16, fc00::/7) for the console's plain-HTTP listener,
// unless allowAll: every interface, a public or link-local IP, or a hostname
// would put it on networks nobody chose.
func checkAdminListenAddr(addr string, allowAll bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("ADMIN_LISTEN_ADDR %q is not host:port: %w", addr, err)
	}
	if allowAll {
		return nil
	}
	if ip := net.ParseIP(host); ip == nil || !(ip.IsLoopback() || ip.IsPrivate()) {
		return fmt.Errorf("ADMIN_LISTEN_ADDR %q is not a loopback or private IP address; bind one (for example 10.0.0.5:8081), "+
			"or set ADMIN_LISTEN_ALLOW_ALL_INTERFACES=true when only a private network reaches it", addr)
	}
	return nil
}

// validatePlane checks OPENCTEM_PLANE against what each plane must and must
// not have: a tenant process holds no console credentials and opens no
// console listener; an admin process serves the console on its main listener
// (a private address unless explicitly allowed) with the console role.
func (c *Config) validatePlane() error {
	switch c.AdminPlane.Plane {
	case "", PlaneAll:
		c.AdminPlane.Plane = PlaneAll
	case PlaneTenant:
		if c.AdminPlane.ListenAddr != "" {
			return fmt.Errorf("OPENCTEM_PLANE=tenant serves no console: unset ADMIN_LISTEN_ADDR")
		}
		if c.Database.AdminUser != "" || c.Database.AdminPassword != "" {
			return fmt.Errorf("OPENCTEM_PLANE=tenant holds no console database credentials: unset DB_ADMIN_USER and DB_ADMIN_PASSWORD")
		}
	case PlaneAdmin:
		if c.AdminPlane.ListenAddr != "" {
			return fmt.Errorf("OPENCTEM_PLANE=admin serves the console on its main listener (SERVER_HOST, SERVER_PORT): unset ADMIN_LISTEN_ADDR")
		}
		if c.Database.AdminUser == "" {
			return fmt.Errorf("OPENCTEM_PLANE=admin needs the console database role (DB_ADMIN_USER, DB_ADMIN_PASSWORD)")
		}
		if err := checkAdminListenAddr(c.Server.Addr(), c.AdminPlane.ListenAllowAllInterfaces); err != nil {
			return fmt.Errorf("OPENCTEM_PLANE=admin: the main listener is the console's: %w", err)
		}
	default:
		return fmt.Errorf("OPENCTEM_PLANE=%q is not one of: all, tenant, admin", c.AdminPlane.Plane)
	}
	return nil
}
