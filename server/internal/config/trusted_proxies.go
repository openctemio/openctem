package config

import (
	"net/netip"
	"strings"
)

// A trusted proxy may set the client address the API believes (rate-limit
// keys, audit addresses, IP allowlists). Listing a whole container network
// trusts every container on it, including a sensor that runs third-party
// tools. These ranges should name the gateway (and the web server) only.
//
// maxTrustedProxyBits sets the widest range reported as fine: 16
// addresses (an IPv4 /28, an IPv6 /124) covers a small proxy pool.
const maxTrustedProxyBits = 4

// WideTrustedProxies returns the SERVER_TRUSTED_PROXIES and
// SENSOR_MTLS_TRUSTED_PROXIES entries that cover more than 16 addresses,
// each prefixed with its variable name. Unparseable entries are left to the
// code that parses them.
func (c *Config) WideTrustedProxies() []string {
	var wide []string
	for _, v := range []struct {
		name    string
		entries []string
	}{
		{"SERVER_TRUSTED_PROXIES", c.Server.TrustedProxies},
		{"SENSOR_MTLS_TRUSTED_PROXIES", c.SensorConfig.TransportV3.MTLSTrustedProxies},
	} {
		for _, e := range v.entries {
			e = strings.TrimSpace(e)
			p, err := netip.ParsePrefix(e)
			if err != nil {
				continue // a bare address, or invalid
			}
			if p.Addr().BitLen()-p.Bits() > maxTrustedProxyBits {
				wide = append(wide, v.name+"="+e)
			}
		}
	}
	return wide
}
