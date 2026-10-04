package dnsprobe

import "net"

// SystemResolverForTest exposes systemResolver to the external test package.
var SystemResolverForTest = systemResolver

// AllowServersForTest lets QueryServer reach test servers on loopback at
// port.
func AllowServersForTest(c *Client, port string) {
	c.authPort = port
	c.ipAllowed = func(net.IP) bool { return true }
}
