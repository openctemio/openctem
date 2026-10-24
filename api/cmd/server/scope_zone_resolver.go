package main

import (
	"context"
	"net"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
)

// zoneResolver is the resolver scan-zone routing resolves hostnames with:
// the platform's own for "system", else one that asks only the given
// recursive resolver (host[:port], port 53 by default), so tenants cannot
// resolve names through the platform's internal DNS.
func zoneResolver(spec string) *net.Resolver {
	if spec == "" || spec == config.ScanZoneResolverSystem {
		return net.DefaultResolver
	}
	server := spec
	if _, _, err := net.SplitHostPort(spec); err != nil {
		server = net.JoinHostPort(spec, "53")
	}
	d := &net.Dialer{Timeout: 3 * time.Second}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, server)
		},
	}
}
