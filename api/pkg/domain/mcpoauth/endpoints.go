package mcpoauth

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MCPPath is the path of the MCP endpoint. Its canonical URI is the OAuth
// resource every MCP token is issued for.
const MCPPath = "/api/v1/mcp"

// Well-known paths (RFC 9728 §3, RFC 8414 §3).
const (
	ProtectedResourceMetadataPath   = "/.well-known/oauth-protected-resource"
	AuthorizationServerMetadataPath = "/.well-known/oauth-authorization-server"
)

// Endpoints are the public identifiers of the MCP resource and of the
// authorization server, all derived from the platform's public origin.
type Endpoints struct {
	// Issuer is the authorization server's issuer identifier: the public
	// origin, no path and no trailing slash.
	Issuer string
	// Resource is the canonical URI of the MCP endpoint (RFC 8707 resource,
	// RFC 9728 resource).
	Resource string
	// ResourceMetadata is the URL of the Protected Resource Metadata for
	// Resource, with the path inserted after the well-known prefix.
	ResourceMetadata string
}

// NewEndpoints derives the endpoints from the public origin (APP_URL).
//
// The origin must be an absolute https URL with no path, query, fragment or
// user info; plain http is accepted only for a loopback host (local
// development). The issuer has no path so that every MCP client finds the
// authorization server metadata at the first well-known location it tries.
func NewEndpoints(publicURL string) (Endpoints, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(publicURL), "/"))
	if err != nil || u.Host == "" {
		return Endpoints{}, fmt.Errorf("%w: public URL must be an absolute URL", shared.ErrValidation)
	}
	scheme := strings.ToLower(u.Scheme)
	switch {
	case scheme == "https":
	case scheme == "http" && isLoopbackHost(u.Hostname()):
	default:
		return Endpoints{}, fmt.Errorf("%w: public URL must use https", shared.ErrValidation)
	}
	if u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return Endpoints{}, fmt.Errorf("%w: public URL must be an origin (no path, query, fragment or user info)", shared.ErrValidation)
	}
	issuer := scheme + "://" + strings.ToLower(u.Host)
	return Endpoints{
		Issuer:           issuer,
		Resource:         issuer + MCPPath,
		ResourceMetadata: issuer + ProtectedResourceMetadataPath + MCPPath,
	}, nil
}

// Origin returns the issuer as a browser origin (the same string).
func (e Endpoints) Origin() string { return e.Issuer }

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
