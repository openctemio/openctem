package mcpoauth

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// PolicyReader returns an organization's MCP policy (RFC-062 §8).
type PolicyReader interface {
	MCPPolicy(ctx context.Context, tenantID shared.ID) (tenantdom.MCPSettings, error)
}

// ErrPolicy is a consent the organization's MCP policy does not allow.
var ErrPolicy = fmt.Errorf("%w: your organization does not allow this application", shared.ErrForbidden)

// Why a request is blocked by policy, as the consent page shows it.
const (
	BlockedMCPDisabled    = "mcp_disabled"
	BlockedClientNotFound = "client_not_allowed"
)

// policy reads the organization's MCP policy. Without a reader (tests,
// minimal wiring) the defaults apply; a read error fails closed.
func (s *Service) policy(ctx context.Context, tenantID shared.ID) (tenantdom.MCPSettings, error) {
	if s.policies == nil {
		return tenantdom.MCPSettings{}, nil
	}
	return s.policies.MCPPolicy(ctx, tenantID)
}

// verifiedClient reports whether the organization can vouch for the client:
// registered by this organization (or by the platform operator), or a
// metadata document published on a host the organization or the platform
// lists.
func (s *Service) verifiedClient(p tenantdom.MCPSettings, c mcpoauth.Client, tenantID shared.ID) bool {
	switch c.Kind {
	case mcpoauth.ClientKindOrganization:
		return c.TenantID == nil || *c.TenantID == tenantID
	case mcpoauth.ClientKindMetadataDocument:
		host := clientHost(c)
		for _, h := range p.ClientHosts {
			if h == host {
				return true
			}
		}
		for _, h := range s.trustedHosts {
			if h == host {
				return true
			}
		}
	}
	return false
}

// blockedReason is why the policy refuses the client in the organization,
// or "" when it allows it.
func (s *Service) blockedReason(p tenantdom.MCPSettings, c mcpoauth.Client, tenantID shared.ID) string {
	if p.Disabled {
		return BlockedMCPDisabled
	}
	// Another organization's client is never usable here.
	if c.Kind == mcpoauth.ClientKindOrganization && c.TenantID != nil && *c.TenantID != tenantID {
		return BlockedClientNotFound
	}
	if s.verifiedClient(p, c, tenantID) || p.AnyClient {
		return ""
	}
	return BlockedClientNotFound
}

// allowsScope reports whether the policy lets members grant sc: the listed
// scopes, or every read scope when none are listed.
func allowsScope(p tenantdom.MCPSettings, sc mcpoauth.Scope) bool {
	if len(p.Scopes) == 0 {
		return !mcpoauth.IsWrite(sc)
	}
	for _, x := range p.Scopes {
		if x == string(sc) {
			return true
		}
	}
	return false
}

// allowedScopes filters scopes by the policy.
func allowedScopes(p tenantdom.MCPSettings, scopes []mcpoauth.Scope) []mcpoauth.Scope {
	out := make([]mcpoauth.Scope, 0, len(scopes))
	for _, sc := range scopes {
		if allowsScope(p, sc) {
			out = append(out, sc)
		}
	}
	return out
}

// grantLifetime is how long a new connection may last under the policy.
func grantLifetime(p tenantdom.MCPSettings) time.Duration {
	return time.Duration(p.RefreshLimitDays()) * 24 * time.Hour
}

// ValidatePolicy checks a policy before it is stored: the generic shape
// (tenant.MCPSettings.Validate) plus scopes that exist in the catalog.
func ValidatePolicy(p *tenantdom.MCPSettings) error {
	if err := p.Validate(); err != nil {
		return err
	}
	for _, sc := range p.Scopes {
		if !mcpoauth.Known(mcpoauth.Scope(sc)) {
			return fmt.Errorf("%w: unknown scope %q", shared.ErrValidation, sc)
		}
	}
	return nil
}

// NormalizeTrustedHosts cleans the platform list of trusted client hosts
// (MCP_OAUTH_TRUSTED_CLIENT_HOSTS): lower case, no scheme or path.
func NormalizeTrustedHosts(in []string) []string {
	out := make([]string, 0, len(in))
	for _, h := range in {
		h = strings.ToLower(strings.TrimSpace(h))
		if u, err := url.Parse(h); err == nil && u.Host != "" {
			h = u.Hostname()
		}
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}
