package tenant

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// MCP policy bounds (RFC-062 §8).
const (
	MaxMCPClientHosts  = 50
	MaxMCPRefreshDays  = 90
	mcpHostMaxLen      = 253
	mcpSettingsDefault = "the platform default"
)

// mcpScopeRe is the shape of an MCP scope. Which scopes exist is the MCP
// authorization server's catalog (pkg/domain/mcpoauth), checked where the
// policy is written; this package cannot import it (permission imports
// tenant).
var mcpScopeRe = regexp.MustCompile(`^mcp:[a-z]+\.(read|write)$`)

var mcpHostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)

// MCPSettings is the organization's policy for AI applications that connect
// to the MCP server (RFC-062 §8). The zero value is the default: MCP on,
// only verified applications (registered by the organization or published
// on a host in ClientHosts or the platform list), every read scope, oct_ keys
// accepted, refresh for up to 90 days. Stored as "disabled" flags so a
// tenant that never saved the section gets the defaults.
type MCPSettings struct {
	// Disabled refuses every MCP request of the organization (tokens and
	// keys) and every consent.
	Disabled bool `json:"disabled,omitempty"`
	// AnyClient lets members connect applications that are not verified;
	// they stay marked as such on the consent page.
	AnyClient bool `json:"any_client,omitempty"`
	// ClientHosts are host names whose Client ID Metadata Documents count
	// as verified, in addition to the platform list.
	ClientHosts []string `json:"client_hosts,omitempty"`
	// Scopes the organization's members may grant; empty means every read
	// scope.
	Scopes []string `json:"scopes,omitempty"`
	// APIKeysDisabled refuses oct_ keys on the MCP endpoint (they keep
	// working on the REST API).
	APIKeysDisabled bool `json:"api_keys_disabled,omitempty"`
	// RefreshDays bounds how long a connection lasts without the person
	// approving it again; 0 means 90.
	RefreshDays int `json:"refresh_days,omitempty"`
	// RequireDPoP accepts only DPoP-bound tokens (RFC 9449): a stolen token
	// is useless without the client's private key.
	RequireDPoP bool `json:"require_dpop,omitempty"`
}

// Validate checks the policy and normalizes host names to lower case.
func (s *MCPSettings) Validate() error {
	if len(s.ClientHosts) > MaxMCPClientHosts {
		return fmt.Errorf("%w: at most %d client hosts", shared.ErrValidation, MaxMCPClientHosts)
	}
	seen := map[string]bool{}
	hosts := make([]string, 0, len(s.ClientHosts))
	for _, h := range s.ClientHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if len(h) > mcpHostMaxLen || !mcpHostRe.MatchString(h) {
			return fmt.Errorf("%w: %q is not a host name (no scheme, path or wildcard)", shared.ErrValidation, h)
		}
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	s.ClientHosts = hosts
	for _, sc := range s.Scopes {
		if !mcpScopeRe.MatchString(sc) {
			return fmt.Errorf("%w: unknown scope %q", shared.ErrValidation, sc)
		}
	}
	if s.RefreshDays < 0 || s.RefreshDays > MaxMCPRefreshDays {
		return fmt.Errorf("%w: refresh_days must be between 1 and %d (or 0 for %s)", shared.ErrValidation, MaxMCPRefreshDays, mcpSettingsDefault)
	}
	return nil
}

// RefreshLimitDays is the effective connection lifetime in days.
func (s MCPSettings) RefreshLimitDays() int {
	if s.RefreshDays <= 0 {
		return MaxMCPRefreshDays
	}
	return s.RefreshDays
}

// UpdateMCPSettings replaces the tenant's MCP policy.
func (t *Tenant) UpdateMCPSettings(s MCPSettings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	settings := t.TypedSettings()
	settings.MCP = s
	return t.UpdateSettings(settings)
}
