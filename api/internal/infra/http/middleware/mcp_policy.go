package middleware

import (
	"context"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// MCPPolicyReader returns an organization's MCP policy (RFC-062 §8).
type MCPPolicyReader interface {
	MCPPolicy(ctx context.Context, tenantID shared.ID) (tenantdom.MCPSettings, error)
}

// MCPKeyPolicyGate applies the organization's MCP policy to oct_ key
// requests on the MCP endpoint: MCP turned off, or keys turned off for MCP,
// is 403. It runs after authentication. Access tokens are checked by the
// authorization server itself on every request, so they pass through here.
// A policy that cannot be read refuses the request (fail closed).
func MCPKeyPolicyGate(policies MCPPolicyReader, log *logger.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			if policies == nil || GetAuthProvider(ctx) != AuthProviderAPIKey {
				next.ServeHTTP(w, r)
				return
			}
			tenantID, err := shared.IDFromString(GetTenantID(ctx))
			if err != nil {
				apierror.Unauthorized("Invalid credentials").WriteJSON(w)
				return
			}
			p, err := policies.MCPPolicy(ctx, tenantID)
			if err != nil {
				log.Warn("mcp policy read failed", "error", err.Error())
				apierror.ServiceUnavailable("Try again later").WriteJSON(w)
				return
			}
			if p.Disabled || p.APIKeysDisabled {
				apierror.Forbidden("Your organization does not allow API keys on the MCP server").WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
