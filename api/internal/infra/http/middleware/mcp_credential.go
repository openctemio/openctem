package middleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	mcpoauthapp "github.com/openctemio/openctem/api/internal/app/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/mcpoauth"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AuthProviderMCPOAuth is the AuthProviderKey value for a request
// authenticated by an MCP OAuth access token (RFC-062).
const AuthProviderMCPOAuth = "mcp_oauth"

// MCPPrincipalKey holds the *mcpoauthapp.Principal of a request
// authenticated by an MCP OAuth access token.
const MCPPrincipalKey logger.ContextKey = "mcp_principal"

// MCPGrantRateLimitPerHour is the request budget of one grant (one person,
// one client, one organization) on the MCP endpoint.
const MCPGrantRateLimitPerHour = 3600

// MCPTokenAuthenticator checks an MCP OAuth access token
// (*mcpoauthapp.Service).
type MCPTokenAuthenticator interface {
	AuthenticateAccessToken(ctx context.Context, raw, ip string, dp mcpoauthapp.DPoPRequest) (*mcpoauthapp.Principal, error)
}

// GetMCPPrincipal returns the OAuth principal of the request, or nil when
// the request was not authenticated by an MCP access token.
func GetMCPPrincipal(ctx context.Context) *mcpoauthapp.Principal {
	p, _ := ctx.Value(MCPPrincipalKey).(*mcpoauthapp.Principal)
	return p
}

// MCPCredentialAuth authenticates the MCP endpoint. A bearer token with the
// access-token prefix goes to the authorization server's token check;
// anything else goes to the oct_ key authenticator, which refuses whatever
// is not a valid key. The two never mix: an access token sent together with
// an X-API-Key header is refused as ambiguous.
//
// For an access token the context carries the grant's tenant and user, the
// effective permissions (granted scopes intersected with what the user holds
// now), never the owner/admin bypass, and the principal for the audit trail
// and scope challenges.
func MCPCredentialAuth(apiKeyAuth func(http.Handler) http.Handler, tokens MCPTokenAuthenticator, log *logger.Logger) func(http.Handler) http.Handler {
	limiter := newAPIKeyRateLimiter()
	return func(next http.Handler) http.Handler {
		keyChain := apiKeyAuth(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			scheme, raw := authorizationToken(r)
			if tokens == nil || !strings.HasPrefix(raw, mcpoauth.AccessTokenPrefix) {
				keyChain.ServeHTTP(w, r)
				return
			}
			proofs := r.Header.Values("DPoP")
			if r.Header.Get("X-API-Key") != "" || len(proofs) > 1 {
				apierror.Unauthorized("Invalid credentials").WriteJSON(w)
				return
			}
			dp := mcpoauthapp.DPoPRequest{Scheme: scheme, Method: r.Method}
			if len(proofs) == 1 {
				dp.Proof = proofs[0]
			}
			p, err := tokens.AuthenticateAccessToken(r.Context(), raw, getClientIP(r), dp)
			if err != nil {
				log.Debug("mcp access token refused", "reason", err.Error())
				if errors.Is(err, mcpoauthapp.ErrDPoP) {
					// RFC 9449 §7.1: the challenge names the DPoP scheme.
					w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof", algs="`+strings.Join(mcpoauthapp.DPoPAlgorithms(), " ")+`"`)
				}
				apierror.Unauthorized("Invalid credentials").WriteJSON(w)
				return
			}
			if !limiter.allow("grant:"+p.GrantID, MCPGrantRateLimitPerHour) {
				apierror.TooManyRequests("Rate limit exceeded for this connection").WriteJSON(w)
				return
			}
			perms := p.Permissions
			if perms == nil {
				perms = []string{}
			}
			ctx := r.Context()
			ctx = context.WithValue(ctx, TenantIDKey, p.TenantID)
			ctx = context.WithValue(ctx, UserIDKey, p.UserID)
			ctx = context.WithValue(ctx, PermissionsKey, perms)
			ctx = context.WithValue(ctx, IsAdminKey, false)
			ctx = context.WithValue(ctx, AuthProviderKey, AuthProviderMCPOAuth)
			ctx = context.WithValue(ctx, MCPPrincipalKey, p)
			if ctxLogger := logger.FromContext(ctx); ctxLogger != nil {
				ctx = logger.ToContext(ctx, ctxLogger.WithContext(ctx))
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// authorizationToken returns the scheme and token of the Authorization
// header for the two schemes an MCP access token may use (Bearer, DPoP).
func authorizationToken(r *http.Request) (scheme, token string) {
	scheme, rest, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || (!strings.EqualFold(scheme, "Bearer") && !strings.EqualFold(scheme, "DPoP")) {
		return "", ""
	}
	return scheme, strings.TrimSpace(rest)
}
