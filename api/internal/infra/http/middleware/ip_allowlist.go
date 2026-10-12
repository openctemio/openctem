package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// CodeIPNotAllowed is the error code for a request refused by an
// organization's IP allowlist (Security.IPWhitelist).
const CodeIPNotAllowed apierror.Code = "IP_NOT_ALLOWED"

// TenantSecurityPolicyProvider returns an organization's security settings.
type TenantSecurityPolicyProvider interface {
	SecuritySettings(ctx context.Context, tenantID string) (tenantdom.SecuritySettings, error)
}

// IPAllowlistGate enforces each organization's Security.IPWhitelist on user
// sessions and on the organization's `oct_` API keys. It applies to requests
// authenticated with a user's access token or an `oct_` key, for the
// organization the request acts on: the organization in the URL
// (/tenants/{tenant}/...) when there is one, else the organization the token
// or key belongs to. Every surface an `oct_` key can reach runs it: the tenant
// REST API (buildBaseMiddlewares) and the MCP endpoint (mcpMiddlewares).
//
// Deliberately outside the gate (each has its own credential and its caller
// is not on the organization's network):
//   - sensor keys: sensors run in scan zones and customer networks, with their
//     own enrollment, key and egress controls (RFC-023, RFC-032, RFC-034);
//   - SCIM (/scim/v2): the caller is the organization's identity provider
//     (Entra ID, Okta), a SaaS whose egress addresses are not the users'
//     network. Gating it would also stop deprovisioning (leavers stay active).
//     The owner-minted SCIM token is the boundary;
//   - inbound integration webhooks (Jira): sent from the vendor's cloud and
//     authenticated by the per-tenant webhook secret;
//   - the platform admin console and public routes (login, token exchange).
//
// The client IP comes from httpsec.ClientIP: forwarding headers are honored
// only from SERVER_TRUSTED_PROXIES, so a client cannot claim an allowed IP.
// Policies are cached per organization for a short TTL; Invalidate drops one
// after a settings change. A policy lookup error is fail-closed.
type IPAllowlistGate struct {
	provider TenantSecurityPolicyProvider
	ttl      time.Duration
	logger   *logger.Logger
	clientIP func(*http.Request) string

	mu    sync.RWMutex
	cache map[string]cachedIPPolicy
}

type cachedIPPolicy struct {
	policy tenantdom.SecuritySettings
	expiry time.Time
}

// NewIPAllowlistGate constructs the gate. A zero ttl defaults to 30s.
func NewIPAllowlistGate(provider TenantSecurityPolicyProvider, ttl time.Duration, log *logger.Logger) *IPAllowlistGate {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &IPAllowlistGate{
		provider: provider,
		ttl:      ttl,
		logger:   log.With("middleware", "ip_allowlist"),
		clientIP: getClientIP,
		cache:    make(map[string]cachedIPPolicy),
	}
}

// RequestClientIP returns the client IP the API attributes a request to, the
// same value the IP allowlist checks (trusted-proxy aware).
func RequestClientIP(r *http.Request) string { return getClientIP(r) }

func (g *IPAllowlistGate) policy(ctx context.Context, tenantID string) (tenantdom.SecuritySettings, error) {
	now := time.Now()
	g.mu.RLock()
	if e, ok := g.cache[tenantID]; ok && now.Before(e.expiry) {
		g.mu.RUnlock()
		return e.policy, nil
	}
	g.mu.RUnlock()

	p, err := g.provider.SecuritySettings(ctx, tenantID)
	if err != nil {
		return tenantdom.SecuritySettings{}, err
	}
	g.mu.Lock()
	g.cache[tenantID] = cachedIPPolicy{policy: p, expiry: now.Add(g.ttl)}
	g.mu.Unlock()
	return p, nil
}

// Invalidate drops an organization's cached policy so a change applies at once.
func (g *IPAllowlistGate) Invalidate(tenantID string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	delete(g.cache, tenantID)
	g.mu.Unlock()
}

// Enforce is the middleware. Must run after authentication (needs the token
// claims) and, on /tenants/{tenant} routes, after TenantContext.
func (g *IPAllowlistGate) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g == nil || g.provider == nil {
			next.ServeHTTP(w, r)
			return
		}
		claims := GetLocalClaims(r.Context())
		var tenantID, subject string
		switch {
		case claims != nil:
			tenantID, subject = claims.TenantID, claims.UserID
		case IsAPIKeyAuthenticated(r.Context()):
			// An organization's network policy binds its API keys too.
			tenantID, subject = GetTenantID(r.Context()), GetUserID(r.Context())
		default:
			// Not a user access token or API key (sensor, OIDC provider mode).
			next.ServeHTTP(w, r)
			return
		}
		if urlTenant := GetTeamID(r.Context()); !urlTenant.IsZero() {
			tenantID = urlTenant.String()
		}
		if tenantID == "" {
			next.ServeHTTP(w, r)
			return
		}

		p, err := g.policy(r.Context(), tenantID)
		if err != nil {
			g.logger.Warn("IP allowlist lookup failed; denying (fail-closed)", "tenant_id", tenantID)
			apierror.New(http.StatusForbidden, CodeIPNotAllowed, "Access to this organization could not be verified").WriteJSON(w)
			return
		}
		if !p.IPAllowed(g.clientIP(r)) {
			g.logger.Info("request blocked by organization IP allowlist",
				"tenant_id", tenantID, "user_id", subject, "api_key_id", GetAPIKeyID(r.Context()))
			apierror.New(http.StatusForbidden, CodeIPNotAllowed,
				"Access to this organization from your network is not allowed").WriteJSON(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}
