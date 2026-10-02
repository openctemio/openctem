package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/apierror"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// CodeIPNotAllowed is the error code for a request refused by an
// organization's IP allowlist (Security.IPWhitelist).
const CodeIPNotAllowed apierror.Code = "IP_NOT_ALLOWED"

// TenantSecurityPolicyProvider returns an organization's security settings.
type TenantSecurityPolicyProvider interface {
	SecuritySettings(ctx context.Context, tenantID string) (tenantdom.SecuritySettings, error)
}

// IPAllowlistGate enforces each organization's Security.IPWhitelist on user
// sessions. It applies to requests authenticated with a user's
// access token, for the organization the request acts on: the organization in
// the URL (/tenants/{tenant}/...) when there is one, else the organization the
// token is scoped to. It does not apply to sensor/agent API keys, tenant API
// keys, the platform admin console, or public routes, none of which carry a
// user access token.
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
