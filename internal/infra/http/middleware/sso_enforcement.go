package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/apierror"
	sessiondom "github.com/openctemio/api/pkg/domain/session"
	tenantdom "github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// SSOEnforcedProvider answers whether a tenant currently enforces SSO. It is the
// per-request counterpart of the token-mint-time gate (AuthService.enforceSSOPolicy):
// the mint gate stops a password session from getting a NEW token for an
// SSO-enforced tenant, while this provider lets the middleware re-apply the same
// decision on EVERY request so an already-minted password token cannot keep
// access after the tenant turns enforcement on.
type SSOEnforcedProvider interface {
	// IsSSOEnforced reports whether the tenant requires SSO. A non-nil error means
	// the flag could not be determined; the caller treats that as fail-closed.
	IsSSOEnforced(ctx context.Context, tenantID string) (bool, error)
}

// SSOEnforcementGate caches each tenant's sso_enforced flag with a short TTL so
// the per-request check costs at most one tenant lookup per tenant per TTL
// window (no N+1). Unlike the module gate this is a SECURITY boundary, so a
// cold-miss lookup error is NOT cached and is surfaced to the caller as
// fail-closed. Successful lookups (enforced or not) are cached.
type SSOEnforcementGate struct {
	provider SSOEnforcedProvider
	ttl      time.Duration
	logger   *logger.Logger

	mu    sync.RWMutex
	cache map[string]cachedEnforced
}

type cachedEnforced struct {
	enforced bool
	expiry   time.Time
}

// NewSSOEnforcementGate constructs a gate. A zero ttl defaults to 60s.
func NewSSOEnforcementGate(provider SSOEnforcedProvider, ttl time.Duration, log *logger.Logger) *SSOEnforcementGate {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &SSOEnforcementGate{
		provider: provider,
		ttl:      ttl,
		logger:   log.With("middleware", "sso_enforcement"),
		cache:    make(map[string]cachedEnforced),
	}
}

// isEnforced returns the tenant's sso_enforced flag, using the TTL cache. On a
// cold-miss lookup error it returns (false, err) — callers fail closed.
func (g *SSOEnforcementGate) isEnforced(ctx context.Context, tenantID string) (bool, error) {
	now := time.Now()
	g.mu.RLock()
	if e, ok := g.cache[tenantID]; ok && now.Before(e.expiry) {
		g.mu.RUnlock()
		return e.enforced, nil
	}
	g.mu.RUnlock()

	enforced, err := g.provider.IsSSOEnforced(ctx, tenantID)
	if err != nil {
		return false, err
	}
	g.mu.Lock()
	g.cache[tenantID] = cachedEnforced{enforced: enforced, expiry: now.Add(g.ttl)}
	g.mu.Unlock()
	return enforced, nil
}

// Invalidate drops a tenant's cached flag so a security-settings change takes
// effect immediately rather than after the TTL.
func (g *SSOEnforcementGate) Invalidate(tenantID string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	delete(g.cache, tenantID)
	g.mu.Unlock()
}

// Enforce is the per-request SSO-enforcement middleware. It re-applies the
// mint-time decision using the signed access-token claims:
//
//   - Federated sessions (auth_method sso/saml) ALWAYS pass — an SSO-enforced
//     tenant must admit the very login method it requires.
//   - The tenant OWNER always passes (break-glass — enabling enforcement can
//     never lock every administrator out).
//   - Any other (non-owner, non-federated) session is rejected when its token's
//     tenant enforces SSO.
//
// Both cheap exits (federated / owner) skip the tenant lookup entirely, so the
// common case costs nothing. Must run AFTER UnifiedAuth (needs the local claims).
// A request without local JWT claims (e.g. OIDC/Keycloak provider, or no tenant
// bound to the token) passes through — this gate only governs local
// tenant-scoped tokens.
func (g *SSOEnforcementGate) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g == nil || g.provider == nil {
			next.ServeHTTP(w, r)
			return
		}

		claims := GetLocalClaims(r.Context())
		if claims == nil {
			// Not a local JWT (OIDC path) — nothing to enforce here.
			next.ServeHTTP(w, r)
			return
		}

		tenantID := claims.TenantID
		if tenantID == "" {
			// Global/non-tenant token — enforcement is per-tenant only.
			next.ServeHTTP(w, r)
			return
		}

		// Cheap exits mirror AuthService.enforceSSOPolicy: federated sessions and
		// owners never trip enforcement, so skip the tenant lookup for them.
		// Empty auth_method is treated as "password" (fail-safe) by AuthMethodFromString.
		method := sessiondom.AuthMethodFromString(claims.AuthMethod)
		if method.IsFederated() || claims.Role == string(tenantdom.RoleOwner) {
			next.ServeHTTP(w, r)
			return
		}

		enforced, err := g.isEnforced(r.Context(), tenantID)
		if err != nil {
			// Fail closed: a password non-owner session for a tenant whose
			// enforcement flag we cannot read is refused. The mint-time gate is
			// the primary control; this is defense-in-depth on the residual window.
			g.logger.Warn("SSO enforcement lookup failed; denying password session (fail-closed)",
				"tenant_id", tenantID, "user_id", claims.UserID)
			apierror.Forbidden("This organization requires SSO sign-in").WriteJSON(w)
			return
		}
		if enforced {
			g.logger.Info("blocked password session from SSO-enforced tenant (per-request)",
				"tenant_id", tenantID, "user_id", claims.UserID)
			apierror.Forbidden("This organization requires SSO sign-in").WriteJSON(w)
			return
		}

		next.ServeHTTP(w, r)
	})
}
