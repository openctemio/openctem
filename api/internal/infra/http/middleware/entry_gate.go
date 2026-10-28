package middleware

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EntryChecker decides whether a session meets the entry requirements of one
// organization (SSO, two-factor, personal-account policy). It is the request
// time counterpart of token issuance: AuthService.CheckEntry.
type EntryChecker interface {
	CheckEntry(ctx context.Context, sessionID, userID, tenantID string) error
}

// entryRefusal is implemented by a refusal that knows how to render itself
// (auth.EntryRefusal).
type entryRefusal interface {
	HTTPStatus() int
	ErrorCode() string
	PublicMessage() string
}

// ErrCodeAccountTokenNotAllowed refuses a token that is bound to no
// organization on a route that acts inside one.
const ErrCodeAccountTokenNotAllowed apierror.Code = "ACCOUNT_TOKEN_NOT_ALLOWED"

// EntryGate is the one entry check of every /api/v1/tenants/{tenant}/...
// route (research/310 X-02). Such a route takes the organization from the URL
// and accepts a token minted for another organization the caller belongs to,
// so token issuance never evaluated the URL organization's requirements.
// The gate:
//
//   - refuses a token bound to no organization (the tenantless token social and
//     SSO sign-in return): it proves a sign-in, not entry to any organization;
//   - applies the URL organization's requirements to the token's session on
//     every request: its SSO rule with the second factor an exception needs,
//     two-factor rule, personal-account policy.
//
// A success is cached for a short TTL per (session, organization), so the
// check costs one lookup per window; a refusal or a failure to decide is never
// cached and fails closed. A request without local JWT claims (API key, OIDC
// provider) is governed by its own chain and passes. It must run after
// RequireMembership.
type EntryGate struct {
	checker EntryChecker
	ttl     time.Duration
	logger  *logger.Logger

	mu    sync.Mutex
	cache map[string]time.Time
}

// NewEntryGate builds the gate. A zero ttl defaults to 15s.
func NewEntryGate(checker EntryChecker, ttl time.Duration, log *logger.Logger) *EntryGate {
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	return &EntryGate{checker: checker, ttl: ttl, logger: log.With("middleware", "entry_gate"), cache: map[string]time.Time{}}
}

func (g *EntryGate) allowed(key string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	exp, ok := g.cache[key]
	if !ok {
		return false
	}
	if now.After(exp) {
		delete(g.cache, key)
		return false
	}
	return true
}

func (g *EntryGate) remember(key string, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.cache) > 10000 {
		for k, exp := range g.cache {
			if now.After(exp) {
				delete(g.cache, k)
			}
		}
		if len(g.cache) > 10000 {
			g.cache = map[string]time.Time{}
		}
	}
	g.cache[key] = now.Add(g.ttl)
}

// Invalidate drops every cached entry of an organization (its security
// settings changed).
func (g *EntryGate) Invalidate(tenantID string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for k := range g.cache {
		if len(k) > len(tenantID) && k[len(k)-len(tenantID):] == tenantID {
			delete(g.cache, k)
		}
	}
}

// Enforce is the middleware.
func (g *EntryGate) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if g == nil || g.checker == nil {
			next.ServeHTTP(w, r)
			return
		}
		claims := GetLocalClaims(r.Context())
		if claims == nil {
			next.ServeHTTP(w, r)
			return
		}
		if claims.TenantID == "" {
			apierror.New(http.StatusForbidden, ErrCodeAccountTokenNotAllowed,
				"This token is not bound to an organization. Choose an organization to continue.").WriteJSON(w)
			return
		}
		urlTenant := GetTeamID(r.Context())
		if urlTenant.IsZero() {
			next.ServeHTTP(w, r)
			return
		}
		tenantID := urlTenant.String()
		now := time.Now()
		key := claims.SessionID + "|" + claims.UserID + "|" + tenantID
		if claims.SessionID != "" && g.allowed(key, now) {
			next.ServeHTTP(w, r)
			return
		}
		err := g.checker.CheckEntry(r.Context(), claims.SessionID, claims.UserID, tenantID)
		if err != nil {
			var ref entryRefusal
			if errors.As(err, &ref) {
				apierror.New(ref.HTTPStatus(), apierror.Code(ref.ErrorCode()), ref.PublicMessage()).WriteJSON(w)
				return
			}
			g.logger.Warn("entry requirements could not be decided; request refused",
				"tenant_id", tenantID, "error", logger.SanitizeError(err))
			apierror.Forbidden("Access to this organization could not be verified").WriteJSON(w)
			return
		}
		g.remember(key, now)
		next.ServeHTTP(w, r)
	})
}
