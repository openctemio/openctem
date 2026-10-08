package middleware

import (
	"context"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/apierror"
	apikeydom "github.com/openctemio/openctem/api/pkg/domain/apikey"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// API-key context keys. The authenticated key's id and non-secret prefix are
// stashed so downstream handlers (e.g. the MCP audit trail) can attribute an
// action to the specific key without re-reading the raw token.
const (
	APIKeyIDKey     logger.ContextKey = "api_key_id"
	APIKeyPrefixKey logger.ContextKey = "api_key_prefix"
)

// AuthProviderAPIKey is the AuthProviderKey value for a request authenticated
// by a tenant `oct_` API key.
const AuthProviderAPIKey = "api_key"

// GetAPIKeyID returns the authenticated API key's id, or "" if the request was
// not authenticated by an `oct_` key.
func GetAPIKeyID(ctx context.Context) string {
	if v, ok := ctx.Value(APIKeyIDKey).(string); ok {
		return v
	}
	return ""
}

// GetAPIKeyPrefix returns the authenticated API key's non-secret prefix (the
// first 8 chars), or "" if the request was not API-key authenticated.
func GetAPIKeyPrefix(ctx context.Context) string {
	if v, ok := ctx.Value(APIKeyPrefixKey).(string); ok {
		return v
	}
	return ""
}

// IsAPIKeyAuthenticated reports whether the request was authenticated by an
// `oct_` API key.
func IsAPIKeyAuthenticated(ctx context.Context) bool {
	return GetAPIKeyID(ctx) != ""
}

// APIKeyAuthenticator is the slice of the apikey service the middleware needs.
// Declared here (not imported from the app package) so the middleware depends
// only on the domain type. Satisfied by *apikey.Service.
//
// AuthenticateWithPermissions resolves a raw key to its active key and the
// permissions it may exercise now: its scopes narrowed to what its user still
// holds. Every failure (unknown, revoked, expired, owner no longer an active
// member) is one generic error.
type APIKeyAuthenticator interface {
	AuthenticateWithPermissions(ctx context.Context, rawKey, ip string) (*apikeydom.APIKey, []string, error)
}

// APIKeyAuthMiddleware authenticates tenant-scoped `oct_` API keys. One
// instance serves both the MCP endpoint (Handler) and the REST API (OrJWT), so
// a key has a single rate-limit budget across the two.
type APIKeyAuthMiddleware struct {
	auth    APIKeyAuthenticator
	log     *logger.Logger
	limiter *apiKeyRateLimiter
}

// NewAPIKeyAuth builds the API-key authenticator.
func NewAPIKeyAuth(auth APIKeyAuthenticator, log *logger.Logger) *APIKeyAuthMiddleware {
	return &APIKeyAuthMiddleware{auth: auth, log: log, limiter: newAPIKeyRateLimiter()}
}

// APIKeyAuth authenticates a request by a tenant-scoped `oct_` API key presented
// as `Authorization: Bearer oct_…` (or `X-API-Key: oct_…`). On success it seeds
// the same context keys the JWT path uses — tenant, optional user, scopes as
// permissions, and IsAdmin=false — so downstream handlers and the Require*
// permission gates work unchanged. Any failure is a generic 401 (the real reason
// is logged server-side only, to avoid key enumeration).
//
// It is the sole authenticator on the routes it guards: a request without a
// valid `oct_` key — including one bearing a JWT — is rejected with 401 rather
// than passed through, so a JWT is never mistakenly treated as an API key.
func APIKeyAuth(auth APIKeyAuthenticator, log *logger.Logger) func(http.Handler) http.Handler {
	return NewAPIKeyAuth(auth, log).Handler
}

// Handler is the key-only authenticator (the MCP endpoint). See APIKeyAuth.
func (m *APIKeyAuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := extractAPIKeyToken(r)
		if raw == "" {
			apierror.Unauthorized("Invalid credentials").WriteJSON(w)
			return
		}
		ctx, ok := m.authenticate(w, r, raw)
		if !ok {
			return
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OrJWT returns the authenticator for the tenant REST API: a request that
// presents an API key (an `Authorization: Bearer oct_…` or any `X-API-Key`
// header) is authenticated by the key and never by anything else; every other
// request goes to jwtAuth unchanged.
//
// A key request:
//   - never falls back to the session. A bad key is 401 even if the request
//     also carries a valid auth_token cookie, and the cookie is not read.
//   - is refused on the routes APIKeyRouteDenied lists (credential and account
//     management, the user's own /me surface, the admin console), before the
//     key is even looked up.
//   - is read-only: only GET, HEAD and OPTIONS are served. Keys were scoped for
//     the read-only MCP server, and whether they may write is an open decision.
//
// Because the key comes from a header a cross-site page cannot set, a key
// request is not an ambient-credential request and needs no CSRF token. It is
// not marked cookie-authenticated, so the CSRF middleware treats it like any
// header-authenticated request.
func (m *APIKeyAuthMiddleware) OrJWT(jwtAuth func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		jwtChain := jwtAuth(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !hasAPIKeyCredential(r) {
				jwtChain.ServeHTTP(w, r)
				return
			}
			raw, ok := restAPIKeyToken(r)
			if !ok {
				apierror.Unauthorized("Invalid credentials").WriteJSON(w)
				return
			}
			if APIKeyRouteDenied(r.URL.Path) || (r.URL.RawPath != "" && APIKeyRouteDenied(r.URL.RawPath)) {
				apierror.Forbidden("API keys cannot be used on this endpoint").WriteJSON(w)
				return
			}
			ctx, ok := m.authenticate(w, r, raw)
			if !ok {
				return
			}
			if !isSafeMethod(r.Method) {
				apierror.Forbidden("API keys are read-only").WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// authenticate validates raw, applies the key's rate limit and returns the
// request context carrying the key's identity. On failure it writes the
// response and returns false.
func (m *APIKeyAuthMiddleware) authenticate(w http.ResponseWriter, r *http.Request, raw string) (context.Context, bool) {
	key, perms, err := m.auth.AuthenticateWithPermissions(r.Context(), raw, getClientIP(r))
	if err != nil {
		m.log.Debug("api key auth failed", "reason", err.Error())
		apierror.Unauthorized("Invalid credentials").WriteJSON(w)
		return nil, false
	}

	// Enforce the key's own stored rate limit (requests per hour). The
	// limit is set at mint time and shown on the key, but was never
	// applied, so a leaked key could be driven at line rate.
	if !m.limiter.allow(key.ID().String(), key.RateLimit()) {
		m.log.Warn("api key rate limit exceeded",
			"key_id", key.ID().String(), "rate_limit_per_hour", key.RateLimit())
		apierror.TooManyRequests("API key rate limit exceeded").WriteJSON(w)
		return nil, false
	}

	if perms == nil {
		perms = []string{}
	}
	ctx := r.Context()
	ctx = context.WithValue(ctx, TenantIDKey, key.TenantID().String())
	ctx = context.WithValue(ctx, APIKeyIDKey, key.ID().String())
	ctx = context.WithValue(ctx, APIKeyPrefixKey, key.KeyPrefix())
	ctx = context.WithValue(ctx, AuthProviderKey, AuthProviderAPIKey)
	if uid := key.UserID(); uid != nil {
		ctx = context.WithValue(ctx, UserIDKey, uid.String())
	}
	// The key's effective scopes are its permission set; an API key is never
	// an admin, so the owner/admin bypass never applies to it.
	ctx = context.WithValue(ctx, PermissionsKey, perms)
	ctx = context.WithValue(ctx, IsAdminKey, false)
	ctx = auditapp.WithAPIKeyActor(ctx, key.ID().String(), key.KeyPrefix())

	if ctxLogger := logger.FromContext(ctx); ctxLogger != nil {
		ctx = logger.ToContext(ctx, ctxLogger.WithContext(ctx))
	}
	return ctx, true
}

// apiKeyDeniedPrefixes are the REST areas an API key may never reach, even
// with a matching scope. They manage credentials or the account itself, or
// belong to a person's browser session rather than to automation:
//
//   - /api/v1/api-keys, /api/v1/scim-tokens: a key must not list, mint or
//     revoke credentials (it could otherwise extend its own life).
//   - /api/v1/me, /api/v1/notifications, /api/v1/ws: the signed-in user's own
//     surface (permissions bootstrap, inbox, websocket).
//   - /api/v1/platform: platform scanning as the signed-in organization sees
//     it in the console; automation has no use for it.
//   - /api/v1/users: account management, including /users/{id}/roles.
//   - /api/v1/oauth: answering an MCP client's consent request is a person's
//     decision in their browser session, never automation's (RFC-062).
//   - /api/v1/auth, /api/v1/admin, /api/v1/tenants, /api/v1/invitations:
//     sign-in, the platform admin console, organization and membership
//     management. These are not on the key-capable chain at all; listing them
//     keeps the policy in one place if that ever changes.
var apiKeyDeniedPrefixes = []string{ //nolint:gochecknoglobals // fixed policy table
	"/api/v1/api-keys",
	"/api/v1/scim-tokens",
	"/api/v1/me",
	"/api/v1/notifications",
	"/api/v1/ws",
	"/api/v1/platform",
	"/api/v1/users",
	"/api/v1/auth",
	"/api/v1/admin",
	"/api/v1/tenants",
	"/api/v1/invitations",
	"/api/v1/oauth",
}

// APIKeyDeniedPrefixes returns the route prefixes an API key may never reach.
func APIKeyDeniedPrefixes() []string {
	return append([]string(nil), apiKeyDeniedPrefixes...)
}

// APIKeyRouteDenied reports whether an API key is refused on urlPath. The path
// is cleaned first, so "//", "." and ".." segments can't step around a prefix.
func APIKeyRouteDenied(urlPath string) bool {
	p := path.Clean("/" + urlPath)
	for _, prefix := range apiKeyDeniedPrefixes {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

// apiKeyRateLimiter holds one token bucket per `oct_` key, sized from the key's
// rate_limit column (requests per HOUR): a full hour's budget as burst,
// refilled continuously. Buckets are rebuilt if the key's limit changes and
// idle buckets are evicted so revoked/unused keys don't accumulate.
type apiKeyRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*apiKeyBucket
	sweepAt time.Time
}

type apiKeyBucket struct {
	limiter  *rate.Limiter
	perHour  int
	lastSeen time.Time
}

const apiKeyBucketIdle = 2 * time.Hour

func newAPIKeyRateLimiter() *apiKeyRateLimiter {
	return &apiKeyRateLimiter{buckets: make(map[string]*apiKeyBucket)}
}

// allow reports whether keyID may make another request. perHour <= 0 means
// the key has no limit configured (unlimited, previous behavior).
func (l *apiKeyRateLimiter) allow(keyID string, perHour int) bool {
	if perHour <= 0 {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	if now.After(l.sweepAt) {
		for id, b := range l.buckets {
			if now.Sub(b.lastSeen) > apiKeyBucketIdle {
				delete(l.buckets, id)
			}
		}
		l.sweepAt = now.Add(10 * time.Minute)
	}

	b, ok := l.buckets[keyID]
	if !ok || b.perHour != perHour {
		b = &apiKeyBucket{
			limiter: rate.NewLimiter(rate.Limit(float64(perHour)/3600.0), perHour),
			perHour: perHour,
		}
		l.buckets[keyID] = b
	}
	b.lastSeen = now
	return b.limiter.AllowN(now, 1)
}

// extractAPIKeyToken pulls an `oct_` key from the Authorization: Bearer header or
// the X-API-Key header. It deliberately never reads a query parameter (keys in
// URLs get logged by proxies) and returns "" for any non-`oct_` token so JWT
// bearer tokens fall through untouched.
func extractAPIKeyToken(r *http.Request) string {
	if tok := bearerToken(r); strings.HasPrefix(tok, "oct_") {
		return tok
	}
	if k := strings.TrimSpace(r.Header.Get("X-API-Key")); strings.HasPrefix(k, "oct_") {
		return k
	}
	return ""
}

// bearerToken returns the token of an `Authorization: Bearer …` header, or "".
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(rest)
}

// hasAPIKeyCredential reports whether the request presents an API key: an
// `oct_` bearer token, or an X-API-Key header of any value. Such a request is
// decided by the key alone.
func hasAPIKeyCredential(r *http.Request) bool {
	return strings.HasPrefix(bearerToken(r), "oct_") || strings.TrimSpace(r.Header.Get("X-API-Key")) != ""
}

// restAPIKeyToken returns the key a REST request presents. It refuses a
// request whose credentials disagree: an X-API-Key that is not an `oct_` key,
// or an X-API-Key alongside a different Authorization header, since it is not
// clear which one the caller meant to act as.
func restAPIKeyToken(r *http.Request) (string, bool) {
	header := strings.TrimSpace(r.Header.Get("X-API-Key"))
	bearer := bearerToken(r)
	if header == "" {
		return bearer, strings.HasPrefix(bearer, "oct_")
	}
	if !strings.HasPrefix(header, "oct_") {
		return "", false
	}
	if r.Header.Get("Authorization") != "" && bearer != header {
		return "", false
	}
	return header, true
}
