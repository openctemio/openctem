package middleware

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/openctemio/api/pkg/apierror"
	apikeydom "github.com/openctemio/api/pkg/domain/apikey"
	"github.com/openctemio/api/pkg/logger"
)

// API-key context keys. The authenticated key's id and non-secret prefix are
// stashed so downstream handlers (e.g. the MCP audit trail) can attribute an
// action to the specific key without re-reading the raw token.
const (
	APIKeyIDKey     logger.ContextKey = "api_key_id"
	APIKeyPrefixKey logger.ContextKey = "api_key_prefix"
)

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

// APIKeyAuthenticator is the slice of the apikey service the middleware needs.
// Declared here (not imported from the app package) so the middleware depends
// only on the domain type. Satisfied by *apikey.Service.
type APIKeyAuthenticator interface {
	Authenticate(ctx context.Context, rawKey, ip string) (*apikeydom.APIKey, error)
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
	limiter := newAPIKeyRateLimiter()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := extractAPIKeyToken(r)
			if raw == "" {
				apierror.Unauthorized("Invalid credentials").WriteJSON(w)
				return
			}

			key, err := auth.Authenticate(r.Context(), raw, getClientIP(r))
			if err != nil {
				log.Debug("api key auth failed", "reason", err.Error())
				apierror.Unauthorized("Invalid credentials").WriteJSON(w)
				return
			}

			// Enforce the key's own stored rate limit (requests per hour). The
			// limit is set at mint time and shown on the key, but was never
			// applied, so a leaked key could be driven at line rate.
			if !limiter.allow(key.ID().String(), key.RateLimit()) {
				log.Warn("api key rate limit exceeded",
					"key_id", key.ID().String(), "rate_limit_per_hour", key.RateLimit())
				apierror.TooManyRequests("API key rate limit exceeded").WriteJSON(w)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, TenantIDKey, key.TenantID().String())
			ctx = context.WithValue(ctx, APIKeyIDKey, key.ID().String())
			ctx = context.WithValue(ctx, APIKeyPrefixKey, key.KeyPrefix())
			if uid := key.UserID(); uid != nil {
				ctx = context.WithValue(ctx, UserIDKey, uid.String())
			}
			// Scopes act as the permission set; an API key is never an admin —
			// it is bounded to exactly the scopes it was minted with.
			ctx = context.WithValue(ctx, PermissionsKey, key.Scopes())
			ctx = context.WithValue(ctx, IsAdminKey, false)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
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
	if h := r.Header.Get("Authorization"); h != "" {
		if rest, ok := strings.CutPrefix(h, "Bearer "); ok {
			tok := strings.TrimSpace(rest)
			if strings.HasPrefix(tok, "oct_") {
				return tok
			}
		}
	}
	if k := strings.TrimSpace(r.Header.Get("X-API-Key")); strings.HasPrefix(k, "oct_") {
		return k
	}
	return ""
}
