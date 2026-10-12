package middleware

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	redisinfra "github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Shared (cross-replica) budgets for the auth rate limits.
//
// An in-memory limiter counts per process, so with N API replicas behind a
// load balancer a password-guessing client gets N times the login budget.
// The auth buckets therefore count in a store every replica shares (Redis in
// production). When the store errors, the request is checked against the
// replica's own in-memory bucket instead: sign-in stays available during a
// Redis outage, still limited, just per replica again.

// authRateWindow is the window the per-minute auth budgets are counted over.
const authRateWindow = time.Minute

// AuthRateCounter is one shared auth bucket: Allow spends one request for key.
type AuthRateCounter interface {
	Allow(ctx context.Context, key string) (*redisinfra.MiddlewareRateLimitResult, error)
}

// AuthRateLimitBackend creates the shared counters for the auth limiters.
// name is unique per bucket ("auth:login", "console:login", ...).
type AuthRateLimitBackend interface {
	Counter(name string, limit int, window time.Duration) (AuthRateCounter, error)
}

// redisAuthRateLimitBackend keeps the auth buckets in Redis (sliding window,
// one sorted set per bucket and key, see redisinfra.RateLimiter).
type redisAuthRateLimitBackend struct {
	client *redisinfra.Client
	log    *logger.Logger
}

// NewRedisAuthRateLimitBackend returns a backend that keeps the auth budgets
// in Redis under "authrl:<bucket>:<key>". A nil client returns nil (the
// limiters then stay in-memory).
func NewRedisAuthRateLimitBackend(client *redisinfra.Client, log *logger.Logger) AuthRateLimitBackend {
	if client == nil {
		return nil
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &redisAuthRateLimitBackend{client: client, log: log}
}

func (b *redisAuthRateLimitBackend) Counter(name string, limit int, window time.Duration) (AuthRateCounter, error) {
	rl, err := redisinfra.NewRateLimiter(b.client, "authrl:"+name, limit, window, b.log)
	if err != nil {
		return nil, err
	}
	return redisinfra.NewMiddlewareAdapter(rl), nil
}

// authBucket is one auth budget: the shared counter when a backend is wired,
// with the in-memory limiter as the fallback for a store error (and as the
// only limiter without a backend).
type authBucket struct {
	name   string
	limit  int
	local  *RateLimiter
	shared AuthRateCounter
	log    *logger.Logger
}

func newAuthBucket(name string, perMin int, cleanup time.Duration, backend AuthRateLimitBackend, log *logger.Logger) *authBucket {
	b := &authBucket{
		name:  name,
		limit: perMin,
		local: NewRateLimiter(&config.RateLimitConfig{
			Enabled:         true,
			RequestsPerSec:  float64(perMin) / 60.0,
			Burst:           perMin,
			CleanupInterval: cleanup,
		}, log),
		log: log,
	}
	if backend != nil {
		shared, err := backend.Counter(name, perMin, authRateWindow)
		if err != nil {
			if log != nil {
				log.Error("auth rate limit: shared bucket unavailable, using in-memory limits",
					"bucket", name, "error", err)
			}
		} else {
			b.shared = shared
		}
	}
	return b
}

// middleware limits requests by the key key returns.
func (b *authBucket) middleware(key func(*http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			k := key(r)
			if b.shared == nil {
				b.local.serveKeyed(w, r, k, next)
				return
			}
			res, err := b.shared.Allow(r.Context(), k)
			if err != nil || res == nil {
				// Store down: stay available, limited per replica.
				if b.log != nil {
					b.log.Warn("auth rate limit: shared store failed, using in-memory limit",
						"bucket", b.name, "error", err,
						"request_id", logSafe(GetRequestID(r.Context())))
				}
				b.local.serveKeyed(w, r, k, next)
				return
			}

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(b.limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(res.ResetAt.Unix(), 10))
			if !res.Allowed {
				retryAfter := max(1, int(time.Until(res.RetryAt).Seconds()))
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				if b.log != nil {
					b.log.Warn("auth rate limit exceeded",
						"bucket", b.name,
						"ip", logSafe(getClientIP(r)),
						"path", logSafe(RedactPath(r.URL.Path)),
						"request_id", logSafe(GetRequestID(r.Context())))
				}
				apierror.RateLimitExceeded().WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
