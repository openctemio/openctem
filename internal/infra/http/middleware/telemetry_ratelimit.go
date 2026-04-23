package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/logger"
	"golang.org/x/time/rate"
)

// Per-tenant rate limiter for the runtime-telemetry ingest endpoint.
//
// The built-in RateLimiter in ratelimit.go keys on IP — fine for
// anonymous public endpoints, but not for /telemetry-events: many
// endpoint agents deploy behind the same corporate NAT and would
// share one bucket, so a single noisy agent would block the whole
// fleet. This limiter keys on the authenticated tenant instead.
//
// Defaults: 200 requests / second per tenant, burst 400. Each request
// carries up to 100 events (handler-enforced), so at steady state a
// tenant can push 20k events/s before being throttled — well above
// any realistic EDR fleet, but low enough that a compromised agent
// key can't flood the table or the correlator.
//
// NOT YET WIRED INTO ROUTES. This file ships the type so a future
// PR can wire it without signature churn. Bootstrap path:
//   1. cmd/server/handlers.go — construct TelemetryRateLimiter
//   2. routes/scanning.go registerAgentRoutes — thread it in and
//      apply .Middleware() on the /telemetry-events route.
// Left unwired here to keep the agent-route signature stable for
// this PR; the P0 work (correlator, IOC, validation) can land
// without the route-registration change.

// TelemetryRateLimiter holds one token bucket per tenant. Old buckets
// are evicted after the configured idle window so long-dormant
// tenants don't leak memory.
type TelemetryRateLimiter struct {
	rate     rate.Limit
	burst    int
	idle     time.Duration
	log      *logger.Logger
	mu       sync.Mutex
	tenants  map[string]*telemetryTenantBucket
	done     chan struct{}
	stopped  chan struct{}
	stopOnce sync.Once
}

type telemetryTenantBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewTelemetryRateLimiter wires a per-tenant limiter with the given
// rate / burst. rps=0 disables the limiter (return a pass-through
// middleware). idle is how long a dormant tenant bucket survives
// before being evicted.
func NewTelemetryRateLimiter(rps float64, burst int, idle time.Duration, log *logger.Logger) *TelemetryRateLimiter {
	if burst <= 0 {
		burst = 1
	}
	if idle <= 0 {
		idle = 10 * time.Minute
	}
	rl := &TelemetryRateLimiter{
		rate:    rate.Limit(rps),
		burst:   burst,
		idle:    idle,
		log:     log.With("component", "telemetry-ratelimit"),
		tenants: make(map[string]*telemetryTenantBucket),
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	go rl.gc()
	return rl
}

// Stop terminates the cleanup goroutine. Safe to call once.
func (rl *TelemetryRateLimiter) Stop() {
	rl.stopOnce.Do(func() { close(rl.done) })
	<-rl.stopped
}

// gc evicts buckets that have been idle past rl.idle. Runs every 1 m.
func (rl *TelemetryRateLimiter) gc() {
	defer close(rl.stopped)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-rl.done:
			return
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-rl.idle)
			for k, b := range rl.tenants {
				if b.lastSeen.Before(cutoff) {
					delete(rl.tenants, k)
				}
			}
			rl.mu.Unlock()
		}
	}
}

func (rl *TelemetryRateLimiter) bucket(tenantID string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.tenants[tenantID]
	if !ok {
		b = &telemetryTenantBucket{limiter: rate.NewLimiter(rl.rate, rl.burst)}
		rl.tenants[tenantID] = b
	}
	b.lastSeen = time.Now()
	return b.limiter
}

// Middleware returns an http middleware that rejects a request with
// 429 when the calling tenant is over budget.
//
// The caller MUST place this AFTER agent-key auth so the
// tenant-from-context lookup succeeds. If tenant is absent the
// middleware passes through (rely on the auth middleware to 401).
func (rl *TelemetryRateLimiter) Middleware() func(http.Handler) http.Handler {
	// Disabled limiter (rps=0) → pass-through, still installable
	// without ops worrying about over-blocking during initial rollout.
	if rl.rate <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tid := GetTenantID(r.Context())
			if tid == "" {
				next.ServeHTTP(w, r)
				return
			}
			if !rl.bucket(tid).Allow() {
				rl.log.Warn("telemetry rate limit exceeded",
					"tenant_id", tid,
					"rate_per_sec", float64(rl.rate),
					"burst", rl.burst,
				)
				apierror.TooManyRequests("telemetry ingest rate limit exceeded").WriteJSON(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
