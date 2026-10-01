package middleware

import (
	"net/http"
	"sync"

	"github.com/openctemio/api/pkg/apierror"
)

// TenantConcurrencyLimiter caps how many requests a single tenant may have in
// flight at once on the routes it guards. The per-tenant token-bucket rate
// limiter bounds request RATE, but each report-ingest request can hold tens of
// MB of decompressed JSON in memory and keep a DB connection busy for seconds;
// a tenant that fires its whole burst in parallel could still pin a large slice
// of the process. This bounds the parallelism per tenant (a 429 is returned
// beyond it, which agents already retry) without affecting other tenants.
//
// Keyed on the tenant the authenticated principal is bound to, so it MUST run
// after authentication. A request without tenant context passes through
// (authentication rejects it separately).
type TenantConcurrencyLimiter struct {
	max      int
	mu       sync.Mutex
	inFlight map[string]int
}

// NewTenantConcurrencyLimiter returns a limiter allowing at most max in-flight
// requests per tenant. max <= 0 disables it (pass-through).
func NewTenantConcurrencyLimiter(maxInFlight int) *TenantConcurrencyLimiter {
	return &TenantConcurrencyLimiter{max: maxInFlight, inFlight: make(map[string]int)}
}

func (l *TenantConcurrencyLimiter) acquire(tenantID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inFlight[tenantID] >= l.max {
		return false
	}
	l.inFlight[tenantID]++
	return true
}

func (l *TenantConcurrencyLimiter) release(tenantID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n := l.inFlight[tenantID]; n <= 1 {
		delete(l.inFlight, tenantID) // keep the map bounded to active tenants
	} else {
		l.inFlight[tenantID] = n - 1
	}
}

// Middleware enforces the per-tenant in-flight cap.
func (l *TenantConcurrencyLimiter) Middleware() func(http.Handler) http.Handler {
	if l == nil || l.max <= 0 {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tid := GetTenantID(r.Context())
			if tid == "" {
				next.ServeHTTP(w, r)
				return
			}
			if !l.acquire(tid) {
				apierror.TooManyRequests("too many concurrent ingest requests").WriteJSON(w)
				return
			}
			defer l.release(tid)
			next.ServeHTTP(w, r)
		})
	}
}
