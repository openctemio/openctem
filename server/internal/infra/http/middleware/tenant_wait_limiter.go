package middleware

import (
	"net/http"
	"sync"

	"github.com/openctemio/openctem/api/pkg/apierror"
)

// TenantWaitLimiter caps how many requests of one tenant run a guarded
// handler at the same time. Unlike TenantConcurrencyLimiter it queues the
// extra requests (until their context ends) instead of refusing them: it
// guards tenant-wide aggregate reads, which a dashboard fires in bursts, so
// that one tenant's burst cannot take every database connection from the
// others.
type TenantWaitLimiter struct {
	max   int
	mu    sync.Mutex
	slots map[string]chan struct{}
}

// NewTenantWaitLimiter returns a limiter allowing maxInFlight requests per
// tenant; maxInFlight <= 0 disables it.
func NewTenantWaitLimiter(maxInFlight int) *TenantWaitLimiter {
	return &TenantWaitLimiter{max: maxInFlight, slots: map[string]chan struct{}{}}
}

func (l *TenantWaitLimiter) tenantSlots(tenantID string) chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	s, ok := l.slots[tenantID]
	if !ok {
		s = make(chan struct{}, l.max)
		l.slots[tenantID] = s
	}
	return s
}

// Middleware runs next once the tenant has a free slot. A request whose
// context ends while it waits gets 503 with Retry-After.
func (l *TenantWaitLimiter) Middleware() func(http.Handler) http.Handler {
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
			slots := l.tenantSlots(tid)
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
				next.ServeHTTP(w, r)
			case <-r.Context().Done():
				w.Header().Set("Retry-After", "5")
				apierror.New(http.StatusServiceUnavailable, "BUSY", "Too many concurrent reports for this organization; try again shortly").WriteJSON(w)
			}
		})
	}
}
