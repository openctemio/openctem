package handler

import (
	"math"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// The scoring preview is a dry run over the whole organization (every live
// asset and every open finding), so it is rate limited per tenant: a
// compromised or scripted admin session cannot use it to load the database.
// The limit is per API replica (in memory), like the recalculate cooldown.
const (
	scoringPreviewPerMinute = 6
	scoringPreviewBurst     = 6
)

// tenantRateLimiter is a token bucket per tenant.
type tenantRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
	every    rate.Limit
	burst    int
}

func newTenantRateLimiter(perMinute, burst int) *tenantRateLimiter {
	return &tenantRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		every:    rate.Limit(float64(perMinute) / 60.0),
		burst:    burst,
	}
}

// allow takes one token from the tenant's bucket. When the bucket is empty it
// takes nothing and returns how long until a token is available (at least one
// second, for Retry-After).
func (l *tenantRateLimiter) allow(tenantID string, now time.Time) (bool, int) {
	l.mu.Lock()
	lim, ok := l.limiters[tenantID]
	if !ok {
		lim = rate.NewLimiter(l.every, l.burst)
		l.limiters[tenantID] = lim
	}
	l.mu.Unlock()

	res := lim.ReserveN(now, 1)
	if !res.OK() {
		return false, 60
	}
	delay := res.DelayFrom(now)
	if delay <= 0 {
		return true, 0
	}
	res.CancelAt(now)
	return false, max(1, int(math.Ceil(delay.Seconds())))
}
