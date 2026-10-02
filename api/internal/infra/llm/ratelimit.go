package llm

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/openctemio/api/pkg/domain/tenant"
)

// DefaultRateLimitMaxWait bounds how long a call parks waiting for a token.
// Without a bound, an over-subscribed limiter would turn a rate limit into an
// unbounded hang: an HTTP-triggered triage would hold its request goroutine
// for minutes instead of failing fast. Callers whose context deadline is
// shorter than this error out at the deadline, which is the common case.
const DefaultRateLimitMaxWait = 30 * time.Second

// rateLimitedProvider enforces a requests-per-minute ceiling in front of a
// Provider. It is the enforcement point for AI_RATE_LIMIT_RPM, which is
// advertised as a cost control: an LLM call that is not made costs nothing.
type rateLimitedProvider struct {
	Provider

	limiter *rate.Limiter
	rpm     int
	maxWait time.Duration
}

// newRateLimitedProvider wraps p so that Complete cannot exceed rpm calls per
// minute across everything sharing limiter. rpm <= 0 means "no limit" and the
// provider is returned unwrapped.
func newRateLimitedProvider(p Provider, limiter *rate.Limiter, rpm int, maxWait time.Duration) Provider {
	if p == nil || limiter == nil || rpm <= 0 {
		return p
	}
	if maxWait <= 0 {
		maxWait = DefaultRateLimitMaxWait
	}
	return &rateLimitedProvider{Provider: p, limiter: limiter, rpm: rpm, maxWait: maxWait}
}

// Complete blocks until the shared limiter grants a token, then delegates.
// If no token becomes available within maxWait (or before the caller's context
// deadline), it returns ErrRateLimited without calling the provider — the
// caller's cost ceiling is the point, so failing is correct.
func (p *rateLimitedProvider) Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error) {
	waitCtx, cancel := context.WithTimeout(ctx, p.maxWait)
	defer cancel()

	if err := p.limiter.Wait(waitCtx); err != nil {
		return nil, fmt.Errorf("%w: local cap of %d requests/minute (AI_RATE_LIMIT_RPM): %v",
			ErrRateLimited, p.rpm, err)
	}
	return p.Provider.Complete(ctx, req)
}

// newRPMLimiter builds a limiter for rpm requests per minute. Burst is the
// full minute's allowance so a batch of triage jobs starting together is not
// serialized to one call every 60/rpm seconds; sustained throughput is still
// capped at rpm.
func newRPMLimiter(rpm int) *rate.Limiter {
	if rpm <= 0 {
		return nil
	}
	return rate.NewLimiter(rate.Limit(float64(rpm)/60.0), rpm)
}

// Budget scopes. Everything sharing a scope shares one RPM allowance.
const (
	// platformBudgetScope covers every tenant running in platform mode: they
	// all spend the platform's API key, so they share its cap.
	platformBudgetScope = "platform"
	// byokBudgetScopePrefix is joined with the tenant ID. A BYOK tenant pays
	// its own LLM bill, so it gets its own allowance and cannot be starved by
	// (or starve) anyone else.
	byokBudgetScopePrefix = "byok:"
)

// budgetScope returns the limiter key for a tenant's AI mode. It is
// deliberately derived from the tenant identity and never from the API key:
// the credential must not end up in a map key that could be logged or dumped,
// and identity is the more accurate unit of billing anyway.
func budgetScope(mode tenant.AIMode, tenantID string) string {
	if mode != tenant.AIModeBYOK {
		return platformBudgetScope
	}
	if tenantID == "" {
		// No identity supplied: fall back to one shared BYOK bucket rather
		// than silently handing out an unlimited per-call allowance.
		return byokBudgetScopePrefix + "unscoped"
	}
	return byokBudgetScopePrefix + tenantID
}

// limiterRegistry hands out one limiter per budget scope.
type limiterRegistry struct {
	mu       sync.Mutex
	limiters map[string]*rate.Limiter
}

func newLimiterRegistry() *limiterRegistry {
	return &limiterRegistry{limiters: make(map[string]*rate.Limiter)}
}

// get returns the limiter for scope, creating it on first use.
func (r *limiterRegistry) get(scope string, rpm int) *rate.Limiter {
	if rpm <= 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if l, ok := r.limiters[scope]; ok {
		return l
	}
	l := newRPMLimiter(rpm)
	r.limiters[scope] = l
	return l
}
