package llm

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/domain/tenant"
)

// countingProvider records how many times Complete reached the provider — i.e.
// how many LLM calls would actually have been billed.
type countingProvider struct {
	mu    sync.Mutex
	calls int
}

func (p *countingProvider) Complete(_ context.Context, _ CompletionRequest) (*CompletionResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	return &CompletionResponse{Content: "{}"}, nil
}
func (p *countingProvider) Name() string  { return "counting" }
func (p *countingProvider) Model() string { return "test-model" }
func (p *countingProvider) Validate() error {
	return nil
}
func (p *countingProvider) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// TestRateLimitedProvider_BlocksCallOverBudget is the load-bearing test for
// AI_RATE_LIMIT_RPM as a cost control: with a cap of N requests per minute, the
// N+1'th call inside the same minute must NOT reach the provider.
//
// Without the limiter every call goes straight through, so this test fails.
func TestRateLimitedProvider_BlocksCallOverBudget(t *testing.T) {
	t.Parallel()

	const rpm = 3

	inner := &countingProvider{}
	// maxWait is tiny so the over-budget call fails fast instead of parking
	// for the ~20s a real token refill would take at 3 rpm.
	p := newRateLimitedProvider(inner, newRPMLimiter(rpm), rpm, 20*time.Millisecond)

	ctx := context.Background()
	for i := range rpm {
		if _, err := p.Complete(ctx, CompletionRequest{}); err != nil {
			t.Fatalf("call %d within the %d rpm budget was rejected: %v", i+1, rpm, err)
		}
	}

	// The (N+1)'th call in the same window must be refused.
	_, err := p.Complete(ctx, CompletionRequest{})
	if err == nil {
		t.Fatalf("call %d exceeded the %d rpm cap but was allowed through; "+
			"AI_RATE_LIMIT_RPM is not enforced", rpm+1, rpm)
	}
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("over-budget call returned %v, want an error wrapping ErrRateLimited", err)
	}
	if got := inner.count(); got != rpm {
		t.Fatalf("provider was called %d times under a %d rpm cap; "+
			"the blocked call still reached the LLM (and would have been billed)", got, rpm)
	}
}

// TestRateLimitedProvider_HonorsCallerContext verifies the limiter never
// outlives the caller's deadline: a canceled context aborts the wait rather
// than parking the goroutine for maxWait.
func TestRateLimitedProvider_HonorsCallerContext(t *testing.T) {
	t.Parallel()

	inner := &countingProvider{}
	p := newRateLimitedProvider(inner, newRPMLimiter(1), 1, time.Minute)

	// Burn the single token.
	if _, err := p.Complete(context.Background(), CompletionRequest{}); err != nil {
		t.Fatalf("first call rejected: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := p.Complete(ctx, CompletionRequest{}); err == nil {
		t.Fatal("expected the over-budget call to fail once the caller's context expired")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("waited %s for a token despite a 20ms caller deadline", elapsed)
	}
	if got := inner.count(); got != 1 {
		t.Fatalf("provider called %d times, want 1", got)
	}
}

// TestRateLimitedProvider_SharedBudgetAcrossProviders proves the cap is a
// process-wide budget, not a per-provider-instance one. Two providers in the
// same budget scope share the allowance — otherwise every triage job could
// mint a fresh limiter and the cap would mean nothing.
func TestRateLimitedProvider_SharedBudgetAcrossProviders(t *testing.T) {
	t.Parallel()

	const rpm = 2

	reg := newLimiterRegistry()
	scope := budgetScope(tenant.AIModePlatform, "")

	a := &countingProvider{}
	b := &countingProvider{}
	pa := newRateLimitedProvider(a, reg.get(scope, rpm), rpm, 20*time.Millisecond)
	pb := newRateLimitedProvider(b, reg.get(scope, rpm), rpm, 20*time.Millisecond)

	ctx := context.Background()
	if _, err := pa.Complete(ctx, CompletionRequest{}); err != nil {
		t.Fatalf("first call rejected: %v", err)
	}
	if _, err := pb.Complete(ctx, CompletionRequest{}); err != nil {
		t.Fatalf("second call rejected: %v", err)
	}
	if _, err := pb.Complete(ctx, CompletionRequest{}); err == nil {
		t.Fatal("third call across two providers in one budget scope was allowed; " +
			"the RPM budget is per-instance, so the cap can be trivially bypassed")
	}
}

// TestBudgetScope pins how RPM allowances are partitioned: every platform-mode
// tenant shares one budget (they share the platform key's bill), each BYOK
// tenant gets its own, and the two never collide. The scope must be derived
// from tenant identity, never from the API key — a credential has no business
// being a map key that could be logged or dumped.
func TestBudgetScope(t *testing.T) {
	t.Parallel()

	const tenantA, tenantB = "tenant-a", "tenant-b"

	// Platform mode: identity is irrelevant, everyone shares the platform cap.
	if got, want := budgetScope(tenant.AIModePlatform, tenantA), budgetScope(tenant.AIModePlatform, tenantB); got != want {
		t.Errorf("platform-mode tenants got separate budgets (%q vs %q); "+
			"they share one API key, so they must share its cap", got, want)
	}

	// BYOK: each tenant gets its own budget.
	byokA := budgetScope(tenant.AIModeBYOK, tenantA)
	byokB := budgetScope(tenant.AIModeBYOK, tenantB)
	if byokA == byokB {
		t.Errorf("two BYOK tenants share budget %q; one can starve the other "+
			"even though each pays its own LLM bill", byokA)
	}
	if byokA != budgetScope(tenant.AIModeBYOK, tenantA) {
		t.Error("budgetScope is not stable for the same tenant")
	}
	if byokA == budgetScope(tenant.AIModePlatform, tenantA) {
		t.Error("a tenant's BYOK budget collided with the platform budget")
	}

	// A BYOK caller with no identity must still land in a bounded bucket
	// rather than getting a fresh unlimited allowance.
	if s := budgetScope(tenant.AIModeBYOK, ""); s == "" {
		t.Error("BYOK with no tenant ID produced an empty scope")
	}
}

// TestFactory_AppliesRateLimit checks the wiring: a provider handed out by the
// Factory is rate limited when AI_RATE_LIMIT_RPM is set, and is not when the
// operator disables the cap.
func TestFactory_AppliesRateLimit(t *testing.T) {
	t.Parallel()

	base := config.AITriageConfig{
		Enabled:          true,
		PlatformProvider: "claude",
		PlatformModel:    "claude-sonnet-4-20250514",
		AnthropicAPIKey:  "sk-ant-test",
		TimeoutSeconds:   30,
	}

	t.Run("limit set", func(t *testing.T) {
		cfg := base
		cfg.RateLimitRPM = 60
		f := NewFactory(cfg)

		p, err := f.CreateProvider(tenant.AISettings{Mode: tenant.AIModePlatform})
		if err != nil {
			t.Fatalf("CreateProvider: %v", err)
		}
		if _, ok := p.(*rateLimitedProvider); !ok {
			t.Fatalf("provider is %T, not rate limited: AI_RATE_LIMIT_RPM=%d is parsed but never enforced",
				p, cfg.RateLimitRPM)
		}
	})

	t.Run("limit disabled", func(t *testing.T) {
		cfg := base
		cfg.RateLimitRPM = 0
		f := NewFactory(cfg)

		p, err := f.CreateProvider(tenant.AISettings{Mode: tenant.AIModePlatform})
		if err != nil {
			t.Fatalf("CreateProvider: %v", err)
		}
		if _, ok := p.(*rateLimitedProvider); ok {
			t.Fatal("AI_RATE_LIMIT_RPM=0 must mean no cap, but the provider was wrapped")
		}
	})
}
