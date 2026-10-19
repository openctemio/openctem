package middleware

import (
	"testing"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// Bulk units come out of the same per-tenant bucket as single requests, and
// a refused bulk spends nothing.
func TestAITriageRateLimiter_AllowExtra(t *testing.T) {
	a := NewAITriageRateLimiter(AITriageRateLimitConfig{TriageRequestsPerMin: 10}, logger.NewNop())
	defer a.Stop()
	if a.AllowExtra("t1", 11) {
		t.Fatal("11 extra units must not fit a 10-per-minute allowance")
	}
	if !a.AllowExtra("t1", 10) {
		t.Fatal("a refused request must not have spent units")
	}
	if a.AllowExtra("t1", 1) {
		t.Fatal("the allowance is used up")
	}
	if !a.AllowExtra("t2", 9) {
		t.Fatal("another tenant has its own allowance")
	}
	var nilLimiter *AITriageRateLimiter
	if !nilLimiter.AllowExtra("t1", 100) {
		t.Fatal("no limiter means no limit")
	}
}
