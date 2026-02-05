package unit

import (
	"testing"
	"time"

	"github.com/openctemio/api/internal/infra/http/middleware"
)

// =============================================================================
// Auth Failure Rate Limiter Tests
// =============================================================================

func TestAuthFailureLimiter_BanAfterMaxFailures(t *testing.T) {
	cfg := middleware.AuthFailureLimiterConfig{
		MaxFailures:     3,
		BanDuration:     time.Minute,
		WindowDuration:  time.Minute,
		CleanupInterval: time.Second,
	}

	limiter := middleware.NewAuthFailureLimiter(cfg, nil)
	defer limiter.Stop()

	ip := "192.168.1.100"

	// First 2 failures should not ban
	if limiter.RecordFailure(ip) {
		t.Error("IP should not be banned after 1 failure")
	}
	if limiter.RecordFailure(ip) {
		t.Error("IP should not be banned after 2 failures")
	}

	// 3rd failure should ban
	if !limiter.RecordFailure(ip) {
		t.Error("IP should be banned after 3 failures")
	}

	// Should be banned
	if !limiter.IsBanned(ip) {
		t.Error("IP should be banned")
	}
}

func TestAuthFailureLimiter_ClearOnSuccess(t *testing.T) {
	cfg := middleware.AuthFailureLimiterConfig{
		MaxFailures:     3,
		BanDuration:     time.Minute,
		WindowDuration:  time.Minute,
		CleanupInterval: time.Second,
	}

	limiter := middleware.NewAuthFailureLimiter(cfg, nil)
	defer limiter.Stop()

	ip := "192.168.1.101"

	// Record 2 failures
	limiter.RecordFailure(ip)
	limiter.RecordFailure(ip)

	// Successful auth should clear
	limiter.RecordSuccess(ip)

	// Now we need 3 more failures to ban
	limiter.RecordFailure(ip)
	limiter.RecordFailure(ip)

	if limiter.IsBanned(ip) {
		t.Error("IP should not be banned yet (only 2 failures after clear)")
	}

	limiter.RecordFailure(ip)
	if !limiter.IsBanned(ip) {
		t.Error("IP should be banned after 3 failures")
	}
}

func TestAuthFailureLimiter_DifferentIPs(t *testing.T) {
	cfg := middleware.AuthFailureLimiterConfig{
		MaxFailures:     2,
		BanDuration:     time.Minute,
		WindowDuration:  time.Minute,
		CleanupInterval: time.Second,
	}

	limiter := middleware.NewAuthFailureLimiter(cfg, nil)
	defer limiter.Stop()

	ip1 := "192.168.1.1"
	ip2 := "192.168.1.2"

	// Ban IP1
	limiter.RecordFailure(ip1)
	limiter.RecordFailure(ip1)

	// IP1 should be banned
	if !limiter.IsBanned(ip1) {
		t.Error("IP1 should be banned")
	}

	// IP2 should not be banned
	if limiter.IsBanned(ip2) {
		t.Error("IP2 should not be banned")
	}
}

func TestAuthFailureLimiter_Stats(t *testing.T) {
	cfg := middleware.AuthFailureLimiterConfig{
		MaxFailures:     2,
		BanDuration:     time.Minute,
		WindowDuration:  time.Minute,
		CleanupInterval: time.Second,
	}

	limiter := middleware.NewAuthFailureLimiter(cfg, nil)
	defer limiter.Stop()

	// Ban 2 IPs
	limiter.RecordFailure("10.0.0.1")
	limiter.RecordFailure("10.0.0.1")
	limiter.RecordFailure("10.0.0.2")
	limiter.RecordFailure("10.0.0.2")

	// Track another IP without banning
	limiter.RecordFailure("10.0.0.3")

	tracked, banned := limiter.GetStats()

	if tracked != 3 {
		t.Errorf("Expected 3 tracked IPs, got %d", tracked)
	}
	if banned != 2 {
		t.Errorf("Expected 2 banned IPs, got %d", banned)
	}
}

// =============================================================================
// Security Event Type Tests
// =============================================================================

func TestSecurityEventTypes_Defined(t *testing.T) {
	events := []string{
		middleware.SecurityEventAuthFailure,
		middleware.SecurityEventAgentNotFound,
		middleware.SecurityEventAPIKeyInvalid,
		middleware.SecurityEventAgentInactive,
		middleware.SecurityEventAgentTypeMismatch,
		middleware.SecurityEventJobAccessDenied,
		middleware.SecurityEventTokenInvalid,
	}

	for _, event := range events {
		if event == "" {
			t.Error("Security event type should not be empty")
		}
		// All events should start with "security."
		if len(event) < 9 || event[:9] != "security." {
			t.Errorf("Security event '%s' should start with 'security.'", event)
		}
	}
}
