package routes

import "testing"

func TestAuthRateLimitConfig_TokenBudgetOnly(t *testing.T) {
	t.Cleanup(func() { authTokenExchangePerMin = 0 })
	authTokenExchangePerMin = 0
	base := authRateLimitConfig()
	if base.TokenExchangeRatePerMin != 20 {
		t.Fatalf("default token budget = %d, want 20", base.TokenExchangeRatePerMin)
	}
	authTokenExchangePerMin = 600
	got := authRateLimitConfig()
	if got.TokenExchangeRatePerMin != 600 {
		t.Fatalf("token budget = %d, want 600", got.TokenExchangeRatePerMin)
	}
	if got.LoginRatePerMin != base.LoginRatePerMin || got.RegisterRatePerMin != base.RegisterRatePerMin || got.PasswordResetRatePerMin != base.PasswordResetRatePerMin {
		t.Fatal("the sign-in, registration and reset budgets must not follow the token budget")
	}
}
