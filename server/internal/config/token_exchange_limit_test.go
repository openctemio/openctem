package config

import "testing"

func TestRateLimit_TokenExchangeDefaultAndProductionCeiling(t *testing.T) {
	t.Setenv("RATE_LIMIT_TOKEN_EXCHANGE_PER_MIN", "")
	if got := getEnvInt("RATE_LIMIT_TOKEN_EXCHANGE_PER_MIN", DefaultTokenExchangePerMin); got != 20 {
		t.Fatalf("default = %d, want 20", got)
	}
	c := &Config{RateLimit: RateLimitConfig{Enabled: true, TokenExchangePerMin: 20}}
	c.Database.SSLMode = "require"
	if err := c.validateProductionSecurity(); err != nil {
		t.Fatalf("default budget refused: %v", err)
	}
	c.RateLimit.TokenExchangePerMin = 600
	if err := c.validateProductionSecurity(); err == nil {
		t.Fatal("production accepted a token budget above the default")
	}
}
