package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/openctemio/api/pkg/logger"
)

func TestDefaultAdminMappingRateLimitConfig(t *testing.T) {
	cfg := DefaultAdminMappingRateLimitConfig()

	assert.Equal(t, 10, cfg.WriteRequestsPerMin, "default should be 10 req/min")
	assert.Equal(t, time.Minute, cfg.CleanupInterval, "default cleanup should be 1 minute")
}

func TestNewAdminMappingRateLimiter(t *testing.T) {
	log := logger.NewNop()

	tests := []struct {
		name   string
		cfg    AdminMappingRateLimitConfig
		wantOK bool
	}{
		{
			name:   "default config",
			cfg:    DefaultAdminMappingRateLimitConfig(),
			wantOK: true,
		},
		{
			name: "zero values get defaults",
			cfg: AdminMappingRateLimitConfig{
				WriteRequestsPerMin: 0,
				CleanupInterval:     0,
			},
			wantOK: true,
		},
		{
			name: "custom config",
			cfg: AdminMappingRateLimitConfig{
				WriteRequestsPerMin: 20,
				CleanupInterval:     2 * time.Minute,
			},
			wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := NewAdminMappingRateLimiter(tt.cfg, log)

			if tt.wantOK {
				assert.NotNil(t, limiter)
				assert.NotNil(t, limiter.writeLimiter)
			}

			// Clean up
			if limiter != nil {
				limiter.Stop()
			}
		})
	}
}

func TestAdminMappingRateLimiter_WriteMiddleware(t *testing.T) {
	log := logger.NewNop()

	// Create a limiter with a very low limit for testing
	limiter := NewAdminMappingRateLimiter(AdminMappingRateLimitConfig{
		WriteRequestsPerMin: 2, // 2 requests per minute
		CleanupInterval:     time.Minute,
	}, log)
	defer limiter.Stop()

	// Create a test handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Wrap with middleware
	wrapped := limiter.WriteMiddleware()(handler)

	// Make requests
	t.Run("first request should succeed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "2", rec.Header().Get("X-RateLimit-Limit"))
	})

	t.Run("second request should succeed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("third request should be rate limited", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		assert.Equal(t, "0", rec.Header().Get("X-RateLimit-Remaining"))
		assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	})

	t.Run("different IP should not be affected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/test", nil)
		req.RemoteAddr = "192.168.1.2:12345" // Different IP
		rec := httptest.NewRecorder()

		wrapped.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestAdminMappingRateLimiter_Stop(t *testing.T) {
	log := logger.NewNop()
	limiter := NewAdminMappingRateLimiter(DefaultAdminMappingRateLimitConfig(), log)

	// Stop should not panic
	assert.NotPanics(t, func() {
		limiter.Stop()
	})
}

func TestAdminMappingRateLimiter_RateLimitHeaders(t *testing.T) {
	log := logger.NewNop()

	limiter := NewAdminMappingRateLimiter(AdminMappingRateLimitConfig{
		WriteRequestsPerMin: 10,
		CleanupInterval:     time.Minute,
	}, log)
	defer limiter.Stop()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := limiter.WriteMiddleware()(handler)

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()

	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Check rate limit headers are present
	assert.NotEmpty(t, rec.Header().Get("X-RateLimit-Limit"), "should have limit header")
	assert.NotEmpty(t, rec.Header().Get("X-RateLimit-Remaining"), "should have remaining header")
	assert.NotEmpty(t, rec.Header().Get("X-RateLimit-Reset"), "should have reset header")
}
