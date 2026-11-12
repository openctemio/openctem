package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A handler mounted ahead of the router (the sensor v3 HTTPS binding) skips
// the global middleware but not the per-IP rate limit: it is reachable
// without credentials.
func TestMountPrefixKeepsThePerIPRateLimit(t *testing.T) {
	cfg := &config.Config{}
	cfg.RateLimit = config.RateLimitConfig{Enabled: true, RequestsPerSec: 0.001, Burst: 2, CleanupInterval: time.Minute}
	s := NewServer(cfg, logger.NewNop())
	t.Cleanup(func() {
		for _, f := range s.cleanupFuncs {
			f()
		}
	})
	served := 0
	s.MountPrefix("/api/v3/sensor", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served++
		w.WriteHeader(http.StatusNoContent)
	}))
	codes := make([]int, 0, 4)
	for range 4 {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v3/sensor/openctem.sensor.v3.SensorService/Hello", nil)
		req.RemoteAddr = "203.0.113.7:4444"
		s.httpServer.Handler.ServeHTTP(rec, req)
		codes = append(codes, rec.Code)
	}
	if served != 2 || codes[2] != http.StatusTooManyRequests || codes[3] != http.StatusTooManyRequests {
		t.Fatalf("served %d, codes %v: want the burst of 2 then 429", served, codes)
	}
}
