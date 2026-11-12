package routes

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// chainHandler wraps h in the middlewares the same way the chi router does
// (first middleware outermost).
func chainHandler(h http.Handler, mws []Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// A throttled tenant must be rejected BEFORE its body is decompressed. The
// body here is a malformed gzip stream: if decompression ran first the request
// would fail with 400 (decompression error); with the limiter first it is a
// 429 and the body is never touched.
func TestIngestMiddlewareChain_RateLimitBeforeDecompress(t *testing.T) {
	rl := middleware.NewTelemetryRateLimiter(0.0001, 1, time.Minute, logger.NewNop())
	defer rl.Stop()

	chain := ingestMiddlewareChain(rl, middleware.NewTenantConcurrencyLimiter(4),
		middleware.BodyLimit(middleware.IngestMaxBodySize), middleware.DecompressForIngest())
	h := chainHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), chain)

	send := func() int {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/ci/runs/r1/results", bytes.NewReader([]byte("not-gzip")))
		r.Header.Set("Content-Encoding", "gzip")
		r = r.WithContext(context.WithValue(r.Context(), middleware.TenantIDKey, "tenant-1"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}

	if code := send(); code != http.StatusBadRequest {
		t.Fatalf("first request should reach decompression (400 on bad gzip), got %d", code)
	}
	if code := send(); code != http.StatusTooManyRequests {
		t.Fatalf("throttled request must be rejected before decompression with 429, got %d", code)
	}
}

// The ingest route limit (50MB) must actually apply under the global 10MB one.
func TestIngestMiddlewareChain_IngestBodyLimitOverridesGlobal(t *testing.T) {
	chain := ingestMiddlewareChain(nil, nil,
		middleware.BodyLimit(middleware.IngestMaxBodySize), middleware.DecompressForIngest())
	var read int
	inner := chainHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := new(bytes.Buffer)
		n, err := buf.ReadFrom(r.Body)
		read = int(n)
		if err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}), chain)
	h := middleware.BodyLimit(middleware.DefaultMaxBodySize)(inner) // the global limit

	body := make([]byte, middleware.DefaultMaxBodySize+1024) // > 10MB, < 50MB
	r := httptest.NewRequest(http.MethodPost, "/api/v1/ci/runs/r1/results", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || read != len(body) {
		t.Fatalf("ingest body over the global limit but under the ingest limit rejected: code=%d read=%d", rec.Code, read)
	}
}
