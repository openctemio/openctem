package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/logger"
)

func metricsStub() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("# HELP go_metrics"))
	})
}

func callMetrics(h http.Handler, authHeader string) int {
	req := httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

// TestMetricsAuth_PublicOpen: when Public=true the endpoint is open (legacy).
func TestMetricsAuth_PublicOpen(t *testing.T) {
	h := middleware.MetricsAuth(true, "", logger.NewNop())(metricsStub())
	if got := callMetrics(h, ""); got != http.StatusOK {
		t.Errorf("public metrics: got %d, want 200", got)
	}
}

// TestMetricsAuth_TokenRequired: Public=false with a token requires a matching
// bearer token; missing/wrong tokens get 404, the correct token gets 200.
func TestMetricsAuth_TokenRequired(t *testing.T) {
	h := middleware.MetricsAuth(false, "s3cr3t", logger.NewNop())(metricsStub())

	if got := callMetrics(h, ""); got != http.StatusNotFound {
		t.Errorf("no token: got %d, want 404", got)
	}
	if got := callMetrics(h, "Bearer wrong"); got != http.StatusNotFound {
		t.Errorf("wrong token: got %d, want 404", got)
	}
	if got := callMetrics(h, "Bearer s3cr3t"); got != http.StatusOK {
		t.Errorf("correct token: got %d, want 200", got)
	}
}

// TestMetricsAuth_XMetricsTokenHeader: the X-Metrics-Token header is also
// accepted for scrapers that cannot set Authorization.
func TestMetricsAuth_XMetricsTokenHeader(t *testing.T) {
	h := middleware.MetricsAuth(false, "s3cr3t", logger.NewNop())(metricsStub())
	req := httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody)
	req.Header.Set("X-Metrics-Token", "s3cr3t")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("X-Metrics-Token: got %d, want 200", rec.Code)
	}
}

// TestMetricsAuth_FailClosed: Public=false and no token configured disables the
// endpoint entirely (404), even with a bearer token supplied.
func TestMetricsAuth_FailClosed(t *testing.T) {
	h := middleware.MetricsAuth(false, "", logger.NewNop())(metricsStub())
	if got := callMetrics(h, ""); got != http.StatusNotFound {
		t.Errorf("disabled metrics (no header): got %d, want 404", got)
	}
	if got := callMetrics(h, "Bearer anything"); got != http.StatusNotFound {
		t.Errorf("disabled metrics (with header): got %d, want 404", got)
	}
}
