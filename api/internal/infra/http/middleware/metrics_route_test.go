package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func panicsRecoveredHTTP() prometheus.Counter {
	return metrics.PanicsRecoveredTotal.WithLabelValues("http")
}

// The path label is the matched route pattern: a name or a host in the URL
// never becomes a label (labels go on to alerting), and random paths cannot
// mint new series.
func TestMetricsLabelsTheRoutePatternNotThePath(t *testing.T) {
	r := chi.NewRouter()
	r.Use(Metrics())
	r.Get("/api/v1/assets/by-name/{name}", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	const secretHost = "payroll.customer-a.example"
	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/assets/by-name/"+secretHost, nil))
	for i := 0; i < 3; i++ {
		r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/wp-admin/probe-"+strings.Repeat("x", i+1)+".php", nil))
	}

	if got := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(http.MethodGet, "/api/v1/assets/by-name/{name}", "200")); got < 1 {
		t.Fatalf("request not counted under its route pattern (got %v)", got)
	}
	if got := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(http.MethodGet, unmatchedRoute, "404")); got < 3 {
		t.Fatalf("unrouted requests not counted under %q (got %v)", unmatchedRoute, got)
	}
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if strings.Contains(l.GetValue(), secretHost) || strings.Contains(l.GetValue(), "wp-admin") {
					t.Fatalf("metric %s label %s carries a raw path: %s", f.GetName(), l.GetName(), l.GetValue())
				}
			}
		}
	}
}

// A panicking handler is counted as the 500 it becomes, and the in-flight
// gauge goes back down; the panic still reaches the recovery middleware.
func TestMetricsCountsAPanicAsA500(t *testing.T) {
	r := chi.NewRouter()
	r.Use(RecoveryWithConfig(logger.New(logger.Config{Output: io.Discard}), true), Metrics())
	r.Get("/boom", func(http.ResponseWriter, *http.Request) { panic("boom") })

	before := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(http.MethodGet, "/boom", "500"))
	panicsBefore := testutil.ToFloat64(panicsRecoveredHTTP())
	inFlightBefore := testutil.ToFloat64(httpRequestsInFlight)

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if got := testutil.ToFloat64(httpRequestsTotal.WithLabelValues(http.MethodGet, "/boom", "500")) - before; got != 1 {
		t.Fatalf("500s counted = %v, want 1", got)
	}
	if got := testutil.ToFloat64(panicsRecoveredHTTP()) - panicsBefore; got != 1 {
		t.Fatalf("panics counted = %v, want 1", got)
	}
	if got := testutil.ToFloat64(httpRequestsInFlight); got != inFlightBefore {
		t.Fatalf("in-flight gauge = %v after the panic, want %v", got, inFlightBefore)
	}
}
