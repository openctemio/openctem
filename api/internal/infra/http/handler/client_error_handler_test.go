package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func postClientError(t *testing.T, body string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	var logs strings.Builder
	h := NewClientErrorHandler(logger.New(logger.Config{Format: "json", Output: &logs}))
	rec := httptest.NewRecorder()
	h.Report(rec, httptest.NewRequest(http.MethodPost, "/api/v1/client-errors", strings.NewReader(body)))
	return rec, logs.String()
}

func TestClientErrorReportCountsTheKind(t *testing.T) {
	before := testutil.ToFloat64(metrics.WebClientErrorsTotal.WithLabelValues("chunk_load"))
	rec, _ := postClientError(t, `{"kind":"chunk_load"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if got := testutil.ToFloat64(metrics.WebClientErrorsTotal.WithLabelValues("chunk_load")) - before; got != 1 {
		t.Fatalf("chunk_load counted %v, want 1", got)
	}
}

// A kind outside the fixed set is counted as "other": a caller cannot mint
// label values. Extra fields (a message, a URL, an email) are dropped and
// never reach the log or a label.
func TestClientErrorReportKeepsOnlyAKnownKind(t *testing.T) {
	const pii = "alice@example.com"
	before := testutil.ToFloat64(metrics.WebClientErrorsTotal.WithLabelValues("other"))
	rec, logs := postClientError(t, `{"kind":"`+pii+`","message":"`+pii+`","url":"https://x/assets/payroll"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if got := testutil.ToFloat64(metrics.WebClientErrorsTotal.WithLabelValues("other")) - before; got != 1 {
		t.Fatalf("unknown kind counted as other %v times, want 1", got)
	}
	if strings.Contains(logs, pii) || strings.Contains(logs, "payroll") {
		t.Fatalf("the log carries reported content: %s", logs)
	}
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if strings.Contains(l.GetValue(), pii) {
					t.Fatalf("metric %s carries reported content", f.GetName())
				}
			}
		}
	}
}

func TestClientErrorReportRefusesAMalformedOrOversizedBody(t *testing.T) {
	for name, body := range map[string]string{
		"not json":  `kind=chunk_load`,
		"oversized": `{"kind":"render","pad":"` + strings.Repeat("x", 2*clientErrorMaxBody) + `"}`,
	} {
		rec, _ := postClientError(t, body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, rec.Code)
		}
	}
}
