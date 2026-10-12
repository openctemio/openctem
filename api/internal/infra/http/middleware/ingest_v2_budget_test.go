package middleware

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"testing"

	protov2 "github.com/openctemio/openctem/api/pkg/sensorproto/v2"
)

// Result requests reserve what they may hold decoded from a process-wide
// budget before they are read (sensor → platform review, RE-6): the
// per-tenant concurrency bound does not bound many tenants together. Over
// the budget a request is refused as retryable, and every reservation is
// returned when the request ends.
func TestV2ReadVerified_DecodeBudget(t *testing.T) {
	old := V2DecodeBudgetBytes
	t.Cleanup(func() { SetV2DecodeBudget(old) })
	limits := protov2.DefaultLimits()
	body := []byte(`{"version":"1.0"}`)

	SetV2DecodeBudget(int64(len(body)))
	rec := httptest.NewRecorder()
	edge(limits).ServeHTTP(rec, v2Request(body, nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("a request within the budget: %d %s", rec.Code, rec.Body.String())
	}
	// The reservation was returned: the same request fits again.
	rec = httptest.NewRecorder()
	edge(limits).ServeHTTP(rec, v2Request(body, nil))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("the budget was not returned: %d", rec.Code)
	}

	// A compressed body reserves its possible decompressed size (at most
	// the whole budget, so one maximal request can always run alone): while
	// other requests hold part of the budget, it is refused before it is
	// read.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(body)
	_ = zw.Close()
	SetV2DecodeBudget(int64(gz.Len()) * 10)
	if !v2DecodeBudget.TryAcquire(1) {
		t.Fatal("could not hold part of the budget")
	}
	defer v2DecodeBudget.Release(1)
	rec = httptest.NewRecorder()
	edge(limits).ServeHTTP(rec, v2Request(gz.Bytes(), func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }))
	if rec.Code != http.StatusTooManyRequests || problemType(t, rec) != string(protov2.ProblemRateLimited) ||
		rec.Header().Get(protov2.HeaderRetryAfter) == "" {
		t.Fatalf("over the budget: %d %s, want 429 rate-limited with Retry-After", rec.Code, rec.Body.String())
	}
}
