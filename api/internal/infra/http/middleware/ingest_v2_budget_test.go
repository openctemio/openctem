package middleware

import (
	"bytes"
	"compress/gzip"
	"context"
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

// One organization cannot spend the whole decode budget (research/191 R-1):
// past its share its next upload is refused as retryable while another
// organization's, and the shared sensors', still fit; an owner holding
// nothing may always start one request.
func TestV2ReadVerified_BudgetSharePerOwner(t *testing.T) {
	old := V2DecodeBudgetBytes
	t.Cleanup(func() { SetV2DecodeBudget(old) })
	limits := protov2.DefaultLimits()
	body := []byte(`{"version":"1.0"}`)
	SetV2DecodeBudget(int64(len(body)) * 8) // share: 2 bodies
	as := func(tenant string) func(*http.Request) {
		return func(r *http.Request) {
			if tenant != "" {
				*r = *r.WithContext(context.WithValue(r.Context(), TenantIDKey, tenant))
			}
		}
	}
	// Organization A already holds its share (two uploads in flight).
	if !v2BudgetShares.tryAcquire("org-a", 2*int64(len(body)), V2DecodeBudgetBytes/v2BudgetShareDivisor) {
		t.Fatal("could not hold A's share")
	}
	t.Cleanup(func() { v2BudgetShares.release("org-a", 2*int64(len(body))) })
	if !v2DecodeBudget.TryAcquire(2 * int64(len(body))) {
		t.Fatal("could not hold part of the budget")
	}
	t.Cleanup(func() { v2DecodeBudget.Release(2 * int64(len(body))) })

	rec := httptest.NewRecorder()
	edge(limits).ServeHTTP(rec, v2Request(body, as("org-a")))
	if rec.Code != http.StatusTooManyRequests || problemType(t, rec) != string(protov2.ProblemRateLimited) {
		t.Fatalf("A past its share: %d %s, want 429 rate-limited", rec.Code, rec.Body.String())
	}
	for _, other := range []string{"org-b", ""} {
		rec = httptest.NewRecorder()
		edge(limits).ServeHTTP(rec, v2Request(body, as(other)))
		if rec.Code != http.StatusAccepted {
			t.Fatalf("owner %q was starved by A: %d %s", other, rec.Code, rec.Body.String())
		}
	}
	// A request larger than a share still runs when its owner holds nothing.
	big := append(append([]byte{}, body...), bytes.Repeat([]byte(" "), 2*len(body))...)
	rec = httptest.NewRecorder()
	edge(limits).ServeHTTP(rec, v2Request(big, as("org-c")))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("a lone request over the share: %d %s", rec.Code, rec.Body.String())
	}
}
