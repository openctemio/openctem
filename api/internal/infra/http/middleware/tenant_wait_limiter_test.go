package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// At most max requests of one tenant run at once; the rest wait and then
// run; another tenant is never held back; a waiter whose context ends gets 503.
func TestTenantWaitLimiter(t *testing.T) {
	l := NewTenantWaitLimiter(2)
	var cur, peak atomic.Int64
	release := make(chan struct{})
	h := l.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := cur.Add(1)
		for p := peak.Load(); c > p && !peak.CompareAndSwap(p, c); p = peak.Load() {
		}
		if GetTenantID(r.Context()) == "t1" {
			<-release
		}
		cur.Add(-1)
		w.WriteHeader(http.StatusOK)
	}))
	req := func(tenant string, ctx context.Context) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/x", nil).WithContext(context.WithValue(ctx, TenantIDKey, tenant))
		return r
	}
	var wg sync.WaitGroup
	codes := make(chan int, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req("t1", context.Background()))
			codes <- rec.Code
		}()
	}
	time.Sleep(50 * time.Millisecond)
	// Another tenant runs while t1 is at its cap.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req("t2", context.Background()))
	if rec.Code != http.StatusOK {
		t.Fatalf("other tenant got %d", rec.Code)
	}
	// A t1 waiter that gives up gets 503.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req("t1", ctx))
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("expired waiter got %d", rec.Code)
	}
	close(release)
	wg.Wait()
	close(codes)
	for c := range codes {
		if c != http.StatusOK {
			t.Fatalf("queued request got %d", c)
		}
	}
	if peak.Load() > 3 { // 2 of t1 + the t2 request
		t.Fatalf("peak in flight %d", peak.Load())
	}
}
