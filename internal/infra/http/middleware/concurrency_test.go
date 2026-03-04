package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrencyLimit tests the ConcurrencyLimit middleware.
//
// Run with: go test -v ./internal/infra/http/middleware/ -run TestConcurrencyLimit
func TestConcurrencyLimit(t *testing.T) {
	t.Run("RequestPassesThroughUnderLimit", func(t *testing.T) {
		handler := ConcurrencyLimit(10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "ok", rec.Body.String())
	})

	t.Run("RequestBlockedWhenAtMaxConcurrent", func(t *testing.T) {
		// Limit to 1 concurrent request
		blockCh := make(chan struct{})
		handler := ConcurrencyLimit(1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-blockCh // Block until released
			w.WriteHeader(http.StatusOK)
		}))

		// Start first request (will block and hold the slot)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/first", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}()

		// Give the first goroutine time to acquire the slot
		time.Sleep(50 * time.Millisecond)

		// Second request should be rejected (503)
		req := httptest.NewRequest(http.MethodGet, "/second", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

		// Release the blocking request
		close(blockCh)
		wg.Wait()
	})

	t.Run("LimitOfZeroDisablesMiddleware", func(t *testing.T) {
		var callCount int32
		handler := ConcurrencyLimit(0)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&callCount, 1)
			w.WriteHeader(http.StatusOK)
		}))

		// All requests should pass through
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code)
		}
		assert.Equal(t, int32(5), atomic.LoadInt32(&callCount))
	})

	t.Run("NegativeLimitDisablesMiddleware", func(t *testing.T) {
		handler := ConcurrencyLimit(-1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("ConcurrentRequestsUpToLimit", func(t *testing.T) {
		const limit = 5
		var concurrentCount int32
		var maxConcurrent int32
		blockCh := make(chan struct{})

		handler := ConcurrencyLimit(limit)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			current := atomic.AddInt32(&concurrentCount, 1)
			// Track maximum concurrent count
			for {
				old := atomic.LoadInt32(&maxConcurrent)
				if current <= old || atomic.CompareAndSwapInt32(&maxConcurrent, old, current) {
					break
				}
			}
			<-blockCh
			atomic.AddInt32(&concurrentCount, -1)
			w.WriteHeader(http.StatusOK)
		}))

		// Launch exactly `limit` requests
		var wg sync.WaitGroup
		for i := 0; i < limit; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, req)
			}()
		}

		// Give goroutines time to acquire slots
		time.Sleep(100 * time.Millisecond)

		// All should be running concurrently
		assert.Equal(t, int32(limit), atomic.LoadInt32(&concurrentCount))

		// Release all
		close(blockCh)
		wg.Wait()

		assert.Equal(t, int32(limit), atomic.LoadInt32(&maxConcurrent))
	})

	t.Run("RequestCompletesAndReleasesSlot", func(t *testing.T) {
		handler := ConcurrencyLimit(1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// First request completes
		req1 := httptest.NewRequest(http.MethodGet, "/first", nil)
		rec1 := httptest.NewRecorder()
		handler.ServeHTTP(rec1, req1)
		assert.Equal(t, http.StatusOK, rec1.Code)

		// Second request should also pass (slot was released)
		req2 := httptest.NewRequest(http.MethodGet, "/second", nil)
		rec2 := httptest.NewRecorder()
		handler.ServeHTTP(rec2, req2)
		assert.Equal(t, http.StatusOK, rec2.Code)
	})

	t.Run("503ResponseContainsMessage", func(t *testing.T) {
		blockCh := make(chan struct{})
		handler := ConcurrencyLimit(1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			<-blockCh
			w.WriteHeader(http.StatusOK)
		}))

		// Hold the slot
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/hold", nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
		}()

		time.Sleep(50 * time.Millisecond)

		// Rejected request should contain error message
		req := httptest.NewRequest(http.MethodGet, "/rejected", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Contains(t, rec.Body.String(), "capacity")

		close(blockCh)
		wg.Wait()
	})

	t.Run("DefaultMaxConcurrentRequestsConstant", func(t *testing.T) {
		assert.Equal(t, 1000, DefaultMaxConcurrentRequests)
	})
}
