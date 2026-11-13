package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// A sensor gets at most perSensor result uploads in flight, shared sensors
// together at most sharedPool; another sensor is not affected (R-1).
func TestV2SensorInFlight(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 16)
	slow := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusAccepted)
	})
	who := map[string]bool{} // key -> shared
	mw := V2SensorInFlight(NewTenantConcurrencyLimiter(2), NewTenantConcurrencyLimiter(3),
		func(r *http.Request) (string, bool) { k := r.Header.Get("X-Test-Sensor"); return k, who[k] })
	h := mw(slow)
	do := func(key string) int {
		req := httptest.NewRequest(http.MethodPut, "/results/x", nil)
		req.Header.Set("X-Test-Sensor", key)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	var wg sync.WaitGroup
	start := func(key string) {
		wg.Add(1)
		go func() { defer wg.Done(); _ = do(key) }()
		<-entered
	}

	start("a")
	start("a")
	if code := do("a"); code != http.StatusTooManyRequests {
		t.Fatalf("third upload of one sensor: %d, want 429", code)
	}
	// Another organization sensor still gets in.
	start("b")

	// Shared sensors share a pool of 3.
	who["s1"], who["s2"] = true, true
	start("s1")
	start("s1")
	start("s2")
	if code := do("s2"); code != http.StatusTooManyRequests {
		t.Fatalf("fourth upload of the shared pool: %d, want 429", code)
	}
	close(release)
	wg.Wait()
	// Slots come back.
	release = make(chan struct{})
	close(release)
	if code := do("a"); code != http.StatusAccepted {
		t.Fatalf("after release: %d", code)
	}
}

func TestV2DecodeBudgetForMemory(t *testing.T) {
	for _, tc := range []struct{ limit, want int64 }{
		{0, 1 << 30},
		{2 << 30, 512 << 20},  // 2 GiB container: a quarter
		{8 << 30, 1 << 30},    // capped at 1 GiB
		{128 << 20, 64 << 20}, // floor
	} {
		if got := V2DecodeBudgetForMemory(tc.limit); got != tc.want {
			t.Errorf("limit %d: %d, want %d", tc.limit, got, tc.want)
		}
	}
	for in, want := range map[string]int64{"max\n": 0, "2147483648\n": 2 << 30, "9223372036854771712": 0, "": 0, "x": 0} {
		if got := parseMemoryLimit(in); got != want {
			t.Errorf("parse %q: %d, want %d", in, got, want)
		}
	}
}
