package middleware_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	redisinfra "github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The auth limits used to be in-memory per process: with N API replicas a
// password-guessing client got N times the login budget. They now count in a
// store every replica shares, and fall back to the replica's own bucket when
// the store errors.

// fakeStore stands in for Redis: fixed-window counters shared by every
// counter created from it, keyed by bucket name + request key.
type fakeStore struct {
	mu     sync.Mutex
	counts map[string]int
	fail   bool
	calls  int
}

func newFakeStore() *fakeStore { return &fakeStore{counts: map[string]int{}} }

func (s *fakeStore) Counter(name string, limit int, _ time.Duration) (middleware.AuthRateCounter, error) {
	return &fakeCounter{store: s, name: name, limit: limit}, nil
}

type fakeCounter struct {
	store *fakeStore
	name  string
	limit int
}

func (c *fakeCounter) Allow(_ context.Context, key string) (*redisinfra.MiddlewareRateLimitResult, error) {
	s := c.store
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.fail {
		return nil, errors.New("redis: connection refused")
	}
	k := c.name + ":" + key
	if s.counts[k] >= c.limit {
		return &redisinfra.MiddlewareRateLimitResult{Allowed: false, ResetAt: time.Now().Add(time.Minute), RetryAt: time.Now().Add(time.Minute)}, nil
	}
	s.counts[k]++
	return &redisinfra.MiddlewareRateLimitResult{Allowed: true, Remaining: c.limit - s.counts[k], ResetAt: time.Now().Add(time.Minute)}, nil
}

func newSharedRL(t *testing.T, store middleware.AuthRateLimitBackend, scope string) *middleware.AuthRateLimiter {
	t.Helper()
	rl := middleware.NewDistributedAuthRateLimiter(middleware.DefaultAuthRateLimitConfig(), nil, store, scope)
	t.Cleanup(rl.Stop)
	return rl
}

func TestAuthRateLimit_TwoReplicasShareTheLoginBudget(t *testing.T) {
	store := newFakeStore()
	replicaA := newSharedRL(t, store, "auth").LoginMiddleware()(okHandler())
	replicaB := newSharedRL(t, store, "auth").LoginMiddleware()(okHandler())

	// Default login budget is 5/min per IP. Alternate between the replicas:
	// with per-process limits the client would get 10.
	for i := range 5 {
		h := replicaA
		if i%2 == 1 {
			h = replicaB
		}
		if code := serve(h, loginPost()); code != http.StatusOK {
			t.Fatalf("attempt %d: got %d, want 200", i+1, code)
		}
	}
	if code := serve(replicaA, loginPost()); code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt on replica A: got %d, want 429", code)
	}
	if code := serve(replicaB, loginPost()); code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt on replica B: got %d, want 429 (budget is shared)", code)
	}
}

func TestAuthRateLimit_ScopesKeepSeparateBudgets(t *testing.T) {
	store := newFakeStore()
	tenant := newSharedRL(t, store, "auth").LoginMiddleware()(okHandler())
	console := newSharedRL(t, store, "console").LoginMiddleware()(okHandler())

	for range 5 {
		serve(tenant, loginPost())
	}
	if code := serve(tenant, loginPost()); code != http.StatusTooManyRequests {
		t.Fatalf("tenant login: got %d, want 429", code)
	}
	if code := serve(console, loginPost()); code != http.StatusOK {
		t.Fatalf("console login must not spend the tenant login budget: got %d", code)
	}
}

func TestAuthRateLimit_StoreErrorFallsBackToLocalLimit(t *testing.T) {
	store := newFakeStore()
	store.fail = true
	h := newSharedRL(t, store, "auth").LoginMiddleware()(okHandler())

	// Sign-in stays available while the store is down...
	for i := range 5 {
		if code := serve(h, loginPost()); code != http.StatusOK {
			t.Fatalf("attempt %d with store down: got %d, want 200", i+1, code)
		}
	}
	// ...but is still limited, by this replica's own bucket.
	if code := serve(h, loginPost()); code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt with store down: got %d, want 429 from the local fallback", code)
	}
	if store.calls != 6 {
		t.Fatalf("store consulted %d times, want 6 (every request tries it first)", store.calls)
	}
}

func TestAuthRateLimit_SharedMFABucketsKeyByChallenge(t *testing.T) {
	store := newFakeStore()
	replicaA := newSharedRL(t, store, "auth").MFAMiddleware()(okHandler())
	replicaB := newSharedRL(t, store, "auth").MFAMiddleware()(okHandler())

	// 10 per challenge across both replicas.
	for i := range 10 {
		h := replicaA
		if i%2 == 1 {
			h = replicaB
		}
		if code := serve(h, mfaPost("challenge-1")); code != http.StatusOK {
			t.Fatalf("attempt %d: got %d, want 200", i+1, code)
		}
	}
	if code := serve(replicaB, mfaPost("challenge-1")); code != http.StatusTooManyRequests {
		t.Fatalf("11th attempt on the challenge: got %d, want 429", code)
	}
	if code := serve(replicaA, mfaPost("challenge-2")); code != http.StatusOK {
		t.Fatalf("another challenge: got %d, want 200", code)
	}
}

func TestNewRedisAuthRateLimitBackend_NilClientIsInMemory(t *testing.T) {
	if b := middleware.NewRedisAuthRateLimitBackend(nil, nil); b != nil {
		t.Fatalf("nil client should give a nil backend, got %T", b)
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func serve(h http.Handler, r *http.Request) int {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// TestAuthRateLimit_RealRedisSharesBudget runs the same check against a real
// Redis when TEST_REDIS_ADDR (host:port) is set, e.g.
//
//	docker run -d --rm -p 127.0.0.1:6390:6379 redis:7-alpine
//	TEST_REDIS_ADDR=127.0.0.1:6390 go test ./internal/infra/http/middleware/ -run RealRedis
func TestAuthRateLimit_RealRedisSharesBudget(t *testing.T) {
	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR not set")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("TEST_REDIS_ADDR: %v", err)
	}
	port, _ := strconv.Atoi(portStr)
	client, err := redisinfra.New(&config.RedisConfig{
		Host: host, Port: port, PoolSize: 4,
		DialTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second, WriteTimeout: 2 * time.Second,
	}, logger.NewNop())
	if err != nil {
		t.Fatalf("redis: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	backend := middleware.NewRedisAuthRateLimitBackend(client, nil)
	scope := "test-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	replicaA := newSharedRL(t, backend, scope).LoginMiddleware()(okHandler())
	replicaB := newSharedRL(t, backend, scope).LoginMiddleware()(okHandler())
	for i := range 5 {
		h := replicaA
		if i%2 == 1 {
			h = replicaB
		}
		if code := serve(h, loginPost()); code != http.StatusOK {
			t.Fatalf("attempt %d: got %d, want 200", i+1, code)
		}
	}
	if code := serve(replicaB, loginPost()); code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt: got %d, want 429", code)
	}
}
