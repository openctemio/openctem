package middleware_test

import (
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	redisinfra "github.com/openctemio/openctem/api/internal/infra/redis"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The CI token exchange used to share one strict budget per address, so on
// hosted runners (many customers behind one egress address) one fleet
// throttled every other organization. It now counts per organization +
// issuer at an address, under a wide per-address backstop.

const (
	tenantA   = "11111111-1111-1111-1111-111111111111"
	tenantB   = "22222222-2222-2222-2222-222222222222"
	gitlabIss = "https://gitlab.com"
	githubIss = "https://token.actions.githubusercontent.com"
)

func ciToken(iss string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"RS256"}`)) + "." + enc([]byte(`{"iss":"`+iss+`","sub":"x"}`)) + ".sig"
}

func exchangeReq(ip, tenant, iss string) *http.Request {
	body := `{"tenant_id":"` + tenant + `","id_token":"` + ciToken(iss) + `"}`
	return exchangeRaw(ip, body)
}

func exchangeRaw(ip, body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/ci/oidc/exchange", strings.NewReader(body))
	r.RemoteAddr = ip + ":40000"
	return r
}

func newCIExchange(t *testing.T, backend middleware.AuthRateLimitBackend, perIdentity, perIP int, next http.Handler) http.Handler {
	t.Helper()
	l := middleware.NewCIExchangeRateLimiter(middleware.CIExchangeRateLimitConfig{
		PerIdentityPerMin: perIdentity, PerIPPerMin: perIP,
	}, backend, nil)
	t.Cleanup(l.Stop)
	return l.Middleware()(next)
}

func TestCIExchangeRateLimit_OrganizationsBehindOneAddressHaveTheirOwnBudget(t *testing.T) {
	for _, store := range []struct {
		name    string
		backend middleware.AuthRateLimitBackend
	}{{"shared store", newFakeStore()}, {"in memory", nil}} {
		t.Run(store.name, func(t *testing.T) {
			h := newCIExchange(t, store.backend, 3, 100, okHandler())
			for i := range 3 {
				if code := serve(h, exchangeReq("198.51.100.20", tenantA, gitlabIss)); code != http.StatusOK {
					t.Fatalf("tenant A attempt %d: got %d, want 200", i+1, code)
				}
			}
			if code := serve(h, exchangeReq("198.51.100.20", tenantA, gitlabIss)); code != http.StatusTooManyRequests {
				t.Fatalf("tenant A over budget: got %d, want 429", code)
			}
			// Another organization on the same shared runner address.
			if code := serve(h, exchangeReq("198.51.100.20", tenantB, gitlabIss)); code != http.StatusOK {
				t.Fatalf("tenant B behind the same address: got %d, want 200", code)
			}
			// The same organization's other CI provider.
			if code := serve(h, exchangeReq("198.51.100.20", tenantA, githubIss)); code != http.StatusOK {
				t.Fatalf("tenant A, other issuer: got %d, want 200", code)
			}
		})
	}
}

// Someone who knows an organization's id (it sits in public pipeline files)
// cannot use up that organization's budget from another address by sending
// junk tokens naming it.
func TestCIExchangeRateLimit_JunkFromAnotherAddressDoesNotStarveAnOrganization(t *testing.T) {
	h := newCIExchange(t, newFakeStore(), 3, 100, okHandler())
	for range 10 {
		serve(h, exchangeReq("203.0.113.66", tenantA, gitlabIss))
	}
	if code := serve(h, exchangeReq("198.51.100.20", tenantA, gitlabIss)); code != http.StatusOK {
		t.Fatalf("tenant A from its own runners after junk elsewhere: got %d, want 200", code)
	}
}

// Inventing tenant ids or issuers gives fresh identity buckets, but the
// address backstop still caps the address.
func TestCIExchangeRateLimit_AddressBackstop(t *testing.T) {
	h := newCIExchange(t, newFakeStore(), 3, 5, okHandler())
	for i := range 5 {
		tenant := "00000000-0000-0000-0000-00000000000" + strconv.Itoa(i)
		if code := serve(h, exchangeReq("203.0.113.66", tenant, gitlabIss)); code != http.StatusOK {
			t.Fatalf("attempt %d: got %d, want 200", i+1, code)
		}
	}
	if code := serve(h, exchangeReq("203.0.113.66", tenantB, githubIss)); code != http.StatusTooManyRequests {
		t.Fatalf("over the address backstop: got %d, want 429", code)
	}
	if code := serve(h, exchangeReq("198.51.100.20", tenantB, githubIss)); code != http.StatusOK {
		t.Fatalf("another address: got %d, want 200", code)
	}
}

// A body or token that cannot be read is limited by address, in the
// identity budget, and does not get a bucket per garbage value.
func TestCIExchangeRateLimit_UnreadableRequestsShareTheAddressBucket(t *testing.T) {
	h := newCIExchange(t, newFakeStore(), 3, 100, okHandler())
	bodies := []string{
		`not json`,
		`{"tenant_id":"` + tenantA + `"}`,
		`{"tenant_id":"` + tenantA + `","id_token":"a.b"}`,
		`{"tenant_id":"` + tenantA + `","id_token":"x.%%%.y"}`,
		`{"tenant_id":"","id_token":"` + ciToken(gitlabIss) + `"}`,
		`{"tenant_id":"` + tenantA + `","id_token":"` + ciToken(strings.Repeat("a", 600)) + `"}`,
	}
	codes := make([]int, 0, len(bodies))
	for _, b := range bodies {
		codes = append(codes, serve(h, exchangeRaw("203.0.113.66", b)))
	}
	want := []int{200, 200, 200, 429, 429, 429}
	for i := range want {
		if codes[i] != want[i] {
			t.Fatalf("unreadable request %d: got %d, want %d (all codes %v)", i+1, codes[i], want[i], codes)
		}
	}
}

func TestCIExchangeRateLimit_HandlerGetsTheWholeBody(t *testing.T) {
	var got string
	h := newCIExchange(t, nil, 3, 100, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	r := exchangeReq("198.51.100.20", tenantA, gitlabIss)
	want := `{"tenant_id":"` + tenantA + `","id_token":"` + ciToken(gitlabIss) + `"}`
	serve(h, r)
	if got != want {
		t.Fatalf("handler body = %q, want %q", got, want)
	}
	// An oversized body reaches the handler whole (it applies its own limit).
	big := strings.Repeat("x", 40<<10)
	serve(h, exchangeRaw("198.51.100.20", big))
	if got != big {
		t.Fatalf("oversized body truncated: got %d bytes, want %d", len(got), len(big))
	}
}

// Real Redis, when TEST_REDIS_ADDR (host:port) is set: two replicas share
// both budgets.
//
//	TEST_REDIS_ADDR=127.0.0.1:6390 go test ./internal/infra/http/middleware/ -run RealRedis
func TestCIExchangeRateLimit_RealRedisSharesBudgets(t *testing.T) {
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

	// Unique addresses per run: the bucket names are fixed.
	n := time.Now().UnixNano()
	ip := net.IPv4(10, byte(n>>16), byte(n>>8), byte(n)).String()
	other := net.IPv4(10, byte(n>>16), byte(n>>8), byte(n+1)).String()
	replicaA := newCIExchange(t, backend, 2, 4, okHandler())
	replicaB := newCIExchange(t, backend, 2, 4, okHandler())

	if code := serve(replicaA, exchangeReq(ip, tenantA, gitlabIss)); code != http.StatusOK {
		t.Fatalf("A 1: %d", code)
	}
	if code := serve(replicaB, exchangeReq(ip, tenantA, gitlabIss)); code != http.StatusOK {
		t.Fatalf("A 2: %d", code)
	}
	if code := serve(replicaA, exchangeReq(ip, tenantA, gitlabIss)); code != http.StatusTooManyRequests {
		t.Fatalf("A 3 over identity budget across replicas: got %d, want 429", code)
	}
	if code := serve(replicaB, exchangeReq(ip, tenantB, gitlabIss)); code != http.StatusOK {
		t.Fatalf("B behind the same address: got %d, want 200", code)
	}
	// Four requests counted on the address so far (the 429 included).
	if code := serve(replicaA, exchangeReq(ip, tenantB, githubIss)); code != http.StatusTooManyRequests {
		t.Fatalf("address backstop across replicas: got %d, want 429", code)
	}
	if code := serve(replicaB, exchangeReq(other, tenantA, gitlabIss)); code != http.StatusOK {
		t.Fatalf("another address: got %d, want 200", code)
	}
}
