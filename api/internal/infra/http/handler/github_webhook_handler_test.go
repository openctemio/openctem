package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type fakeGitHubService struct {
	secrets map[shared.ID][]string
	pushes  int
}

func (f *fakeGitHubService) ListGitHubWebhookSecrets(_ context.Context, tenantID shared.ID) ([]string, error) {
	return f.secrets[tenantID], nil
}

func (f *fakeGitHubService) HandleGitHubPush(context.Context, shared.ID, *integration.GitHubPushEvent) (bool, error) {
	f.pushes++
	return true, nil
}

// memoryDeliveries is an in-memory WebhookDeliveryGuard.
type memoryDeliveries struct {
	mu   sync.Mutex
	seen map[string]bool
	err  error
}

func (m *memoryDeliveries) FirstDelivery(_ context.Context, key string, ttl time.Duration) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	if ttl != GitHubDeliveryWindow {
		return false, errors.New("unexpected window")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[key] {
		return false, nil
	}
	m.seen[key] = true
	return true, nil
}

const pushBody = `{"ref":"refs/heads/main","after":"abc123","repository":{"full_name":"acme/app"}}`

func signedPush(tenant shared.ID, secret, delivery string) *http.Request {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write([]byte(pushBody))
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/incoming/github?tenant="+tenant.String(), strings.NewReader(pushBody))
	req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(m.Sum(nil)))
	req.Header.Set("X-GitHub-Event", "push")
	if delivery != "" {
		req.Header.Set("X-GitHub-Delivery", delivery)
	}
	return req
}

func newGitHubTestHandler(svc *fakeGitHubService, guard WebhookDeliveryGuard) *GitHubWebhookHandler {
	h := &GitHubWebhookHandler{service: svc, logger: logger.NewNop()}
	h.SetDeliveryGuard(guard)
	return h
}

func serveGitHub(h *GitHubWebhookHandler, req *http.Request) int {
	rec := httptest.NewRecorder()
	h.IncomingGitHubWebhook(rec, req)
	return rec.Code
}

// A captured signed delivery is processed once; replaying it (same delivery
// id) is acknowledged without touching anything.
func TestGitHubWebhook_ReplayOfADeliveryIsIgnored(t *testing.T) {
	tenant := shared.NewID()
	svc := &fakeGitHubService{secrets: map[shared.ID][]string{tenant: {"s3cret"}}}
	h := newGitHubTestHandler(svc, &memoryDeliveries{seen: map[string]bool{}})

	delivery := "72d3162e-cc78-11e3-81ab-4c9367dc0958"
	for i := 0; i < 3; i++ {
		if code := serveGitHub(h, signedPush(tenant, "s3cret", delivery)); code != http.StatusOK {
			t.Fatalf("delivery %d: got %d, want 200", i, code)
		}
	}
	if svc.pushes != 1 {
		t.Fatalf("push processed %d times, want once", svc.pushes)
	}
	// A new delivery id is processed.
	if code := serveGitHub(h, signedPush(tenant, "s3cret", "72d3162e-cc78-11e3-81ab-4c9367dc0959")); code != http.StatusOK || svc.pushes != 2 {
		t.Fatalf("new delivery: code %d, pushes %d; want 200 and 2", code, svc.pushes)
	}
}

// The delivery-id cache is per organization: another organization's delivery
// with the same id is not blocked, and an unsigned request never reaches it.
func TestGitHubWebhook_DeliveryIDsArePerOrganization(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	svc := &fakeGitHubService{secrets: map[shared.ID][]string{a: {"secret-a"}, b: {"secret-b"}}}
	guard := &memoryDeliveries{seen: map[string]bool{}}
	h := newGitHubTestHandler(svc, guard)

	id := "11111111-2222-3333-4444-555555555555"
	if code := serveGitHub(h, signedPush(a, "secret-a", id)); code != http.StatusOK {
		t.Fatalf("A: got %d", code)
	}
	if code := serveGitHub(h, signedPush(b, "secret-b", id)); code != http.StatusOK || svc.pushes != 2 {
		t.Fatalf("B with the same id: code %d, pushes %d; want 200 and 2", code, svc.pushes)
	}
	// B's delivery signed with A's secret is refused before the cache.
	before := len(guard.seen)
	if code := serveGitHub(h, signedPush(b, "secret-a", "99999999-2222-3333-4444-555555555555")); code != http.StatusUnauthorized {
		t.Fatalf("B signed with A's secret: got %d, want 401", code)
	}
	if len(guard.seen) != before {
		t.Fatalf("an unverified delivery must not be recorded")
	}
}

// Missing or malformed delivery ids are refused; a store outage fails closed.
func TestGitHubWebhook_DeliveryIDRequiredAndStoreFailsClosed(t *testing.T) {
	tenant := shared.NewID()
	svc := &fakeGitHubService{secrets: map[shared.ID][]string{tenant: {"s3cret"}}}
	h := newGitHubTestHandler(svc, &memoryDeliveries{seen: map[string]bool{}})
	for _, d := range []string{"", "not a guid!", strings.Repeat("a", 65)} {
		if code := serveGitHub(h, signedPush(tenant, "s3cret", d)); code != http.StatusBadRequest {
			t.Errorf("delivery %q: got %d, want 400", d, code)
		}
	}
	down := newGitHubTestHandler(svc, &memoryDeliveries{err: errors.New("redis down")})
	if code := serveGitHub(down, signedPush(tenant, "s3cret", "72d3162e-cc78-11e3-81ab-4c9367dc0958")); code != http.StatusServiceUnavailable {
		t.Errorf("store down: got %d, want 503", code)
	}
	if svc.pushes != 0 {
		t.Errorf("nothing may be processed, got %d pushes", svc.pushes)
	}
}
