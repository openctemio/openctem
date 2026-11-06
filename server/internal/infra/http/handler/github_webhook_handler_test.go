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

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/internal/app/ticketing"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// fakeGitHubIntegration is one GitHub integration as the verifier sees it.
type fakeGitHubIntegration struct {
	tenant shared.ID
	secret string
	org    string
}

type fakeGitHubService struct {
	integrations map[shared.ID]fakeGitHubIntegration
	verifyErr    error
	pushes       int
	pushErr      error
}

// newFakeGitHub returns a service holding one integration.
func newFakeGitHub(integrationID, tenant shared.ID, secret string) *fakeGitHubService {
	return &fakeGitHubService{integrations: map[shared.ID]fakeGitHubIntegration{integrationID: {tenant: tenant, secret: secret}}}
}

func (f *fakeGitHubService) VerifyGitHubDelivery(_ context.Context, id shared.ID, body []byte, sig string) (integration.GitHubDelivery, error) {
	if f.verifyErr != nil {
		return integration.GitHubDelivery{}, f.verifyErr
	}
	intg, ok := f.integrations[id]
	if !ok || !integration.VerifyGitHubSignature(body, sig, intg.secret) {
		return integration.GitHubDelivery{}, integration.ErrGitHubWebhookUnauthorized
	}
	return integration.GitHubDelivery{TenantID: intg.tenant, IntegrationID: id, Organization: intg.org}, nil
}

func (f *fakeGitHubService) HandleGitHubPush(context.Context, shared.ID, *integration.GitHubPushEvent) (bool, error) {
	f.pushes++
	return true, f.pushErr
}

// memoryDeliveries is an in-memory WebhookDeliveryGuard (and releaser).
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

func (m *memoryDeliveries) ReleaseDelivery(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.seen, key)
	return nil
}

type recordingIssueSink struct {
	events  []ticketing.GitHubIssueEvent
	tenants []shared.ID
	err     error
}

func (s *recordingIssueSink) HandleIssueEvent(_ context.Context, tenant shared.ID, ev ticketing.GitHubIssueEvent) error {
	s.events = append(s.events, ev)
	s.tenants = append(s.tenants, tenant)
	return s.err
}

const pushBody = `{"ref":"refs/heads/main","after":"abc123","repository":{"full_name":"acme/app"}}`

func signedGitHub(integrationID shared.ID, secret, event, delivery, body string) *http.Request {
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write([]byte(body))
	req := httptest.NewRequest(http.MethodPost, "/hooks/github-integrations/"+integrationID.String(), strings.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(m.Sum(nil)))
	req.Header.Set("X-GitHub-Event", event)
	if delivery != "" {
		req.Header.Set("X-GitHub-Delivery", delivery)
	}
	return req
}

func signedPush(integrationID shared.ID, secret, delivery string) *http.Request {
	return signedGitHub(integrationID, secret, "push", delivery, pushBody)
}

func newGitHubTestHandler(svc *fakeGitHubService, guard WebhookDeliveryGuard) *GitHubWebhookHandler {
	h := &GitHubWebhookHandler{service: svc, logger: logger.NewNop()}
	if guard != nil {
		h.SetDeliveryGuard(guard)
	}
	return h
}

func serveGitHubRec(h *GitHubWebhookHandler, req *http.Request) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	r.Post("/hooks/github-integrations/{integration_id}", h.IncomingGitHubWebhook)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func serveGitHub(h *GitHubWebhookHandler, req *http.Request) int {
	return serveGitHubRec(h, req).Code
}

// A captured signed delivery is processed once; replaying it with the same
// delivery id, or with a NEW delivery id (the header is outside the
// signature), is acknowledged without touching anything.
func TestGitHubWebhook_ReplayIsIgnoredEvenWithANewDeliveryID(t *testing.T) {
	intg := shared.NewID()
	svc := newFakeGitHub(intg, shared.NewID(), "s3cret")
	h := newGitHubTestHandler(svc, &memoryDeliveries{seen: map[string]bool{}})

	delivery := "72d3162e-cc78-11e3-81ab-4c9367dc0958"
	for i := 0; i < 3; i++ {
		if code := serveGitHub(h, signedPush(intg, "s3cret", delivery)); code != http.StatusOK {
			t.Fatalf("delivery %d: got %d, want 200", i, code)
		}
	}
	if code := serveGitHub(h, signedPush(intg, "s3cret", "72d3162e-cc78-11e3-81ab-4c9367dc0959")); code != http.StatusOK {
		t.Fatalf("replay with a new id: got %d, want 200", code)
	}
	if svc.pushes != 1 {
		t.Fatalf("push processed %d times, want once", svc.pushes)
	}
	// A different body is a new delivery.
	other := `{"ref":"refs/heads/main","after":"def456","repository":{"full_name":"acme/app"}}`
	if code := serveGitHub(h, signedGitHub(intg, "s3cret", "push", "72d3162e-cc78-11e3-81ab-4c9367dc0960", other)); code != http.StatusOK || svc.pushes != 2 {
		t.Fatalf("new body: code %d, pushes %d; want 200 and 2", code, svc.pushes)
	}
}

// Replay protection is mandatory: without a delivery store nothing is
// processed (503).
func TestGitHubWebhook_NoDeliveryStoreFailsClosed(t *testing.T) {
	intg := shared.NewID()
	svc := newFakeGitHub(intg, shared.NewID(), "s3cret")
	h := newGitHubTestHandler(svc, nil)
	if code := serveGitHub(h, signedPush(intg, "s3cret", "72d3162e-cc78-11e3-81ab-4c9367dc0958")); code != http.StatusServiceUnavailable {
		t.Fatalf("no store: got %d, want 503", code)
	}
	if svc.pushes != 0 {
		t.Fatal("a delivery was processed without replay protection")
	}
}

// The URL names one integration: another integration's id (another
// tenant's, or an unknown one) with this signature is refused before the
// cache, and so is a signature under another integration's secret.
func TestGitHubWebhook_CrossTenantIntegrationAndSignatureRefused(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	svc := &fakeGitHubService{integrations: map[shared.ID]fakeGitHubIntegration{
		a: {tenant: shared.NewID(), secret: "secret-a"},
		b: {tenant: shared.NewID(), secret: "secret-b"},
	}}
	guard := &memoryDeliveries{seen: map[string]bool{}}
	h := newGitHubTestHandler(svc, guard)

	for name, req := range map[string]*http.Request{
		"B's URL signed with A's secret": signedPush(b, "secret-a", "99999999-2222-3333-4444-555555555551"),
		"A's URL signed with B's secret": signedPush(a, "secret-b", "99999999-2222-3333-4444-555555555552"),
		"unknown integration":            signedPush(shared.NewID(), "secret-a", "99999999-2222-3333-4444-555555555553"),
	} {
		if code := serveGitHub(h, req); code != http.StatusUnauthorized {
			t.Errorf("%s: got %d, want 401", name, code)
		}
	}
	bad := httptest.NewRequest(http.MethodPost, "/hooks/github-integrations/not-a-uuid", strings.NewReader(pushBody))
	if code := serveGitHub(h, bad); code != http.StatusUnauthorized {
		t.Errorf("malformed id: got %d, want 401", code)
	}
	if len(guard.seen) != 0 || svc.pushes != 0 {
		t.Fatalf("an unverified delivery was recorded (%d) or processed (%d)", len(guard.seen), svc.pushes)
	}
	// A verification outage (not a bad signature) is a 503.
	svc.verifyErr = errors.New("db down")
	if code := serveGitHub(h, signedPush(a, "secret-a", "99999999-2222-3333-4444-555555555554")); code != http.StatusServiceUnavailable {
		t.Errorf("verification outage: got %d, want 503", code)
	}
}

// Missing or malformed delivery ids are refused; a store outage fails closed.
func TestGitHubWebhook_DeliveryIDRequiredAndStoreFailsClosed(t *testing.T) {
	intg := shared.NewID()
	svc := newFakeGitHub(intg, shared.NewID(), "s3cret")
	h := newGitHubTestHandler(svc, &memoryDeliveries{seen: map[string]bool{}})
	for _, d := range []string{"", "not a guid!", strings.Repeat("a", 65)} {
		if code := serveGitHub(h, signedPush(intg, "s3cret", d)); code != http.StatusBadRequest {
			t.Errorf("delivery %q: got %d, want 400", d, code)
		}
	}
	down := newGitHubTestHandler(svc, &memoryDeliveries{err: errors.New("redis down")})
	if code := serveGitHub(down, signedPush(intg, "s3cret", "72d3162e-cc78-11e3-81ab-4c9367dc0958")); code != http.StatusServiceUnavailable {
		t.Errorf("store down: got %d, want 503", code)
	}
	if svc.pushes != 0 {
		t.Errorf("nothing may be processed, got %d pushes", svc.pushes)
	}
}

// An event for a repository outside the integration's organization is
// refused and not recorded.
func TestGitHubWebhook_RepositoryBoundToIntegration(t *testing.T) {
	intg := shared.NewID()
	svc := newFakeGitHub(intg, shared.NewID(), "s3cret")
	i := svc.integrations[intg]
	i.org = "Acme"
	svc.integrations[intg] = i
	sink := &recordingIssueSink{}
	guard := &memoryDeliveries{seen: map[string]bool{}}
	h := newGitHubTestHandler(svc, guard)
	h.SetIssueSink(sink)

	foreign := `{"action":"closed","issue":{"html_url":"https://github.com/evil/app/issues/1","state_reason":"completed"},"repository":{"full_name":"evil/app"}}`
	if code := serveGitHub(h, signedGitHub(intg, "s3cret", "issues", "11111111-2222-3333-4444-555555555551", foreign)); code != http.StatusForbidden {
		t.Fatalf("foreign repository: got %d, want 403", code)
	}
	noRepo := `{"action":"closed","issue":{"html_url":"https://github.com/acme/app/issues/1"}}`
	if code := serveGitHub(h, signedGitHub(intg, "s3cret", "issues", "11111111-2222-3333-4444-555555555552", noRepo)); code != http.StatusForbidden {
		t.Fatalf("no repository: got %d, want 403", code)
	}
	if len(sink.events) != 0 || len(guard.seen) != 0 {
		t.Fatal("a refused event reached the sink or the cache")
	}
	// The organization's own repository (owner compared case-insensitively).
	if code := serveGitHub(h, signedPush(intg, "s3cret", "11111111-2222-3333-4444-555555555553")); code != http.StatusOK || svc.pushes != 1 {
		t.Fatalf("own repository: code %d pushes %d", code, svc.pushes)
	}
}

// An issues event reaches the sink with the verified tenant, the state
// reason and the sender; a processing failure releases the keys so a
// redelivery is processed.
func TestGitHubWebhook_IssueEventToSinkAndRedeliveryAfterFailure(t *testing.T) {
	intg, tenant := shared.NewID(), shared.NewID()
	svc := newFakeGitHub(intg, tenant, "s3cret")
	sink := &recordingIssueSink{err: errors.New("db down")}
	h := newGitHubTestHandler(svc, &memoryDeliveries{seen: map[string]bool{}})
	h.SetIssueSink(sink)

	body := `{"action":"closed","issue":{"html_url":"https://github.com/acme/app/issues/7","state_reason":"not_planned"},"repository":{"full_name":"acme/app"},"sender":{"login":"octocat"}}`
	delivery := "22222222-2222-3333-4444-555555555555"
	if code := serveGitHub(h, signedGitHub(intg, "s3cret", "issues", delivery, body)); code != http.StatusInternalServerError {
		t.Fatalf("failed processing: got %d, want 500", code)
	}
	sink.err = nil
	if code := serveGitHub(h, signedGitHub(intg, "s3cret", "issues", delivery, body)); code != http.StatusOK {
		t.Fatalf("redelivery: got %d, want 200", code)
	}
	if len(sink.events) != 2 {
		t.Fatalf("sink saw %d events, want 2 (failure, then redelivery)", len(sink.events))
	}
	ev := sink.events[1]
	if sink.tenants[1] != tenant || ev.Action != "closed" || ev.StateReason != "not_planned" ||
		ev.Sender != "octocat" || ev.IssueURL != "https://github.com/acme/app/issues/7" {
		t.Fatalf("sink got %+v for tenant %s", ev, sink.tenants[1])
	}
}
