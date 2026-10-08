package unit

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/auth"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/pkg/domain/identityprovider"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Anti-enumeration: the public sign-in endpoints answer an unknown
// organization or email exactly like a known one, so an unauthenticated
// caller cannot list customers or accounts.

func ssoHandlerFor(t *testing.T, slugs ...string) (*handler.SSOHandler, *ssoMockIPRepo) {
	t.Helper()
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	for _, s := range slugs {
		tenantRepo.addTenant(createTestTenant(s))
	}
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())
	return handler.NewSSOHandler(svc, logger.NewNop()), ipRepo
}

func getRec(fn http.HandlerFunc, target string, pathValues map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for k, v := range pathValues {
		req.SetPathValue(k, v)
	}
	rec := httptest.NewRecorder()
	fn(rec, req)
	return rec
}

func TestSSOProviders_UnknownOrgLooksLikeOrgWithoutSSO(t *testing.T) {
	h, _ := ssoHandlerFor(t, "known-org")
	known := getRec(h.ListTenantProviders, "/api/v1/auth/sso/providers?org=known-org", nil)
	unknown := getRec(h.ListTenantProviders, "/api/v1/auth/sso/providers?org=no-such-org", nil)
	if known.Code != http.StatusOK || unknown.Code != http.StatusOK {
		t.Fatalf("both must answer 200, got known=%d unknown=%d", known.Code, unknown.Code)
	}
	if !bytes.Equal(known.Body.Bytes(), unknown.Body.Bytes()) {
		t.Fatalf("bodies differ:\nknown:   %s\nunknown: %s", known.Body.String(), unknown.Body.String())
	}
	var body map[string][]any
	if err := json.Unmarshal(unknown.Body.Bytes(), &body); err != nil || body["providers"] == nil || len(body["providers"]) != 0 {
		t.Fatalf("expected {providers: []}, got %s", unknown.Body.String())
	}
}

// A known organization with SSO still lists its providers.
func TestSSOProviders_KnownOrgListsProviders(t *testing.T) {
	ipRepo := newSSOmockIPRepo()
	tenantRepo := newSSOmockTenantRepo()
	tn := createTestTenant("acme")
	tenantRepo.addTenant(tn)
	p := createTestProvider(tn.ID().String(), identityprovider.ProviderOkta, true)
	ipRepo.providers[p.ID()] = p
	svc := newTestSSOService(ipRepo, tenantRepo, newSSOmockUserRepo(), newSSOmockSessionRepo(), newSSOmockRefreshTokenRepo(), newSSOmockEncryptor())
	got, err := svc.GetProvidersForTenant(context.Background(), "acme")
	if err != nil || len(got) != 1 {
		t.Fatalf("expected the provider, got %v %v", got, err)
	}
}

func TestSSOAuthorize_UnknownOrgLooksLikeMissingProvider(t *testing.T) {
	h, _ := ssoHandlerFor(t, "known-org")
	redirect := "&redirect_uri=" + "http%3A%2F%2Flocalhost%3A3000%2Fauth%2Fsso%2Fcallback"
	known := getRec(h.Authorize, "/api/v1/auth/sso/okta/authorize?org=known-org"+redirect, map[string]string{"provider": "okta"})
	unknown := getRec(h.Authorize, "/api/v1/auth/sso/okta/authorize?org=no-such-org"+redirect, map[string]string{"provider": "okta"})
	if known.Code != unknown.Code || !bytes.Equal(known.Body.Bytes(), unknown.Body.Bytes()) {
		t.Fatalf("answers differ:\nknown:   %d %s\nunknown: %d %s", known.Code, known.Body.String(), unknown.Code, unknown.Body.String())
	}
	if known.Code != http.StatusNotFound {
		t.Fatalf("expected a refusal, got %d %s", known.Code, known.Body.String())
	}
}

func TestSAMLMetadata_ServedForAnyWellFormedSlug(t *testing.T) {
	tenantRepo := newSSOmockTenantRepo()
	tenantRepo.addTenant(createTestTenant("known-org"))
	svc := auth.NewSAMLService(nil, tenantRepo, nil, logger.NewNop())
	ctx := context.Background()
	known, err := svc.Metadata(ctx, "known-org", "https://app.example.com")
	if err != nil {
		t.Fatalf("known: %v", err)
	}
	unknown, err := svc.Metadata(ctx, "no-such-org", "https://app.example.com")
	if err != nil {
		t.Fatalf("an unknown well-formed slug must be served like a known one, got %v", err)
	}
	if len(unknown) == 0 || len(known) == 0 {
		t.Fatal("expected metadata")
	}
	if _, err := svc.Metadata(ctx, "Bad Slug/..", "https://app.example.com"); err == nil {
		t.Fatal("a malformed slug must be refused")
	}
}

// Register: a new email and an existing one get byte-identical answers, and
// a weak password is refused for both.
func TestRegister_NewAndExistingEmailAnswerIdentically(t *testing.T) {
	svc, deps := newTestAuthService()
	sess := auth.NewSessionService(deps.sessionRepo, deps.rtRepo, logger.NewNop())
	h := handler.NewLocalAuthHandler(svc, sess, nil, nil, deps.cfg, logger.NewNop())

	first := postJSON(t, h.Register, map[string]string{"email": "taken@example.com", "password": "Str0ngPassw0rd!", "name": "Same Name"})
	if first.Code != http.StatusCreated {
		t.Fatalf("seed registration: %d %s", first.Code, first.Body.String())
	}
	again := postJSON(t, h.Register, map[string]string{"email": "taken@example.com", "password": "An0therPassw0rd!", "name": "Same Name"})
	fresh := postJSON(t, h.Register, map[string]string{"email": "fresh@example.com", "password": "Str0ngPassw0rd!", "name": "Same Name"})
	if again.Code != fresh.Code {
		t.Fatalf("status differs: existing=%d new=%d", again.Code, fresh.Code)
	}
	var a, f map[string]any
	_ = json.Unmarshal(again.Body.Bytes(), &a)
	_ = json.Unmarshal(fresh.Body.Bytes(), &f)
	delete(a, "email")
	delete(f, "email")
	ab, _ := json.Marshal(a)
	fb, _ := json.Marshal(f)
	if !bytes.Equal(ab, fb) {
		t.Fatalf("bodies differ beyond the echoed email:\nexisting: %s\nnew:      %s", again.Body.String(), fresh.Body.String())
	}
	if id, _ := f["id"].(string); id != "" {
		t.Fatalf("the response must not carry the account id, got %q", id)
	}

	weakExisting := postJSON(t, h.Register, map[string]string{"email": "taken@example.com", "password": "short", "name": "N"})
	weakNew := postJSON(t, h.Register, map[string]string{"email": "other@example.com", "password": "short", "name": "N"})
	if weakExisting.Code != weakNew.Code || !bytes.Equal(weakExisting.Body.Bytes(), weakNew.Body.Bytes()) {
		t.Fatalf("a weak password must be refused the same way:\nexisting: %d %s\nnew:      %d %s",
			weakExisting.Code, weakExisting.Body.String(), weakNew.Code, weakNew.Body.String())
	}
}

// Forgot password: unknown and known emails get the same answer. Each call
// gets its own service: the lookup runs in the background after the response,
// and the in-memory test repository is not safe for concurrent use.
func TestForgotPassword_UnknownAndKnownEmailAnswerIdentically(t *testing.T) {
	forgot := func(seed bool, email string) *httptest.ResponseRecorder {
		svc, deps := newTestAuthService()
		sess := auth.NewSessionService(deps.sessionRepo, deps.rtRepo, logger.NewNop())
		h := handler.NewLocalAuthHandler(svc, sess, nil, nil, deps.cfg, logger.NewNop())
		if seed {
			if rec := postJSON(t, h.Register, map[string]string{"email": email, "password": "Str0ngPassw0rd!", "name": "K"}); rec.Code != http.StatusCreated {
				t.Fatalf("seed: %d", rec.Code)
			}
		}
		return postJSON(t, h.ForgotPassword, map[string]string{"email": email})
	}
	known := forgot(true, "known@example.com")
	unknown := forgot(false, "unknown@example.com")
	if known.Code != unknown.Code || !bytes.Equal(known.Body.Bytes(), unknown.Body.Bytes()) {
		t.Fatalf("answers differ: known %d %s, unknown %d %s", known.Code, known.Body.String(), unknown.Code, unknown.Body.String())
	}
}
