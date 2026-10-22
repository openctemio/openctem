package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/scim"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/scimtoken"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type memScimRepo struct {
	byID map[shared.ID]*scimtoken.ScimToken
}

func (m *memScimRepo) Create(_ context.Context, t *scimtoken.ScimToken) error {
	m.byID[t.ID()] = t
	return nil
}
func (m *memScimRepo) GetByHash(context.Context, string) (*scimtoken.ScimToken, error) {
	return nil, scimtoken.ErrNotFound
}
func (m *memScimRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*scimtoken.ScimToken, error) {
	if t, ok := m.byID[id]; ok && t.TenantID() == tenantID {
		return t, nil
	}
	return nil, scimtoken.ErrNotFound
}
func (m *memScimRepo) ListByTenant(_ context.Context, tenantID shared.ID) ([]*scimtoken.ScimToken, error) {
	var out []*scimtoken.ScimToken
	for _, t := range m.byID {
		if t.TenantID() == tenantID {
			out = append(out, t)
		}
	}
	return out, nil
}
func (m *memScimRepo) Update(_ context.Context, t *scimtoken.ScimToken) error {
	m.byID[t.ID()] = t
	return nil
}
func (m *memScimRepo) TouchLastUsed(context.Context, shared.ID, shared.ID, time.Time) error {
	return nil
}
func (m *memScimRepo) ShortenExpiry(_ context.Context, tenantID, id shared.ID, at time.Time) error {
	t, ok := m.byID[id]
	if !ok || t.TenantID() != tenantID || !t.IsActive() {
		return scimtoken.ErrNotFound
	}
	t.ExpireBy(at)
	return nil
}

func scimTokenRequest(method, path, body string, tenant shared.ID, id string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
	if id != "" {
		rc := chi.NewRouteContext()
		rc.URLParams.Add("id", id)
		ctx = context.WithValue(ctx, chi.RouteCtxKey, rc)
	}
	return req.WithContext(ctx)
}

func TestSCIMTokenHandler_CreateNeedsLifetime(t *testing.T) {
	repo := &memScimRepo{byID: map[shared.ID]*scimtoken.ScimToken{}}
	h := NewSCIMTokenHandler(scim.NewTokenService(repo, "pepper", logger.NewNop()), logger.NewNop())
	tenant := shared.NewID()

	for _, body := range []string{`{"name":"okta"}`, `{"name":"okta","expires_in_days":0}`, `{"name":"okta","expires_in_days":366}`} {
		rec := httptest.NewRecorder()
		h.Create(rec, scimTokenRequest(http.MethodPost, "/api/v1/scim-tokens", body, tenant, ""))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", body, rec.Code)
		}
	}
	if len(repo.byID) != 0 {
		t.Fatal("a token was minted without a valid lifetime")
	}

	rec := httptest.NewRecorder()
	h.Create(rec, scimTokenRequest(http.MethodPost, "/api/v1/scim-tokens", `{"name":"okta","expires_in_days":30}`, tenant, ""))
	if rec.Code != http.StatusCreated || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create: %d %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	var created struct {
		ID        string `json:"id"`
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if created.Token == "" || created.ExpiresAt == "" {
		t.Fatalf("create body %s", rec.Body.String())
	}

	// Rotation by another tenant: not found, nothing minted.
	rec = httptest.NewRecorder()
	h.Rotate(rec, scimTokenRequest(http.MethodPost, "/api/v1/scim-tokens/x/rotate", ``, shared.NewID(), created.ID))
	if rec.Code != http.StatusNotFound || len(repo.byID) != 1 {
		t.Fatalf("cross-tenant rotate: %d, %d tokens", rec.Code, len(repo.byID))
	}

	rec = httptest.NewRecorder()
	h.Rotate(rec, scimTokenRequest(http.MethodPost, "/api/v1/scim-tokens/x/rotate", ``, tenant, created.ID))
	if rec.Code != http.StatusCreated {
		t.Fatalf("rotate: %d %s", rec.Code, rec.Body.String())
	}
	var rotated struct {
		Token             string `json:"token"`
		ReplacedID        string `json:"replaced_id"`
		ReplacedExpiresAt string `json:"replaced_expires_at"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &rotated)
	if rotated.Token == "" || rotated.Token == created.Token || rotated.ReplacedID != created.ID || rotated.ReplacedExpiresAt == "" {
		t.Fatalf("rotate body %s", rec.Body.String())
	}

	// The list shows expiry, and an expired token as expired.
	old, _ := shared.IDFromString(created.ID)
	repo.byID[old].ExpireBy(time.Now().Add(-time.Minute))
	rec = httptest.NewRecorder()
	h.List(rec, scimTokenRequest(http.MethodGet, "/api/v1/scim-tokens", ``, tenant, ""))
	var list struct {
		Tokens []struct {
			ID        string `json:"id"`
			Status    string `json:"status"`
			ExpiresAt string `json:"expires_at"`
		} `json:"tokens"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	statuses := map[string]string{}
	for _, tk := range list.Tokens {
		if tk.ExpiresAt == "" {
			t.Fatalf("list without expires_at: %s", rec.Body.String())
		}
		statuses[tk.ID] = tk.Status
	}
	if statuses[created.ID] != "expired" || len(statuses) != 2 {
		t.Fatalf("statuses %v", statuses)
	}
}
