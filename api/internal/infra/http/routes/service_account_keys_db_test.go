package routes

// API keys of a service account against a migrated database: a key is minted
// only for a service account of the caller's organization, only with scopes
// the caller holds, and at request time carries only the scopes the account
// itself still holds. Another organization's account, a person, or a key of
// someone else reads as not found.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/app/apikey"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// harnessPerms reads a user's live permissions from the database.
type harnessPerms struct{ h *grbHarness }

func (p harnessPerms) GetPermissionsWithFallback(_ context.Context, _, userID string) ([]string, error) {
	id, err := shared.IDFromString(userID)
	if err != nil {
		return nil, err
	}
	return p.h.perms(id), nil
}

func TestServiceAccountKeys(t *testing.T) {
	h := newGRBHarness(t)
	ctx := context.Background()
	db := &postgres.DB{DB: h.db}
	repo := postgres.NewServiceAccountRepository(db)
	svc := accesscontrol.NewServiceAccountService(repo, nil, logger.NewNop())
	keys := apikey.NewService(postgres.NewAPIKeyRepository(db), "test-pepper", logger.NewNop())
	keys.SetHolderPermissions(apikey.NewHolderPermissions(postgres.NewTenantRepository(db), harnessPerms{h}))
	hd := handler.NewServiceAccountHandler(svc, keys, validator.New(), logger.NewNop())

	r := chi.NewRouter()
	r.Get("/{id}/api-keys", hd.ListKeys)
	r.Post("/{id}/api-keys", hd.CreateKey)
	r.Delete("/{id}/api-keys/{key_id}", hd.DeleteKey)

	a, err := svc.Create(ctx, accesscontrol.CreateServiceAccountInput{Name: "ticket bridge"}, h.actx(h.owner))
	if err != nil {
		t.Fatal(err)
	}
	// The account holds findings:read and findings:verify (analyst).
	h.exec(`INSERT INTO user_roles (user_id, tenant_id, role_id) VALUES ($1, $2, $3)`, a.ID.String(), h.tenant.String(), h.analyst.String())

	// The caller: a delegated member (not an administrator) who holds
	// findings:read and assets:read but not findings:verify.
	callerPerms := []string{"findings:read", "assets:read", "integrations:api_keys:write", "integrations:api_keys:read", "integrations:api_keys:delete", "team:members:write", "team:members:read"}
	call := func(tenant shared.ID, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		c := context.WithValue(req.Context(), middleware.TenantIDKey, tenant.String())
		c = context.WithValue(c, middleware.UserIDKey, h.lead.String())
		c = context.WithValue(c, middleware.PermissionsKey, callerPerms)
		c = context.WithValue(c, middleware.IsAdminKey, false)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req.WithContext(c))
		return w
	}
	mint := func(tenant, account shared.ID, scopes string) *httptest.ResponseRecorder {
		return call(tenant, http.MethodPost, "/"+account.String()+"/api-keys",
			`{"name":"k-`+shared.NewID().String()+`","expires_in_days":30,"scopes":[`+scopes+`]}`)
	}

	// Minted with scopes the caller holds; the account does not hold
	// assets:read, so the key never carries it.
	w := mint(h.tenant, a.ID, `"findings:read","assets:read"`)
	if w.Code != http.StatusCreated {
		t.Fatalf("mint: %d %s", w.Code, w.Body)
	}
	var created handler.CreateAPIKeyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || !strings.HasPrefix(created.Key, "oct_") {
		t.Fatalf("mint response: %v %s", err, w.Body)
	}
	key, perms, err := keys.AuthenticateWithPermissions(ctx, created.Key, "127.0.0.1")
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if key.UserID() == nil || *key.UserID() != a.ID {
		t.Fatalf("the key does not act as the service account: %v", key.UserID())
	}
	if !slices.Equal(perms, []string{"findings:read"}) {
		t.Fatalf("the key carries %v, want only what both the caller granted and the account holds", perms)
	}

	// A scope the caller does not hold is refused, even though the account holds it.
	if w := mint(h.tenant, a.ID, `"findings:verify"`); w.Code != http.StatusForbidden {
		t.Errorf("a scope the caller lacks: %d %s", w.Code, w.Body)
	}
	// No scope at all is refused.
	if w := mint(h.tenant, a.ID, ``); w.Code != http.StatusBadRequest {
		t.Errorf("no scope: %d %s", w.Code, w.Body)
	}
	// A person is not a service account; another organization cannot reach it.
	if w := mint(h.tenant, h.member, `"findings:read"`); w.Code != http.StatusNotFound {
		t.Errorf("a key for a person: %d %s", w.Code, w.Body)
	}
	if w := mint(h.other, a.ID, `"findings:read"`); w.Code != http.StatusNotFound {
		t.Errorf("a key from another organization: %d %s", w.Code, w.Body)
	}

	// Listing shows only the account's keys.
	personKey := shared.NewID()
	h.exec(`INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash, key_prefix, status) VALUES ($1, $2, $3, 'person', $4, 'oct_pers', 'active')`,
		personKey.String(), h.tenant.String(), h.member.String(), "hash-"+personKey.String())
	w = call(h.tenant, http.MethodGet, "/"+a.ID.String()+"/api-keys", "")
	var list handler.ListResponse[handler.APIKeyResponse]
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || w.Code != http.StatusOK || len(list.Data) != 1 || list.Data[0].ID != created.ID {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
	if w := call(h.other, http.MethodGet, "/"+a.ID.String()+"/api-keys", ""); w.Code != http.StatusNotFound {
		t.Errorf("listed from another organization: %d", w.Code)
	}

	// A person's key cannot be deleted through the account; its own can.
	if w := call(h.tenant, http.MethodDelete, "/"+a.ID.String()+"/api-keys/"+personKey.String(), ""); w.Code != http.StatusNotFound {
		t.Errorf("deleted a person's key through the account: %d", w.Code)
	}
	if w := call(h.tenant, http.MethodDelete, "/"+a.ID.String()+"/api-keys/"+created.ID, ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if _, _, err := keys.AuthenticateWithPermissions(ctx, created.Key, "127.0.0.1"); err == nil {
		t.Fatal("a deleted key still authenticates")
	}
}
