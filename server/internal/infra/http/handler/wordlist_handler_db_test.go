package handler

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/contentpin"
	wordlistapp "github.com/openctemio/openctem/api/internal/app/wordlist"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/wordlist"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type previewFn func(tenantID shared.ID, root, depth string) (*contentpin.Preview, error)

func (f previewFn) Preview(_ context.Context, tenantID shared.ID, root, depth string) (*contentpin.Preview, error) {
	return f(tenantID, root, depth)
}

// The wordlist API end to end (handler, service, Postgres): create with a
// report of dropped lines, read with labels, an oversized body refused,
// and tenant isolation: another organization's list is 404 for read,
// update and delete, and absent from its list. The preview runs for the
// caller's tenant only. Route gating is covered by the route tests.
// Requires DATABASE_URL.
func TestWordlistAPI_DB(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set")
	}
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	tenant := func() string {
		id := shared.NewID().String()
		if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'wlh', $2)`, id, "wlh-"+id); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM tenants WHERE id = $1`, id) })
		return id
	}
	a, b := tenant(), tenant()
	var previewTenant shared.ID
	svc := wordlistapp.NewService(postgres.NewTenantWordlistRepository(&postgres.DB{DB: db}), nil, logger.NewNop())
	h := NewWordlistHandler(svc, previewFn(func(tid shared.ID, root, _ string) (*contentpin.Preview, error) {
		previewTenant = tid
		return &contentpin.Preview{Root: root, Learned: 7, Total: 7}, nil
	}), logger.NewNop())
	r := chi.NewRouter()
	r.Get("/wordlists", h.List)
	r.Get("/wordlists/preview", h.Preview)
	r.Get("/wordlists/{id}", h.Get)
	r.Post("/wordlists", h.Create)
	r.Patch("/wordlists/{id}", h.Update)
	r.Delete("/wordlists/{id}", h.Delete)
	do := func(tenantID, method, path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), middleware.TenantIDKey, tenantID))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	rec := do(a, http.MethodPost, "/wordlists", []byte(`{"name":"branches","text":"hn01\nhcm02\nhttp://x\n"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var saved WordlistSaveResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &saved)
	if saved.Wordlist.Lines != 2 || saved.Report == nil || saved.Report.Invalid != 1 || saved.Wordlist.Content != "" {
		t.Fatalf("saved %+v", saved)
	}
	id := saved.Wordlist.ID

	rec = do(a, http.MethodGet, "/wordlists/"+id, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"content":"hn01\nhcm02\n"`) {
		t.Fatalf("get: %d %s", rec.Code, rec.Body)
	}
	// Tenant isolation.
	for _, c := range []struct{ method, body string }{{http.MethodGet, ""}, {http.MethodPatch, `{"enabled":false}`}, {http.MethodDelete, ""}} {
		if rec := do(b, c.method, "/wordlists/"+id, []byte(c.body)); rec.Code != http.StatusNotFound {
			t.Fatalf("%s as another organization: %d", c.method, rec.Code)
		}
	}
	rec = do(b, http.MethodGet, "/wordlists", nil)
	if strings.Contains(rec.Body.String(), id) {
		t.Fatal("another organization lists the list")
	}
	// Unknown fields, oversized bodies and invalid text are refused.
	if rec := do(a, http.MethodPost, "/wordlists", []byte(`{"name":"x","text":"a\n","tenant_id":"`+b+`"}`)); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", rec.Code)
	}
	big, _ := json.Marshal(map[string]string{"name": "big", "text": strings.Repeat("a\n", wordlist.MaxInputBytes)})
	if rec := do(a, http.MethodPost, "/wordlists", big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized: %d", rec.Code)
	}
	if rec := do(a, http.MethodPost, "/wordlists", []byte(`{"name":"empty","text":"*.x\n"}`)); rec.Code != http.StatusBadRequest ||
		!strings.Contains(rec.Body.String(), "WORDLIST_EMPTY") {
		t.Fatalf("empty: %d %s", rec.Code, rec.Body)
	}
	if rec := do(a, http.MethodPost, "/wordlists", []byte(`{"name":"branches","text":"z\n"}`)); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate name: %d", rec.Code)
	}
	// The preview is the caller's tenant's.
	rec = do(a, http.MethodGet, "/wordlists/preview?root=example.vn", nil)
	if rec.Code != http.StatusOK || previewTenant.String() != a {
		t.Fatalf("preview: %d %s for %s", rec.Code, rec.Body, previewTenant)
	}
	if rec := do(a, http.MethodGet, "/wordlists/preview?root=example.vn&depth=full", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("depth full: %d", rec.Code)
	}
	if rec := do(a, http.MethodDelete, "/wordlists/"+id, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
}
