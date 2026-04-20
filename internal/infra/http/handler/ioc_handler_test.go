package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/ioc"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// mockIOCRepo is a concurrency-safe in-memory implementation of
// ioc.Repository used only by these handler tests. Keeps the tests
// focused on the HTTP contract (status codes, body shape) rather than
// repository behaviour.
type mockIOCRepo struct {
	mu   sync.Mutex
	inds map[string]*ioc.Indicator
}

func newMockIOCRepo() *mockIOCRepo {
	return &mockIOCRepo{inds: make(map[string]*ioc.Indicator)}
}

func (m *mockIOCRepo) Create(_ context.Context, ind *ioc.Indicator) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inds[ind.ID.String()] = ind
	return nil
}

func (m *mockIOCRepo) GetByID(_ context.Context, tenantID, id shared.ID) (*ioc.Indicator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ind, ok := m.inds[id.String()]
	if !ok || ind.TenantID != tenantID {
		return nil, shared.ErrNotFound
	}
	return ind, nil
}

func (m *mockIOCRepo) FindActiveByValues(_ context.Context, _ shared.ID, _ []ioc.Candidate) ([]*ioc.Indicator, error) {
	return nil, nil
}

func (m *mockIOCRepo) RecordMatch(_ context.Context, _ ioc.Match) error { return nil }

func (m *mockIOCRepo) ListByTenant(_ context.Context, tenantID shared.ID, limit, _ int) ([]*ioc.Indicator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*ioc.Indicator, 0, len(m.inds))
	for _, ind := range m.inds {
		if ind.TenantID == tenantID {
			out = append(out, ind)
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (m *mockIOCRepo) Deactivate(_ context.Context, tenantID, id shared.ID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ind, ok := m.inds[id.String()]
	if !ok || ind.TenantID != tenantID {
		return shared.ErrNotFound
	}
	ind.Active = false
	return nil
}

// requestWithTenant builds a request whose context carries the tenant
// ID the auth middleware would normally set.
func requestWithTenant(method, path, body string, tenantID shared.ID) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, bytes.NewBufferString(body))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	ctx := context.WithValue(r.Context(), middleware.TenantIDKey, tenantID.String())
	return r.WithContext(ctx)
}

func newTestIOCHandler(t *testing.T) (*IOCHandler, *mockIOCRepo) {
	t.Helper()
	repo := newMockIOCRepo()
	return NewIOCHandler(repo, logger.NewNop()), repo
}

// -----------------------------------------------------------------------------

func TestIOCHandler_Create_ValidPayload_Returns201(t *testing.T) {
	h, repo := newTestIOCHandler(t)
	tenantID := shared.NewID()

	body := `{"type":"ip","value":"203.0.113.10","source":"manual","confidence":80}`
	w := httptest.NewRecorder()
	h.Create(w, requestWithTenant("POST", "/iocs", body, tenantID))

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201. body=%s", w.Code, w.Body.String())
	}
	if len(repo.inds) != 1 {
		t.Fatalf("want 1 indicator persisted, got %d", len(repo.inds))
	}
	var resp iocResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.Type != "ip" {
		t.Fatalf("type = %q", resp.Type)
	}
	if resp.Normalized != "203.0.113.10" {
		t.Fatalf("normalized = %q", resp.Normalized)
	}
	if resp.Confidence != 80 {
		t.Fatalf("confidence = %d", resp.Confidence)
	}
}

func TestIOCHandler_Create_InvalidType_Returns400(t *testing.T) {
	h, repo := newTestIOCHandler(t)
	tenantID := shared.NewID()

	body := `{"type":"not_a_real_type","value":"foo"}`
	w := httptest.NewRecorder()
	h.Create(w, requestWithTenant("POST", "/iocs", body, tenantID))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid ioc type") {
		t.Fatalf("error body should mention invalid type: %s", w.Body.String())
	}
	if len(repo.inds) != 0 {
		t.Fatal("nothing should be persisted on invalid type")
	}
}

func TestIOCHandler_Create_EmptyValue_Returns400(t *testing.T) {
	h, _ := newTestIOCHandler(t)
	body := `{"type":"ip","value":""}`
	w := httptest.NewRecorder()
	h.Create(w, requestWithTenant("POST", "/iocs", body, shared.NewID()))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestIOCHandler_Create_ConfidenceOutOfRange_Returns400(t *testing.T) {
	h, _ := newTestIOCHandler(t)
	body := `{"type":"ip","value":"1.2.3.4","confidence":150}`
	w := httptest.NewRecorder()
	h.Create(w, requestWithTenant("POST", "/iocs", body, shared.NewID()))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for confidence=150", w.Code)
	}
}

func TestIOCHandler_Create_NoTenantContext_Returns401(t *testing.T) {
	h, _ := newTestIOCHandler(t)

	// No tenant in context — this is what happens when auth middleware
	// didn't run (misconfigured route).
	body := `{"type":"ip","value":"1.2.3.4"}`
	r := httptest.NewRequest("POST", "/iocs", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.Create(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without tenant context", w.Code)
	}
}

func TestIOCHandler_Create_MalformedJSON_Returns400(t *testing.T) {
	h, _ := newTestIOCHandler(t)
	w := httptest.NewRecorder()
	h.Create(w, requestWithTenant("POST", "/iocs", `{not json`, shared.NewID()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestIOCHandler_Get_Found_Returns200(t *testing.T) {
	h, repo := newTestIOCHandler(t)
	tenantID := shared.NewID()

	// Seed one indicator.
	ind, err := ioc.NewIndicator(tenantID, ioc.TypeDomain, "evil.example.com", ioc.SourceManual)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := repo.Create(context.Background(), ind); err != nil {
		t.Fatal(err)
	}

	r := requestWithTenant("GET", "/iocs/"+ind.ID.String(), "", tenantID)
	// Chi URLParam reads the routing context — install a fresh
	// routeContext so chi.URLParam returns the id from the path.
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", ind.ID.String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.Get(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200. body=%s", w.Code, w.Body.String())
	}
	var resp iocResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.ID != ind.ID.String() {
		t.Fatalf("id mismatch")
	}
}

func TestIOCHandler_Get_NotFound_Returns404(t *testing.T) {
	h, _ := newTestIOCHandler(t)
	missing := shared.NewID()

	r := requestWithTenant("GET", "/iocs/"+missing.String(), "", shared.NewID())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", missing.String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.Get(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestIOCHandler_Get_InvalidID_Returns400(t *testing.T) {
	h, _ := newTestIOCHandler(t)
	r := requestWithTenant("GET", "/iocs/not-a-uuid", "", shared.NewID())
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.Get(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestIOCHandler_List_ReturnsPagedShape(t *testing.T) {
	h, repo := newTestIOCHandler(t)
	tenantID := shared.NewID()

	// Seed 3.
	for _, v := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		ind, err := ioc.NewIndicator(tenantID, ioc.TypeIP, v, ioc.SourceManual)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.Create(context.Background(), ind); err != nil {
			t.Fatal(err)
		}
	}

	w := httptest.NewRecorder()
	h.List(w, requestWithTenant("GET", "/iocs?limit=10&offset=0", "", tenantID))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp struct {
		Items  []iocResponse `json:"items"`
		Limit  int           `json:"limit"`
		Offset int           `json:"offset"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 3 {
		t.Fatalf("items count = %d, want 3", len(resp.Items))
	}
	if resp.Limit != 10 || resp.Offset != 0 {
		t.Fatalf("pagination echoed wrong: %+v", resp)
	}
}

func TestIOCHandler_Delete_Deactivates(t *testing.T) {
	h, repo := newTestIOCHandler(t)
	tenantID := shared.NewID()

	ind, err := ioc.NewIndicator(tenantID, ioc.TypeIP, "9.9.9.9", ioc.SourceManual)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(context.Background(), ind); err != nil {
		t.Fatal(err)
	}

	r := requestWithTenant("DELETE", "/iocs/"+ind.ID.String(), "", tenantID)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", ind.ID.String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.Delete(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204. body=%s", w.Code, w.Body.String())
	}

	// Repo state: indicator soft-deleted (active=false), still present.
	got, err := repo.GetByID(context.Background(), tenantID, ind.ID)
	if err != nil {
		t.Fatalf("should still be able to read after soft-delete: %v", err)
	}
	if got.Active {
		t.Fatal("Active must be false after DELETE (soft delete contract)")
	}
}

func TestIOCHandler_Delete_CrossTenantIsolated(t *testing.T) {
	h, repo := newTestIOCHandler(t)
	tenantA := shared.NewID()
	tenantB := shared.NewID()

	// A creates an indicator.
	ind, err := ioc.NewIndicator(tenantA, ioc.TypeIP, "8.8.8.8", ioc.SourceManual)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(context.Background(), ind); err != nil {
		t.Fatal(err)
	}

	// B tries to delete A's indicator — must 404, not silently succeed.
	r := requestWithTenant("DELETE", "/iocs/"+ind.ID.String(), "", tenantB)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", ind.ID.String())
	r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.Delete(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 for cross-tenant delete", w.Code)
	}
	// A's indicator must still be active — B couldn't affect it.
	got, err := repo.GetByID(context.Background(), tenantA, ind.ID)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			t.Fatal("A's indicator vanished from B's 404 — cross-tenant bleed")
		}
		t.Fatal(err)
	}
	if !got.Active {
		t.Fatal("A's indicator should still be active; B's 404 must not have mutated it")
	}
}
