package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/internal/config"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The finding view answers each part by sending it through the API's own
// router with the caller's credentials. These tests use a fake router that
// records what reaches it and answers like gated endpoints.

const fvID = "019f5e75-08c4-7e03-8759-9d714faa29c3"

type fvRouter struct {
	mu     sync.Mutex
	seen   map[string]http.Header
	answer func(w http.ResponseWriter, r *http.Request) bool
}

func (f *fvRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	if f.seen == nil {
		f.seen = map[string]http.Header{}
	}
	f.seen[r.URL.RequestURI()] = r.Header.Clone()
	f.mu.Unlock()
	if f.answer != nil && f.answer(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"uri":"` + r.URL.RequestURI() + `"}`))
}

func fvRequest(id string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+id+"/view?path=/api/v1/admin/x", nil)
	req.SetPathValue("id", id)
	req.Header.Set("Cookie", "auth_token=abc")
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	ctx := context.WithValue(req.Context(), middleware.TenantIDKey, "t1")
	ctx = context.WithValue(ctx, middleware.UserIDKey, "u1")
	return req.WithContext(ctx)
}

func fvServe(t *testing.T, router http.Handler, id string) (*httptest.ResponseRecorder, ViewResponse) {
	t.Helper()
	h := NewFindingViewHandler(func() http.Handler { return router }, nil)
	rec := httptest.NewRecorder()
	h.View(rec, fvRequest(id))
	var resp ViewResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
	}
	return rec, resp
}

// Only the fixed parts of the parsed id are dispatched, with the caller's
// credentials and nothing else; the request's query chooses nothing.
func TestFindingView_DispatchesTheFixedPartsOfTheParsedID(t *testing.T) {
	router := &fvRouter{}
	// An upper-case id is parsed and dispatched in its canonical form.
	rec, resp := fvServe(t, router, strings.ToUpper(fvID))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "private, no-store" {
		t.Fatalf("Cache-Control %q", got)
	}
	want := append([]string{FindingViewGate(fvID)}, FindingViewParts(fvID)...)
	if len(router.seen) != len(want) || len(resp.Parts) != len(want) {
		t.Fatalf("dispatched %d, answered %d, want %d", len(router.seen), len(resp.Parts), len(want))
	}
	for _, part := range want {
		hdr, ok := router.seen[part]
		if !ok {
			t.Fatalf("part %s not dispatched", part)
		}
		if hdr.Get("Cookie") != "auth_token=abc" || hdr.Get("Authorization") != "Bearer tok" {
			t.Errorf("%s: credentials not forwarded", part)
		}
		if hdr.Get("X-Forwarded-For") != "" {
			t.Errorf("%s: forwarded a client header it should not", part)
		}
		p := resp.Parts[part]
		var got struct {
			URI string `json:"uri"`
		}
		if p.Status != http.StatusOK || json.Unmarshal(p.Body, &got) != nil || got.URI != part {
			t.Errorf("%s: an allowed part must carry its own body: status %d body %s", part, p.Status, p.Body)
		}
	}
	for uri := range router.seen {
		if strings.Contains(uri, "admin") {
			t.Fatalf("dispatched a path from the request: %s", uri)
		}
	}
}

// Text that is not a finding id never reaches the router.
func TestFindingView_RejectsAnythingButAnID(t *testing.T) {
	for _, id := range []string{"", "../../admin/tenants", "x", fvID + "/../../admin"} {
		router := &fvRouter{}
		rec, _ := fvServe(t, router, id)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q: status %d, want 400", id, rec.Code)
		}
		if len(router.seen) != 0 {
			t.Errorf("%q: dispatched %v", id, router.seen)
		}
	}
}

// A finding the caller may not open (another tenant's, out of data scope, or
// missing) costs one read: the view holds only the finding's own answer.
func TestFindingView_RefusedFindingHoldsOnlyItsOwnAnswer(t *testing.T) {
	router := &fvRouter{answer: func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"code":"NOT_FOUND","message":"Finding not found"}`))
		return true
	}}
	rec, resp := fvServe(t, router, fvID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if len(router.seen) != 1 || len(resp.Parts) != 1 {
		t.Fatalf("dispatched %d parts, answered %d, want only the finding", len(router.seen), len(resp.Parts))
	}
	if p := resp.Parts[FindingViewGate(fvID)]; p.Status != http.StatusNotFound || !strings.Contains(string(p.Body), "NOT_FOUND") {
		t.Fatalf("finding part %+v", p)
	}
}

// A panel the caller may not read (a permission it lacks, a module that is
// off) is that part's own refusal, with its error code: the view still
// answers 200 and every other part. A server failure carries no body.
func TestFindingView_RefusedPanelIsAbsentNotAFailure(t *testing.T) {
	approvals := "/api/v1/findings/" + fvID + "/approvals"
	triage := "/api/v1/findings/" + fvID + "/ai-triage"
	broken := "/api/v1/findings/" + fvID + "/identity"
	router := &fvRouter{answer: func(w http.ResponseWriter, r *http.Request) bool {
		switch r.URL.RequestURI() {
		case approvals:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":"FORBIDDEN","message":"Missing permission"}`))
		case triage:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":"MODULE_NOT_ENABLED","message":"Module is not enabled"}`))
		case broken:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"code":"INTERNAL","detail":"stack"}`))
		default:
			return false
		}
		return true
	}}
	rec, resp := fvServe(t, router, fvID)
	if rec.Code != http.StatusOK {
		t.Fatalf("one refused panel failed the view: %d", rec.Code)
	}
	if p := resp.Parts[approvals]; p.Status != http.StatusForbidden || !strings.Contains(string(p.Body), `"FORBIDDEN"`) {
		t.Errorf("approvals %+v", p)
	}
	if p := resp.Parts[triage]; p.Status != http.StatusForbidden || !strings.Contains(string(p.Body), "MODULE_NOT_ENABLED") {
		t.Errorf("ai-triage %+v", p)
	}
	if p := resp.Parts[broken]; p.Status != http.StatusInternalServerError || len(p.Body) != 0 {
		t.Errorf("a failed part must carry its status and no body: %+v", p)
	}
	if p := resp.Parts[FindingViewGate(fvID)]; p.Status != http.StatusOK {
		t.Errorf("finding %+v", p)
	}
}

// Finding data changes with every action on the page: a view is computed per
// request, never served from an earlier one.
func TestFindingView_IsNotCached(t *testing.T) {
	var n int
	var mu sync.Mutex
	router := &fvRouter{answer: func(_ http.ResponseWriter, _ *http.Request) bool {
		mu.Lock()
		n++
		mu.Unlock()
		return false
	}}
	h := NewFindingViewHandler(func() http.Handler { return router }, nil)
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		h.View(rec, fvRequest(fvID))
	}
	if want := 2 * (len(FindingViewParts(fvID)) + 1); n != want {
		t.Fatalf("dispatched %d, want %d", n, want)
	}
}

// A part whose handler panics fails alone (500); the view and the process
// survive.
func TestFindingView_PanickingPartFailsAlone(t *testing.T) {
	evidence := "/api/v1/findings/" + fvID + "/evidence"
	router := &fvRouter{answer: func(_ http.ResponseWriter, r *http.Request) bool {
		if r.URL.RequestURI() == evidence {
			panic("handler bug")
		}
		return false
	}}
	rec, resp := fvServe(t, router, fvID)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if p := resp.Parts[evidence]; p.Status != http.StatusInternalServerError || len(p.Body) != 0 {
		t.Fatalf("panicking part %+v", p)
	}
	if p := resp.Parts[FindingViewGate(fvID)]; p.Status != http.StatusOK {
		t.Fatalf("finding %+v", p)
	}
}

// One finding view costs findingViewReadCost tokens of the caller's per-user
// read budget, whatever its parts: the parts run through the same read
// limiter (as in production) and take nothing, and a view the budget cannot
// cover is refused before any part runs.
func TestFindingView_ChargesItsFixedReadCostOnly(t *testing.T) {
	limiter := middleware.NewReadEndpointRateLimiter(
		middleware.ReadEndpointRateLimitConfigFrom(config.RateLimitConfig{ReadRequestsPerMin: findingViewReadCost}),
		logger.NewNop())
	defer limiter.Stop()
	asUser := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), middleware.UserIDKey, "u1")))
		})
	}
	parts := &fvRouter{}
	// The parts' router authenticates the same user and applies the same
	// read limiter, as the API's router does.
	router := asUser(limiter.Middleware()(parts))
	h := NewFindingViewHandler(func() http.Handler { return router }, nil)
	view := asUser(limiter.Middleware()(http.HandlerFunc(h.View)))

	rec := httptest.NewRecorder()
	view.ServeHTTP(rec, fvRequest(fvID))
	if rec.Code != http.StatusOK {
		t.Fatalf("first view: %d", rec.Code)
	}
	var resp ViewResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	for url, p := range resp.Parts {
		if p.Status != http.StatusOK {
			t.Errorf("part %s took a read token of its own: %d", url, p.Status)
		}
	}
	seen := len(parts.seen)

	rec = httptest.NewRecorder()
	view.ServeHTTP(rec, fvRequest(fvID))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second view within the budget of one: %d, want 429", rec.Code)
	}
	if len(parts.seen) != seen {
		t.Fatalf("a refused view dispatched parts")
	}
}

// Only a request the view dispatched skips the read limiter: the same URL
// from a client takes a token.
func TestViewPartMark_IsServerOnly(t *testing.T) {
	limiter := middleware.NewReadEndpointRateLimiter(
		middleware.ReadEndpointRateLimitConfigFrom(config.RateLimitConfig{ReadRequestsPerMin: 1}), logger.NewNop())
	defer limiter.Stop()
	h := limiter.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	get := func(ctx context.Context, hdr string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+fvID+"/comments", nil).WithContext(ctx)
		req.Header.Set("X-View-Part", hdr) // a client header means nothing
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	ctx := context.WithValue(context.Background(), middleware.UserIDKey, "u1")
	if get(ctx, "1") != http.StatusOK || get(ctx, "1") != http.StatusTooManyRequests {
		t.Fatal("client requests must take tokens")
	}
	for i := 0; i < 5; i++ {
		if code := get(middleware.WithViewPart(ctx), ""); code != http.StatusOK {
			t.Fatalf("view part %d refused: %d", i, code)
		}
	}
}
