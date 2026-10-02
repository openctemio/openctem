package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

func TestDataScopeTarget(t *testing.T) {
	id := shared.NewID()
	s := id.String()
	cases := []struct {
		path string
		kind dataScopeKind
		ok   bool
	}{
		{"/api/v1/assets/" + s, dataScopeAsset, true},
		{"/api/v1/assets/" + s + "/full", dataScopeAsset, true},
		{"/api/v1/assets/" + s + "/owners/x", dataScopeAsset, true},
		{"/api/v1/findings/" + s + "/comments/" + shared.NewID().String(), dataScopeFinding, true},
		{"/api/v1/compliance/findings/" + s + "/controls", dataScopeFinding, true},
		{"/api/v1/verification-checklists/" + s, dataScopeFinding, true},
		{"//api/v1//assets/./" + s + "/", dataScopeAsset, true}, // cleaned like the router does
		{"/api/v1/assets/stats", 0, false},
		{"/api/v1/assets/bulk/status", 0, false},
		{"/api/v1/findings/actions/verify", 0, false},
		{"/api/v1/asset-groups/" + s, 0, false},
		{"/api/v1/assetsX/" + s, 0, false},
	}
	for _, tc := range cases {
		kind, got, ok := dataScopeTarget(tc.path)
		if ok != tc.ok || kind != tc.kind || (ok && got != id) {
			t.Errorf("dataScopeTarget(%q) = (%v, %v, %v), want (%v, %v, true)", tc.path, kind, got, ok, tc.kind, id)
		}
	}
}

type fakeAsserter struct{ deny map[shared.ID]bool }

func (f fakeAsserter) AssertAsset(_ context.Context, _, id shared.ID) error {
	if f.deny[id] {
		return shared.ErrNotFound
	}
	return nil
}

func (f fakeAsserter) AssertFinding(ctx context.Context, t, id shared.ID) error {
	return f.AssertAsset(ctx, t, id)
}

func TestDataScopeGuard(t *testing.T) {
	hidden, visible := shared.NewID(), shared.NewID()
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	h := DataScopeGuard(fakeAsserter{deny: map[shared.ID]bool{hidden: true}})(next)

	run := func(path string) int {
		req := httptest.NewRequest(http.MethodPatch, path, nil)
		req = req.WithContext(context.WithValue(req.Context(), TenantIDKey, shared.NewID().String()))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := run("/api/v1/findings/" + hidden.String() + "/status"); got != http.StatusNotFound {
		t.Errorf("out-of-scope finding = %d, want 404", got)
	}
	if got := run("/api/v1/assets/" + hidden.String()); got != http.StatusNotFound {
		t.Errorf("out-of-scope asset = %d, want 404", got)
	}
	if got := run("/api/v1/findings/" + visible.String() + "/status"); got != http.StatusTeapot {
		t.Errorf("in-scope finding = %d, want pass-through", got)
	}
	if got := run("/api/v1/findings/stats"); got != http.StatusTeapot {
		t.Errorf("non-id route = %d, want pass-through", got)
	}
}
