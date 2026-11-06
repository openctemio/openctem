package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type staticReadOnly map[shared.ID]bool

func (s staticReadOnly) ReadOnly(_ context.Context, id shared.ID) bool { return s[id] }

func TestIdleReadOnly(t *testing.T) {
	locked, open := shared.NewID(), shared.NewID()
	mw := IdleReadOnly(staticReadOnly{locked: true})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := mw(next)

	serve := func(method, tenant string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1/assets", nil)
		if tenant != "" {
			r = r.WithContext(context.WithValue(r.Context(), TenantIDKey, tenant))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec
	}

	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rec := serve(m, locked.String())
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), CodeWorkspaceReadOnly) {
			t.Fatalf("%s on a read-only organization: %d %s", m, rec.Code, rec.Body)
		}
	}
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if rec := serve(m, locked.String()); rec.Code != http.StatusNoContent {
			t.Fatalf("%s must pass on a read-only organization: %d", m, rec.Code)
		}
	}
	if rec := serve(http.MethodPost, open.String()); rec.Code != http.StatusNoContent {
		t.Fatalf("an active organization must pass: %d", rec.Code)
	}
	if rec := serve(http.MethodPost, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("no tenant in the token must pass: %d", rec.Code)
	}
}
