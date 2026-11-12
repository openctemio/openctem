package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A request without the "rule" key must not clear a group's rule: removing it
// is said with null.
func TestSetRule_RequiresTheRuleKey(t *testing.T) {
	h := &AssetGroupHandler{}
	for _, body := range []string{`{}`, `{"other":1}`, ``} {
		rc := chi.NewRouteContext()
		rc.URLParams.Add("id", shared.NewID().String())
		req := httptest.NewRequest(http.MethodPut, "/api/v1/asset-groups/x/rule", strings.NewReader(body))
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
		rec := httptest.NewRecorder()
		h.SetRule(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status %d, want 400", body, rec.Code)
		}
	}
}
