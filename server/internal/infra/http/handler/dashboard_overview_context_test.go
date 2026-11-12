package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A part authenticates from the forwarded credentials alone: the identity
// that this request's middleware stored in its context never reaches it.
func TestDashboardOverview_PartsDoNotInheritTheRequestContext(t *testing.T) {
	var leaked atomic.Int32
	router := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if middleware.GetUserID(r.Context()) != "" {
			leaked.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	h := NewDashboardOverviewHandler(func() http.Handler { return router }, logger.NewNop())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/overview", nil)
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserIDKey, "user-from-outer-chain"))
	h.Overview(httptest.NewRecorder(), req)
	if n := leaked.Load(); n != 0 {
		t.Fatalf("%d parts saw the outer request identity", n)
	}
}
