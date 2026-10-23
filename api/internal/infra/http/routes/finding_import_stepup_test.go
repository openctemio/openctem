package routes

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
)

// An upload that declares coverage=full closes findings in bulk, so it needs
// step-up like POST /findings/bulk/status closing findings; any other upload
// closes nothing and passes without it.
func TestRequireStepUpWhenFullCoverage(t *testing.T) {
	for _, c := range []struct {
		name   string
		query  string
		authAt time.Time
		want   int
	}{
		{"partial upload, stale session", "", time.Now().Add(-24 * time.Hour), http.StatusNoContent},
		{"coverage=partial, stale session", "?coverage=partial", time.Now().Add(-24 * time.Hour), http.StatusNoContent},
		{"coverage=full, stale session", "?coverage=full&asset_id=x", time.Now().Add(-24 * time.Hour), http.StatusForbidden},
		{"coverage=full twice, stale session", "?coverage=full&coverage=partial", time.Now().Add(-24 * time.Hour), http.StatusForbidden},
		{"coverage=full, fresh session", "?coverage=full&asset_id=x", time.Now(), http.StatusNoContent},
	} {
		t.Run(c.name, func(t *testing.T) {
			withStepUpChecker(t, steppedUpAt(c.authAt))
			h := requireStepUpWhenFullCoverage()(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			req := httptest.NewRequest(http.MethodPost, "/api/v1/findings/imports"+c.query, nil)
			ctx := context.WithValue(req.Context(), middleware.UserIDKey, "u1")
			ctx = context.WithValue(ctx, middleware.SessionIDKey, "s1")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req.WithContext(ctx))
			if rec.Code != c.want {
				t.Fatalf("%s: %d, want %d (%s)", c.query, rec.Code, c.want, rec.Body.String())
			}
		})
	}
}
