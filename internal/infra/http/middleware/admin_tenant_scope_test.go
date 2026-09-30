package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

func TestAdminTenantScope(t *testing.T) {
	known := shared.NewID()
	exists := func(_ context.Context, id shared.ID) error {
		if id == known {
			return nil
		}
		return fmt.Errorf("%w: organization", shared.ErrNotFound)
	}
	var gotTenant, gotUser string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenant, gotUser = GetTenantID(r.Context()), GetUserID(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	mux := http.NewServeMux()
	mux.Handle("GET /admin/tenants/{tenantId}/x", AdminTenantScope(exists)(next))

	call := func(id string) int {
		req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+id+"/x", nil)
		// The admin auth middleware put the admin id under the user id key.
		req = req.WithContext(context.WithValue(req.Context(), UserIDKey, "admin-id"))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := call(known.String()); code != http.StatusNoContent {
		t.Fatalf("known org: %d", code)
	}
	if gotTenant != known.String() {
		t.Fatalf("tenant in context %q, want %q", gotTenant, known.String())
	}
	// The admin id must not leak into handlers that write users(id) FKs.
	if gotUser != "" {
		t.Fatalf("user id in context %q, want empty", gotUser)
	}
	if code := call(shared.NewID().String()); code != http.StatusNotFound {
		t.Fatalf("unknown org: %d, want 404", code)
	}
	if code := call("not-a-uuid"); code != http.StatusBadRequest {
		t.Fatalf("bad id: %d, want 400", code)
	}
}
