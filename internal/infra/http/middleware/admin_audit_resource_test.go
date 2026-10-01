package middleware_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// A create route has no id in its URL, so the audit row used to carry no
// resource_id. The handler can now name what it created, and a 201 whose
// body has a top-level "id" is used when it does not.

func runAudit(t *testing.T, build func(*middleware.AuditMiddleware) func(http.Handler) http.Handler, route, target string, h http.HandlerFunc) *admin.AuditLog {
	t.Helper()
	repo := newFakeAuditRepo()
	am := middleware.NewAuditMiddleware(repo, logger.NewNop())
	r := chi.NewRouter()
	r.With(build(am)).Post(route, h)
	req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(httptest.NewRecorder(), req)
	return waitForAudit(t, repo.created)
}

func TestAuditCreate_HandlerSetsCreatedResource(t *testing.T) {
	created := shared.NewID()
	log := runAudit(t, func(am *middleware.AuditMiddleware) func(http.Handler) http.Handler {
		return am.AuditTargetMappingCreate()
	}, "/m", "/m", func(w http.ResponseWriter, r *http.Request) {
		middleware.SetAuditResource(r.Context(), created, "url -> website")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + shared.NewID().String() + `"}`)) // handler-set id wins
	})
	if log.ResourceID == nil || *log.ResourceID != created {
		t.Fatalf("resource_id: got %v, want %s", log.ResourceID, created)
	}
	if log.ResourceName != "url -> website" {
		t.Errorf("resource_name: got %q", log.ResourceName)
	}
	if log.ResourceType != admin.ResourceTypeTargetMapping {
		t.Errorf("resource_type: got %q", log.ResourceType)
	}
}

func TestAuditCreate_FallsBackToResponseID(t *testing.T) {
	created := shared.NewID()
	log := runAudit(t, func(am *middleware.AuditMiddleware) func(http.Handler) http.Handler {
		return am.AuditLog("organization.create", "tenant", "tenantId")
	}, "/orgs", "/orgs", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": created.String(), "owner_setup": map[string]any{"setup_token": "secret"}})
	})
	if log.ResourceID == nil || *log.ResourceID != created {
		t.Fatalf("resource_id: got %v, want %s", log.ResourceID, created)
	}
}

func TestAuditCreate_FailedCreateRecordsNoID(t *testing.T) {
	log := runAudit(t, func(am *middleware.AuditMiddleware) func(http.Handler) http.Handler {
		return am.AuditTargetMappingCreate()
	}, "/m", "/m", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"id":"` + shared.NewID().String() + `"}`))
	})
	if log.ResourceID != nil {
		t.Fatalf("a refused create must not record a resource id, got %s", log.ResourceID)
	}
	if log.ResponseStatus != http.StatusConflict {
		t.Errorf("status: got %d", log.ResponseStatus)
	}
}

// The URL id stays authoritative: a sub-resource created under an
// organization keeps the organization as the audited resource.
func TestAuditCreate_URLParamWins(t *testing.T) {
	org := shared.NewID()
	log := runAudit(t, func(am *middleware.AuditMiddleware) func(http.Handler) http.Handler {
		return am.AuditLog("organization.idp_create", "tenant", "tenantId")
	}, "/orgs/{tenantId}/idps", "/orgs/"+org.String()+"/idps", func(w http.ResponseWriter, r *http.Request) {
		middleware.SetAuditResource(r.Context(), shared.NewID(), "idp")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + shared.NewID().String() + `"}`))
	})
	if log.ResourceID == nil || *log.ResourceID != org {
		t.Fatalf("resource_id: got %v, want the URL organization %s", log.ResourceID, org)
	}
}

// Setting the resource outside an audited request is a no-op, not a panic.
func TestSetAuditResource_NoAuditContext(t *testing.T) {
	middleware.SetAuditResource(context.Background(), shared.NewID(), "x")
}
