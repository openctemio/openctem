package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openctemio/api/pkg/domain/agent"
	"github.com/openctemio/api/pkg/domain/shared"
)

// A platform agent (tenant_id NULL) must be rejected with 403 on tenant-scoped
// agent operations, not panic on agt.TenantID deref (recovered as a 500).
func TestRequireAgentTenant_RejectsNilTenant(t *testing.T) {
	rec := httptest.NewRecorder()
	agt := &agent.Agent{ID: shared.NewID()} // TenantID nil
	if requireAgentTenant(rec, agt) {
		t.Fatal("expected false for nil-tenant agent")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestRequireAgentTenant_AllowsTenantAgent(t *testing.T) {
	rec := httptest.NewRecorder()
	tid := shared.NewID()
	agt := &agent.Agent{ID: shared.NewID(), TenantID: &tid}
	if !requireAgentTenant(rec, agt) {
		t.Fatal("expected true for tenant-bound agent")
	}
	if rec.Code != http.StatusOK { // nothing written
		t.Fatalf("expected no error response, got %d", rec.Code)
	}
}

func TestAgentTenantString_NilSafe(t *testing.T) {
	if got := agentTenantString(nil); got != "" {
		t.Errorf("nil agent: expected empty, got %q", got)
	}
	if got := agentTenantString(&agent.Agent{}); got != "" {
		t.Errorf("nil tenant: expected empty, got %q", got)
	}
	tid := shared.NewID()
	if got := agentTenantString(&agent.Agent{TenantID: &tid}); got != tid.String() {
		t.Errorf("expected %q, got %q", tid.String(), got)
	}
}
