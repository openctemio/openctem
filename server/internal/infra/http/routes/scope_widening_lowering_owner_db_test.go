package routes

// Lowering the widening approvals (PUT /api/v1/scope/settings) is for the
// organization's owner; an administrator with scope:approve may raise them or
// leave them alone. A refusal writes nothing.

import (
	"database/sql"
	"net/http"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func TestScopeSettings_LoweringWideningApprovalsIsOwnerOnly_DB(t *testing.T) {
	h := newChangeAuditHarness(t, func(s *scopeapp.Service, sh *handler.ScopeHandler, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		sh.SetSettingsStore(ts)
		s.SetEntryPolicy(ts, postgres.NewMemberLifecycleRepository(db), nil)
	})
	org := h.tenant()
	owner, admin := h.member(org, "owner"), h.member(org, "admin")
	const url = "/api/v1/scope/settings"
	stored := func() string {
		t.Helper()
		var v sql.NullString
		if err := h.db.QueryRow(`SELECT settings->'scope'->>'widening_approvals' FROM tenants WHERE id = $1`, org).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v.String
	}

	h.expect(owner, http.MethodPut, url, `{"widening_approvals":2}`, http.StatusOK)
	// An administrator may not lower it, nor reset it to the default (lower).
	h.expect(admin, http.MethodPut, url, `{"widening_approvals":1}`, http.StatusForbidden)
	h.expect(admin, http.MethodPut, url, `{"one_off_max_days":5}`, http.StatusForbidden)
	if got := stored(); got != "2" {
		t.Fatalf("a refused change wrote widening_approvals = %q", got)
	}
	// Keeping it, or another change that names the same value, is allowed.
	h.expect(admin, http.MethodPut, url, `{"widening_approvals":2,"one_off_max_days":5}`, http.StatusOK)
	// The owner lowers; the administrator raises it again.
	h.expect(owner, http.MethodPut, url, `{"widening_approvals":1}`, http.StatusOK)
	h.expect(admin, http.MethodPut, url, `{"widening_approvals":2}`, http.StatusOK)
	if got := stored(); got != "2" {
		t.Fatalf("raising by an administrator: %q", got)
	}
}
