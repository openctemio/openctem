package routes

// Turning the hold on shared provider addresses off lifts every hold of the
// organization at once, so PUT /api/v1/scope/settings asks for the critical
// re-authentication on that change (the same as Keep scanning), on top of the
// route's own step-up. A refusal changes nothing; the change that goes through
// is audited at high severity (the administrators' notice is sent by the handler).

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"testing"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	scopeapp "github.com/openctemio/openctem/server/internal/app/scope"
	tenantapp "github.com/openctemio/openctem/server/internal/app/tenant"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/logger"
)

func TestScopeSettings_TurningHoldOffNeedsCriticalStepUp_DB(t *testing.T) {
	fresh := false // a stale session
	h := newChangeAuditHarness(t, func(s *scopeapp.Service, sh *handler.ScopeHandler, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		ts.SetStepUpGate(middleware.RecentAuthGate{Checker: switchableStepUp{fresh: &fresh}})
		sh.SetSettingsStore(ts)
		s.SetEntryPolicy(ts, postgres.NewMemberLifecycleRepository(db), nil)
	})
	org := h.tenant()
	owner := h.member(org, "owner")
	const url = "/api/v1/scope/settings"
	stored := func() string {
		t.Helper()
		var v sql.NullString
		if err := h.db.QueryRowContext(context.Background(), `SELECT settings->'scope'->>'hold_provider_entries' FROM tenants WHERE id = $1`, org).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v.String
	}
	// A stale session: the route's own step-up passes in this harness, the
	// critical re-login does not.
	out := h.expect(owner, http.MethodPut, url, `{"hold_provider_entries":false}`, http.StatusForbidden)
	var e struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal([]byte(out), &e)
	if e.Code != "STEP_UP_REQUIRED" {
		t.Fatalf("hold off with a stale session: %s", out)
	}
	if got := stored(); got != "" {
		t.Fatalf("a refused change wrote hold_provider_entries = %q", got)
	}
	if rows := h.auditRows(org, "scope.settings_updated"); len(rows) != 0 {
		t.Fatalf("a refused change was audited: %+v", rows)
	}
	// Other changes, and keeping the hold on, need nothing more.
	h.expect(owner, http.MethodPut, url, `{"one_off_max_days":5}`, http.StatusOK)
	h.expect(owner, http.MethodPut, url, `{"hold_provider_entries":true}`, http.StatusOK)

	// A fresh critical re-login lets it through, audited and announced.
	fresh = true
	before := len(h.auditRows(org, "scope.settings_updated"))
	h.expect(owner, http.MethodPut, url, `{"hold_provider_entries":false}`, http.StatusOK)
	if got := stored(); got != "false" {
		t.Fatalf("hold_provider_entries = %q, want false", got)
	}
	rows := h.auditRows(org, "scope.settings_updated")
	if len(rows) != before+1 || rows[len(rows)-1].severity != "high" {
		t.Fatalf("audit after lifting the hold: %+v", rows)
	}
	var meta sql.NullString
	if err := h.db.QueryRowContext(context.Background(), `SELECT metadata->>'provider_hold_lifted' FROM audit_logs WHERE tenant_id = $1 AND action LIKE 'scope.settings%' ORDER BY logged_at DESC, id DESC LIMIT 1`, org).Scan(&meta); err != nil || meta.String != "true" {
		t.Fatalf("provider_hold_lifted metadata = %q, %v", meta.String, err)
	}

	// Already off: staying off with a stale session again needs nothing.
	fresh = false
	h.expect(owner, http.MethodPut, url, `{"hold_provider_entries":false,"one_off_max_days":6}`, http.StatusOK)
}
