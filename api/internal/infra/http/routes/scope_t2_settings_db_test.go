package routes

import (
	"encoding/json"
	"net/http"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func settingsOf(t *testing.T, body string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// The t2 maximum duration through the real routes (RFC-054 §12.4): only an
// owner changes it, with a reason; the general settings update keeps it;
// the scope entry routes enforce it; another organization is not affected.
func TestScopeT2Settings_Routes_DB(t *testing.T) {
	h := newChangeAuditHarness(t, func(s *scopeapp.Service, sh *handler.ScopeHandler, db *postgres.DB) {
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), logger.NewNop(),
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), logger.NewNop())))
		sh.SetSettingsStore(ts)
		s.SetEntryPolicy(ts, postgres.NewMemberLifecycleRepository(db), nil)
	})
	org := h.tenant()
	owner, admin := h.member(org, "owner"), h.member(org, "admin")
	other := h.tenant()
	otherOwner := h.member(other, "owner")

	st := settingsOf(t, h.expect(admin, http.MethodGet, "/api/v1/scope/settings", "", http.StatusOK))
	if st["t2_max_duration"] != "30d" || st["t2_max_days"] != float64(30) || st["t2_permanent_allowed"] != false {
		t.Fatalf("default t2 settings: %v", st)
	}
	h.expect(admin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"perm.t2.example.com","max_tier":"t2","reason":"pentest"}`, http.StatusBadRequest)
	h.expect(admin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"long.t2.example.com","max_tier":"t2","expires_in_days":31,"reason":"pentest"}`, http.StatusBadRequest)

	body := `{"t2_max_duration":"permanent","reason":"standing pentest contract"}`
	h.expect(admin, http.MethodPut, "/api/v1/scope/settings/intrusive", body, http.StatusForbidden)
	h.expect(owner, http.MethodPut, "/api/v1/scope/settings/intrusive", `{"t2_max_duration":"permanent"}`, http.StatusUnprocessableEntity)
	h.expect(owner, http.MethodPut, "/api/v1/scope/settings/intrusive", `{"t2_max_duration":"forever","reason":"x"}`, http.StatusUnprocessableEntity)
	st = settingsOf(t, h.expect(owner, http.MethodPut, "/api/v1/scope/settings/intrusive", body, http.StatusOK))
	if st["t2_max_duration"] != "permanent" || st["t2_permanent_allowed"] != true {
		t.Fatalf("after the owner's change: %v", st)
	}
	// An administrator's general settings change keeps the owner's choice.
	h.expect(admin, http.MethodPut, "/api/v1/scope/settings", `{"one_off_max_days":10}`, http.StatusOK)
	st = settingsOf(t, h.expect(admin, http.MethodGet, "/api/v1/scope/settings", "", http.StatusOK))
	if st["t2_max_duration"] != "permanent" || st["one_off_max_days"] != float64(10) {
		t.Fatalf("after the general update: %v", st)
	}
	// A permanent t2 entry is allowed now, and still waits for an approval.
	e := settingsOf(t, h.expect(admin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"perm.t2.example.com","max_tier":"t2","reason":"pentest"}`, http.StatusCreated))
	if e["status"] != "pending" || e["approvals_required"] != float64(1) || e["expires_at"] != nil {
		t.Fatalf("permanent t2 entry: %v", e)
	}
	// Another organization keeps its own default.
	st = settingsOf(t, h.expect(otherOwner, http.MethodGet, "/api/v1/scope/settings", "", http.StatusOK))
	if st["t2_max_duration"] != "30d" {
		t.Fatalf("another organization's setting changed: %v", st)
	}
	rows := h.auditRows(org, "scope.settings_updated")
	if len(rows) == 0 || rows[0].actor != owner.id || rows[0].severity != "high" {
		t.Fatalf("audit rows %+v, want the owner's high-severity change first", rows)
	}
}
