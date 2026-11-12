package routes

// Settings > AI > Use cases through the real router and table
// (docs/architecture/ai-use-cases.md): the authorization matrix (read with
// settings:read; write only an owner or administrator with settings:write),
// the recent sign-in on a loosening, the audit rows (critical for a
// loosening), and tenant isolation (the tenant comes from the token).

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/tenantai"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/crypto"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// useCaseStepUp answers a stale or fresh sign-in on demand.
type useCaseStepUp struct {
	mu    sync.Mutex
	stale bool
}

func (g *useCaseStepUp) RequireRecentAuth(context.Context, string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.stale {
		return middleware.ErrStepUpRequired
	}
	return nil
}

func (g *useCaseStepUp) set(stale bool) {
	g.mu.Lock()
	g.stale = stale
	g.mu.Unlock()
}

func newUseCaseRouteHarness(t *testing.T) (*authzPolicyHarness, *useCaseStepUp) {
	t.Helper()
	gate := &useCaseStepUp{}
	changeAuditExtraHandlers = func(hs *Handlers, db *postgres.DB) {
		log := logger.NewNop()
		svc := tenantai.NewService(postgres.NewTenantAISettingsRepository(db), crypto.NewNoOpEncryptor(),
			auditapp.NewAuditService(postgres.NewAuditRepository(db), log), nil, nil, log)
		svc.SetStepUpGate(gate)
		hs.AISettings = handler.NewAISettingsHandler(svc, validator.New(), log)
	}
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	return newChangeAuditHarness(t), gate
}

func TestAIUseCasesRoutes_AuthzStepUpAuditIsolation_DB(t *testing.T) {
	h, gate := newUseCaseRouteHarness(t)
	org, other := h.tenant(), h.tenant()
	for _, id := range []string{org, other} {
		id := id
		h.t.Cleanup(func() {
			_, _ = h.db.ExecContext(context.Background(), `DELETE FROM tenant_ai_settings WHERE tenant_id = $1`, id)
		})
	}
	admin := h.member(org, "admin")
	reader := h.member(org, "member")
	h.grantCustomRole(&reader, org, "settings:read")
	writer := h.member(org, "member") // settings:write, but not an administrator
	h.grantCustomRole(&writer, org, "settings:read", "settings:write")
	otherAdmin := h.member(other, "admin")

	const list = "/api/v1/organization/settings/ai/use-cases"
	const triage = list + "/triage"
	autoOn := `{"mode":"auto_apply","ceiling":"internal","min_confidence":0.9}`

	// Read: anyone with settings:read; defaults until saved.
	body := h.expect(reader, http.MethodGet, list, "", http.StatusOK)
	var got struct {
		Items []struct {
			UseCase       string  `json:"use_case"`
			Mode          string  `json:"mode"`
			EffectiveMode string  `json:"effective_mode"`
			Ceiling       string  `json:"ceiling"`
			MinConfidence float64 `json:"min_confidence"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 3 || got.Items[0].UseCase != "triage" || got.Items[0].Mode != "suggest" ||
		got.Items[0].EffectiveMode != "off" || got.Items[0].Ceiling != "internal" || got.Items[0].MinConfidence != 0.85 {
		t.Fatalf("defaults (AI off, so in force off): %s", body)
	}

	// Write: only an owner or administrator with settings:write.
	h.expect(reader, http.MethodPut, triage, autoOn, http.StatusForbidden)
	h.expect(writer, http.MethodPut, triage, autoOn, http.StatusForbidden)

	// Validation.
	h.expect(admin, http.MethodPut, list+"/chat", autoOn, http.StatusBadRequest)
	h.expect(admin, http.MethodPut, triage, `{"mode":"auto_apply","ceiling":"tenant_only","min_confidence":0.9}`, http.StatusBadRequest)
	h.expect(admin, http.MethodPut, triage, `{"mode":"auto_apply","ceiling":"internal","min_confidence":0.2}`, http.StatusBadRequest)

	// A loosening on a stale sign-in: the re-authentication answer, nothing stored.
	gate.set(true)
	resp := h.expect(admin, http.MethodPut, triage, autoOn, http.StatusForbidden)
	if !strings.Contains(resp, string(middleware.CodeStepUpRequired)) {
		t.Fatalf("stale sign-in: %s", resp)
	}
	resp = h.expect(admin, http.MethodPut, list+"/summary", `{"mode":"suggest","ceiling":"restricted","min_confidence":0.85}`, http.StatusForbidden)
	if !strings.Contains(resp, string(middleware.CodeStepUpRequired)) {
		t.Fatalf("ceiling above internal on a stale sign-in: %s", resp)
	}
	if n := useCaseCount(h, `SELECT count(*) FROM tenant_ai_settings WHERE tenant_id = $1 AND use_cases <> '{}'::jsonb`, org); n != 0 {
		t.Fatal("a refused loosening was stored")
	}
	// Tightening needs no recent sign-in.
	h.expect(admin, http.MethodPut, list+"/summary", `{"mode":"off","ceiling":"public","min_confidence":0.85}`, http.StatusOK)

	// Fresh sign-in: stored, critical audit.
	gate.set(false)
	resp = h.expect(admin, http.MethodPut, triage, autoOn, http.StatusOK)
	if !strings.Contains(resp, `"loosened":["auto_apply_on"]`) || !strings.Contains(resp, `"mode":"auto_apply"`) {
		t.Fatalf("auto-apply on: %s", resp)
	}

	rows := h.auditRows(org, "ai_use_case.")
	if len(rows) != 2 {
		t.Fatalf("audit rows: %+v", rows)
	}
	if rows[0].severity != "medium" || rows[1].severity != "critical" || rows[1].actor != admin.id {
		t.Fatalf("audit severities: %+v", rows)
	}
	if rows[1].before["mode"] != "suggest" || rows[1].after["mode"] != "auto_apply" {
		t.Fatalf("audit changes: %+v", rows[1])
	}

	// Another organization sees its own defaults, and its administrator
	// cannot reach this organization's settings (the tenant is the token's).
	body = h.expect(otherAdmin, http.MethodGet, list, "", http.StatusOK)
	if strings.Contains(body, "auto_apply") {
		t.Fatalf("another organization sees this one's settings: %s", body)
	}
	if n := useCaseCount(h, `SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action LIKE 'ai_use_case.%'`, other); n != 0 {
		t.Fatal("audit rows written to another organization")
	}
}

func useCaseCount(h *authzPolicyHarness, q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}
