package routes

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/app/tenant"
	toolapp "github.com/openctemio/openctem/api/internal/app/tool"
	"github.com/openctemio/openctem/api/internal/config"
	infrahttp "github.com/openctemio/openctem/api/internal/infra/http"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/jwt"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// Changes to what sensors scan and run were not in the audit log at all:
// scope targets, scope exclusions, tools and their tenant config, scanner
// templates (RFC-040 gap B3). Each change is now one entry with the actor and
// the state before and after, written through the real routes.

// newChangeAuditHarness is the authorization-policy harness (real route
// registration, auth chain and role tables) with the scope, scanner template
// and tool handlers wired to the audit service as in cmd/server.
// changeAuditExtraHandlers adds handlers to the next harness (set and
// reset by a test; the route tests do not run in parallel).
var changeAuditExtraHandlers func(*Handlers, *postgres.DB)

func newChangeAuditHarness(t *testing.T, configure ...func(*scopeapp.Service, *handler.ScopeHandler, *postgres.DB)) *authzPolicyHarness {
	t.Helper()
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping change audit route test")
	}
	sqldb, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Skipf("open db: %v", err)
	}
	t.Cleanup(func() { _ = sqldb.Close() })
	if err := sqldb.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}

	// Register sets package-level chain parts; put them back afterwards.
	saved := []Middleware{csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware,
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware}
	savedKeyAuth := apiKeyOrJWT
	t.Cleanup(func() {
		apiKeyOrJWT = savedKeyAuth
		csrfProtectionMiddleware, readRateLimitMiddleware, activeMembershipFromJWTMiddleware = saved[0], saved[1], saved[2]
		permissionSyncMiddleware, ssoEnforcementMiddleware, ipAllowlistMiddleware = saved[3], saved[4], saved[5]
	})

	db := &postgres.DB{DB: sqldb}
	log := logger.NewNop()
	tenantRepo := postgres.NewTenantRepository(db)
	auditSvc := auditapp.NewAuditService(postgres.NewAuditRepository(db), log)
	v := validator.New()
	gen := jwt.NewGenerator(jwt.TokenConfig{Secret: "change-audit-route-test-secret-0123456789abcdef", Issuer: "test",
		AccessTokenDuration: time.Hour, RefreshTokenDuration: time.Hour})
	cfg := &config.Config{}
	cfg.Auth.Provider = config.AuthProviderLocal

	scopeSvc := scopeapp.NewService(postgres.NewScopeTargetRepository(db),
		postgres.NewScopeExclusionRepository(db),
		postgres.NewAssetRepository(db), log)
	scopeSvc.SetStepUpGate(middleware.RecentAuthGate{Checker: alwaysSteppedUp{}, Window: time.Hour})
	scopeSvc.SetEntryPolicy(nil, postgres.NewMemberLifecycleRepository(db), nil)
	scope := handler.NewScopeHandler(scopeSvc, v, log)
	scope.SetAuditService(auditSvc)
	for _, c := range configure {
		c(scopeSvc, scope, db)
	}
	templates := handler.NewScannerTemplateHandler(
		app.NewScannerTemplateService(postgres.NewScannerTemplateRepository(db), "change-audit-template-signing-key-0123456789", log), v, log)
	templates.SetAuditService(auditSvc)
	tools := handler.NewToolHandler(toolapp.NewService(postgres.NewToolRepository(db),
		postgres.NewTenantToolConfigRepository(db), log), v, log)
	tools.SetAuditService(auditSvc)

	router := infrahttp.NewChiRouter()
	hs := Handlers{Scope: scope, ScannerTemplate: templates, Tool: tools, StepUp: alwaysSteppedUp{}}
	if changeAuditExtraHandlers != nil {
		changeAuditExtraHandlers(&hs, db)
	}
	Register(router, hs, cfg, log,
		AuthConfig{Provider: config.AuthProviderLocal, LocalValidator: gen},
		tenantRepo, tenant.NewUserService(postgres.NewUserRepository(db), log), nil, nil, nil)
	srv := httptest.NewServer(router.(interface{ Handler() http.Handler }).Handler())
	t.Cleanup(srv.Close)
	return &authzPolicyHarness{t: t, db: sqldb, srv: srv, gen: gen, roles: postgres.NewRoleRepository(db)}
}

type auditRow struct {
	action, resourceID, actor, severity string
	before, after                       map[string]any
}

func (h *authzPolicyHarness) auditRows(tenantID, prefix string) []auditRow {
	h.t.Helper()
	rows, err := h.db.QueryContext(context.Background(), `SELECT action, resource_id, COALESCE(actor_id::text, ''), severity,
		COALESCE(changes, '{}'::jsonb) FROM audit_logs WHERE tenant_id = $1 AND action LIKE $2 || '%' ORDER BY logged_at, id`,
		tenantID, prefix)
	if err != nil {
		h.t.Fatal(err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var a auditRow
		var raw []byte
		if err := rows.Scan(&a.action, &a.resourceID, &a.actor, &a.severity, &raw); err != nil {
			h.t.Fatal(err)
		}
		var ch struct {
			Before map[string]any `json:"before"`
			After  map[string]any `json:"after"`
		}
		_ = json.Unmarshal(raw, &ch)
		a.before, a.after = ch.Before, ch.After
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		h.t.Fatal(err)
	}
	return out
}

// requireAudited checks the entries for one resource, in order: action,
// actor, and which of before/after are present.
func requireAudited(t *testing.T, got []auditRow, id string, want []auditRow) {
	t.Helper()
	var mine []auditRow
	for _, r := range got {
		if r.resourceID == id {
			mine = append(mine, r)
		}
	}
	if len(mine) != len(want) {
		t.Fatalf("resource %s: %d audit entries, want %d: %+v", id, len(mine), len(want), mine)
	}
	for i, w := range want {
		g := mine[i]
		if g.action != w.action || g.actor != w.actor {
			t.Fatalf("entry %d: %s by %s, want %s by %s", i, g.action, g.actor, w.action, w.actor)
		}
		if w.severity != "" && g.severity != w.severity {
			t.Fatalf("%s: severity %s, want %s", g.action, g.severity, w.severity)
		}
		if (g.before != nil) != (w.before != nil) || (g.after != nil) != (w.after != nil) {
			t.Fatalf("%s: before %v after %v, want before present=%v after present=%v",
				g.action, g.before, g.after, w.before != nil, w.after != nil)
		}
		for k, v := range w.before {
			if g.before[k] != v {
				t.Fatalf("%s: before[%s] = %v, want %v", g.action, k, g.before[k], v)
			}
		}
		for k, v := range w.after {
			if g.after[k] != v {
				t.Fatalf("%s: after[%s] = %v, want %v", g.action, k, g.after[k], v)
			}
		}
	}
}

func decodeID(t *testing.T, body string) string {
	t.Helper()
	var out struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil || out.ID == "" {
		t.Fatalf("no id in %s", body)
	}
	return out.ID
}

func TestScopeChangesAreAudited_DB(t *testing.T) {
	h := newChangeAuditHarness(t)
	tid := h.tenant()
	owner, admin, member := h.member(tid, "owner"), h.member(tid, "admin"), h.member(tid, "member")

	// Scope target (RFC-054): an admin's entry in a two-admin organization
	// waits for the other admin; a member's change that does not widen is
	// fine; activation widens again; a member only requests a one-off.
	target := decodeID(t, h.expect(admin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"*.audit.example.com","description":"before"}`, http.StatusCreated))
	base := "/api/v1/scope/targets/" + target
	h.expect(member, http.MethodPut, base, `{"description":"after"}`, http.StatusOK)
	h.expect(admin, http.MethodPost, base+"/approve", "", http.StatusForbidden)  // the requester
	h.expect(member, http.MethodPost, base+"/approve", "", http.StatusForbidden) // no scope:approve
	h.expect(owner, http.MethodPost, base+"/approve", "", http.StatusOK)
	h.expect(admin, http.MethodPost, base+"/deactivate", "", http.StatusOK)
	h.expect(member, http.MethodPost, base+"/activate", "", http.StatusForbidden)
	h.expect(admin, http.MethodPost, base+"/activate", "", http.StatusOK)
	h.expect(owner, http.MethodDelete, base, "", http.StatusNoContent)

	present := map[string]any{}
	requireAudited(t, h.auditRows(tid, "scope_target."), target, []auditRow{
		{action: "scope_target.created", actor: admin.id, severity: "high", after: map[string]any{"pattern": "*.audit.example.com", "status": "pending", "in_effect": false}},
		{action: "scope_target.updated", actor: member.id, before: map[string]any{"description": "before"}, after: map[string]any{"description": "after"}},
		{action: "scope_target.approved", actor: owner.id, severity: "high", before: map[string]any{"status": "pending"}, after: map[string]any{"status": "active", "in_effect": true}},
		{action: "scope_target.deactivated", actor: admin.id, before: map[string]any{"status": "active"}, after: map[string]any{"status": "inactive"}},
		{action: "scope_target.activated", actor: admin.id, severity: "high", before: map[string]any{"status": "inactive"}, after: map[string]any{"status": "pending"}},
		{action: "scope_target.deleted", actor: owner.id, before: map[string]any{"pattern": "*.audit.example.com"}},
	})

	// A member's request: a one-off for one name, with a reason; pending.
	h.expect(member, http.MethodPost, "/api/v1/scope/targets", `{"target_type":"domain","pattern":"*.req.example.com"}`, http.StatusBadRequest)
	req := decodeID(t, h.expect(member, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"promo.example.com","reason":"bought last week","expires_in_days":7}`, http.StatusCreated))
	requireAudited(t, h.auditRows(tid, "scope_target."), req, []auditRow{
		{action: "scope_target.created", actor: member.id, after: map[string]any{"status": "pending", "approvals_required": float64(1)}},
	})

	// Scope exclusion: create, update, approve, deactivate, activate, delete;
	// and a rejected one.
	excl := decodeID(t, h.expect(member, http.MethodPost, "/api/v1/scope/exclusions",
		`{"exclusion_type":"domain","pattern":"payroll.example.com","reason":"fragile"}`, http.StatusCreated))
	base = "/api/v1/scope/exclusions/" + excl
	h.expect(member, http.MethodPut, base, `{"reason":"very fragile"}`, http.StatusOK)
	h.expect(admin, http.MethodPost, base+"/approve", "", http.StatusOK)
	// Taking an approved exclusion out of effect needs the approval
	// permission (L-07): scope:write alone is refused and writes nothing.
	h.expect(member, http.MethodPost, base+"/deactivate", "", http.StatusForbidden)
	h.expect(owner, http.MethodPost, base+"/deactivate", "", http.StatusOK)
	h.expect(member, http.MethodPost, base+"/activate", "", http.StatusOK)
	h.expect(admin, http.MethodDelete, base, "", http.StatusNoContent)
	requireAudited(t, h.auditRows(tid, "scope_exclusion."), excl, []auditRow{
		{action: "scope_exclusion.created", actor: member.id, after: map[string]any{"pattern": "payroll.example.com", "status": "pending"}},
		{action: "scope_exclusion.updated", actor: member.id, before: map[string]any{"reason": "fragile"}, after: map[string]any{"reason": "very fragile"}},
		{action: "scope_exclusion.approved", actor: admin.id, before: map[string]any{"status": "pending"}, after: map[string]any{"status": "active", "in_effect": true}},
		{action: "scope_exclusion.deactivated", actor: owner.id, severity: "high", before: map[string]any{"in_effect": true}, after: map[string]any{"in_effect": false}},
		{action: "scope_exclusion.activated", actor: member.id, before: map[string]any{"in_effect": false}, after: map[string]any{"in_effect": true}},
		{action: "scope_exclusion.deleted", actor: admin.id, severity: "high", before: map[string]any{"pattern": "payroll.example.com"}},
	})
	rej := decodeID(t, h.expect(member, http.MethodPost, "/api/v1/scope/exclusions",
		`{"exclusion_type":"domain","pattern":"hr.example.com","reason":"fragile"}`, http.StatusCreated))
	h.expect(owner, http.MethodPost, "/api/v1/scope/exclusions/"+rej+"/reject", "", http.StatusOK)
	requireAudited(t, h.auditRows(tid, "scope_exclusion."), rej, []auditRow{
		{action: "scope_exclusion.created", actor: member.id, after: present},
		{action: "scope_exclusion.rejected", actor: owner.id, before: map[string]any{"status": "pending"}, after: map[string]any{"status": "rejected"}},
	})

	// Bulk delete audits each deleted exclusion and target.
	bulkExcl := decodeID(t, h.expect(member, http.MethodPost, "/api/v1/scope/exclusions",
		`{"exclusion_type":"domain","pattern":"bulk.example.com","reason":"fragile"}`, http.StatusCreated))
	bulkTarget := decodeID(t, h.expect(admin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"*.bulk.example.com"}`, http.StatusCreated))
	h.expect(admin, http.MethodPost, "/api/v1/scope/exclusions/bulk/delete", `{"exclusion_ids":["`+bulkExcl+`"]}`, http.StatusOK)
	h.expect(admin, http.MethodPost, "/api/v1/scope/targets/bulk/delete", `{"target_ids":["`+bulkTarget+`"]}`, http.StatusOK)
	requireAudited(t, h.auditRows(tid, "scope_exclusion."), bulkExcl, []auditRow{
		{action: "scope_exclusion.created", actor: member.id, after: present},
		{action: "scope_exclusion.deleted", actor: admin.id, before: map[string]any{"pattern": "bulk.example.com"}},
	})
	requireAudited(t, h.auditRows(tid, "scope_target."), bulkTarget, []auditRow{
		{action: "scope_target.created", actor: admin.id, after: present},
		{action: "scope_target.deleted", actor: admin.id, before: map[string]any{"pattern": "*.bulk.example.com"}},
	})

	// A refused change writes nothing.
	n := len(h.auditRows(tid, "scope_"))
	h.expect(member, http.MethodPost, "/api/v1/scope/exclusions/"+rej+"/approve", "", http.StatusForbidden)
	h.expect(admin, http.MethodPost, "/api/v1/scope/exclusions/"+rej+"/approve", "", http.StatusConflict)
	if got := len(h.auditRows(tid, "scope_")); got != n {
		t.Fatalf("refused changes wrote %d audit entries", got-n)
	}
}

func TestScannerTemplateAndToolChangesAreAudited_DB(t *testing.T) {
	h := newChangeAuditHarness(t)
	tid := h.tenant()
	admin, member := h.member(tid, "admin"), h.member(tid, "member")

	nuclei := func(name string) string {
		return base64.StdEncoding.EncodeToString([]byte(`id: ` + name + `
info:
  name: ` + name + `
  author: test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: status
        status:
          - 200
`))
	}
	tmpl := decodeID(t, h.expect(admin, http.MethodPost, "/api/v1/scanner-templates",
		`{"name":"audit-template","template_type":"nuclei","content":"`+nuclei("audit-template")+`"}`, http.StatusCreated))
	base := "/api/v1/scanner-templates/" + tmpl
	h.expect(admin, http.MethodPut, base, `{"description":"changed","content":"`+nuclei("audit-template-v2")+`"}`, http.StatusOK)
	h.expect(admin, http.MethodPost, base+"/deprecate", "", http.StatusOK)
	h.expect(admin, http.MethodDelete, base, "", http.StatusNoContent)
	rows := h.auditRows(tid, "scanner_template.")
	requireAudited(t, rows, tmpl, []auditRow{
		{action: "scanner_template.created", actor: admin.id, severity: "high", after: map[string]any{"name": "audit-template"}},
		{action: "scanner_template.updated", actor: admin.id, severity: "high", before: map[string]any{"name": "audit-template"}, after: map[string]any{"description": "changed"}},
		{action: "scanner_template.deprecated", actor: admin.id, before: map[string]any{"status": "active"}, after: map[string]any{"status": "deprecated"}},
		{action: "scanner_template.deleted", actor: admin.id, before: map[string]any{"name": "audit-template"}},
	})
	if rows[1].before["content_hash"] == rows[1].after["content_hash"] {
		t.Fatal("template update: the audit entry does not show the content change")
	}
	if _, has := rows[0].after["content"]; has {
		t.Fatal("template content copied into the audit log")
	}

	// A custom tool and the tenant's settings of it.
	tool := decodeID(t, h.expect(admin, http.MethodPost, "/api/v1/tools",
		`{"name":"audit-tool","display_name":"Audit tool","install_method":"binary","capabilities":["scan"]}`, http.StatusCreated))
	h.expect(admin, http.MethodPut, "/api/v1/tools/"+tool, `{"display_name":"Audit tool 2"}`, http.StatusOK)
	// A secret in a config is refused, before anything is stored or audited.
	h.expect(admin, http.MethodPatch, "/api/v1/tools/"+tool+"/settings",
		`{"is_enabled":true,"config":{"rate_limit":10,"api_key":"fake-key-Zq8vT3mP0wX7rL2kN9sB4yH6"}}`, http.StatusBadRequest)
	h.expect(admin, http.MethodPatch, "/api/v1/tools/"+tool+"/settings", `{"is_enabled":true,"config":{"rate_limit":10}}`, http.StatusOK)
	h.expect(member, http.MethodPatch, "/api/v1/tools/"+tool+"/settings", `{"is_enabled":false}`, http.StatusOK)
	h.expect(admin, http.MethodPatch, "/api/v1/tools/"+tool+"/settings", `{"config":{}}`, http.StatusOK)
	h.expect(member, http.MethodPatch, "/api/v1/tools/settings", `{"tool_ids":["`+tool+`"],"is_enabled":true}`, http.StatusNoContent)
	h.expect(admin, http.MethodDelete, "/api/v1/tools/"+tool, "", http.StatusNoContent)
	rows = h.auditRows(tid, "tool.")
	requireAudited(t, rows, "bulk", []auditRow{
		{action: "tool.config_updated", actor: member.id, after: map[string]any{"is_enabled": true}},
	})
	requireAudited(t, rows, tool, []auditRow{
		{action: "tool.created", actor: admin.id, after: map[string]any{"name": "audit-tool"}},
		{action: "tool.updated", actor: admin.id, before: map[string]any{"display_name": "Audit tool"}, after: map[string]any{"display_name": "Audit tool 2"}},
		{action: "tool.config_updated", actor: admin.id, after: map[string]any{"is_enabled": true}},
		{action: "tool.config_updated", actor: member.id, before: map[string]any{"is_enabled": true}, after: map[string]any{"is_enabled": false}},
		{action: "tool.config_updated", actor: admin.id, before: map[string]any{"is_enabled": false}, after: map[string]any{"is_enabled": false}},
		{action: "tool.deleted", actor: admin.id, before: map[string]any{"name": "audit-tool"}},
	})
	var raw string
	_ = h.db.QueryRow(`SELECT changes::text FROM audit_logs WHERE tenant_id = $1 AND action = 'tool.config_updated' ORDER BY logged_at LIMIT 1`, tid).Scan(&raw)
	if strings.Contains(raw, "Zq8vT3mP0wX7") || !strings.Contains(raw, `"rate_limit": 10`) {
		t.Fatalf("tool config audit entry must hold the config and never the refused secret: %s", raw)
	}
}

// An approved exclusion was put into effect by two people; taking that
// protection away (deactivate, delete, an expiry moved earlier or into the
// past) needs the same: the approval permission, and not the requester.
// scope:write alone (a member default) used to be enough. Research doc 15,
// L-07.
func TestScopeExclusion_ReducingProtectionNeedsSecondApprover_DB(t *testing.T) {
	h := newChangeAuditHarness(t)
	tid := h.tenant()
	owner, admin, member := h.member(tid, "owner"), h.member(tid, "admin"), h.member(tid, "member")
	week := time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	day := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)

	// Requested by the admin, approved by the owner.
	excl := decodeID(t, h.expect(admin, http.MethodPost, "/api/v1/scope/exclusions",
		`{"exclusion_type":"domain","pattern":"payments.reduce.example.com","reason":"prod","expires_at":"`+week+`"}`, http.StatusCreated))
	base := "/api/v1/scope/exclusions/" + excl
	h.expect(owner, http.MethodPost, base+"/approve", "", http.StatusOK)
	n := len(h.auditRows(tid, "scope_exclusion."))

	for _, c := range []struct{ method, path, body string }{
		{http.MethodPost, base + "/deactivate", ""},
		{http.MethodPut, base, `{"expires_at":"` + past + `"}`},
		{http.MethodPut, base, `{"expires_at":"` + day + `"}`},
		{http.MethodDelete, base, ""},
		{http.MethodPost, "/api/v1/scope/exclusions/bulk/delete", `{"exclusion_ids":["` + excl + `"]}`},
	} {
		// A member with scope:write (and scope:delete for the delete routes
		// it does not hold anyway) is refused...
		if c.method != http.MethodDelete && c.path != "/api/v1/scope/exclusions/bulk/delete" {
			h.expect(member, c.method, c.path, c.body, http.StatusForbidden)
		}
		// ...and so is the requester, although an admin.
		if c.path == "/api/v1/scope/exclusions/bulk/delete" {
			body := h.expect(admin, c.method, c.path, c.body, http.StatusOK)
			if !strings.Contains(body, excl) || !strings.Contains(body, `"affected_count":0`) {
				t.Errorf("bulk delete by the requester: %s, want the exclusion refused", body)
			}
			continue
		}
		h.expect(admin, c.method, c.path, c.body, http.StatusForbidden)
	}
	if got := len(h.auditRows(tid, "scope_exclusion.")); got != n {
		t.Fatalf("refused reductions wrote %d audit entries", got-n)
	}
	var status string
	var expires time.Time
	if err := h.db.QueryRow(`SELECT status, expires_at FROM scope_exclusions WHERE id = $1`, excl).Scan(&status, &expires); err != nil {
		t.Fatal(err)
	}
	if status != "active" || expires.Format(time.RFC3339) != week {
		t.Fatalf("after refused reductions: status %s expires %s, want active until %s", status, expires.Format(time.RFC3339), week)
	}

	// Editing the reason stays on scope:write.
	h.expect(member, http.MethodPut, base, `{"reason":"still prod"}`, http.StatusOK)
	// A second approver may shorten and then deactivate it; both audited.
	h.expect(owner, http.MethodPut, base, `{"expires_at":"`+day+`"}`, http.StatusOK)
	h.expect(owner, http.MethodPost, base+"/deactivate", "", http.StatusOK)
	rows := h.auditRows(tid, "scope_exclusion.")
	if len(rows) < 3 || rows[len(rows)-1].action != "scope_exclusion.deactivated" || rows[len(rows)-1].actor != owner.id {
		t.Fatalf("the second approver's changes were not audited: %+v", rows)
	}
	// Out of effect, it can be deleted with ordinary rights.
	h.expect(admin, http.MethodDelete, base, "", http.StatusNoContent)
}
