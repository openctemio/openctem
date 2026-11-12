package routes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/internal/app/adminapproval"
	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/app/consolesetting"
	"github.com/openctemio/openctem/api/internal/app/scopenames"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

const scopeNamesPath = "/api/v1/admin/settings/scope-blocked-names"

// scopeNamesHarness serves the blocked names routes over a migrated database
// with their own policy (not the platform's global one).
func scopeNamesHarness(t *testing.T, managed bool) (*chainHarness, *scopedom.NamePolicy) {
	t.Helper()
	policy := scopedom.NewNamePolicy()
	h := newChainHarness(t, func(hs *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		log := logger.NewNop()
		rec := consolesetting.NewRecorder(postgres.NewAuditLogRepository(db), nil, "OpenCTEM", nil)
		tenants := postgres.NewTenantRepository(db)
		namer := adminapproval.TenantNamerFunc(func(ctx context.Context, id shared.ID) (string, error) {
			tn, err := tenants.GetByID(ctx, id)
			if err != nil {
				return "", err
			}
			return tn.Name(), nil
		})
		ps := handler.NewAdminPlatformSettingsHandler(postgres.NewAdminRepository(db), log)
		approvals := adminapproval.NewService(postgres.NewAdminApprovalRepository(db), postgres.NewAdminRepository(db),
			postgres.NewAuditLogRepository(db), log)
		ps.WithApprovals(approvals)
		ps.ScopeNames = scopenames.NewService(postgres.NewPlatformSettingRepository(db),
			postgres.NewScopeNameExceptionRepository(db), namer, rec, policy, []string{"env.example"}, managed, log)
		hs.AdminPlatformSettings = ps
	})
	clear := func() {
		h.exec(`DELETE FROM platform_settings WHERE key = $1`, scopenames.SettingKey)
		h.exec(`DELETE FROM scope_name_exceptions`)
	}
	clear()
	t.Cleanup(clear)
	return h, policy
}

func decodeJSON[T any](t *testing.T, body string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return v
}

// Only a platform owner, with a fresh code and a reason, grants, extends and
// revokes an exception; the guardrails honor it for that organization and
// name only, at once; every change is a critical audit row; a tenant token
// never reaches the routes.
func TestAdminScopeNames_Exceptions_DB(t *testing.T) {
	h, policy := scopeNamesHarness(t, false)
	orgA, orgB := h.organization(0), h.organization(0)
	idA, _ := shared.IDFromString(orgA)
	idB, _ := shared.IDFromString(orgB)
	g := scopedom.DefaultGuardrails().WithNamePolicy(policy)
	expires := time.Now().UTC().AddDate(0, 0, 30).Format(time.DateOnly)
	grant := map[string]any{"organization_id": orgA, "name": "sub.example.gov.vn", "reason": "bug bounty program",
		"authorization_ref": "letter 2026-11 ref 42", "expires_at": expires}

	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	if code, body := reader.do(http.MethodGet, scopeNamesPath, nil, false); code != http.StatusOK ||
		!jsonHasBool(body, "government_rule", true) || !strings.Contains(body, "env.example") {
		t.Fatalf("read: %d %s (rule on by default, environment names shown)", code, body)
	}
	reader.autoStepUp = true
	if code, _ := reader.do(http.MethodPost, scopeNamesPath+"/exceptions", grant, true); code != http.StatusForbidden {
		t.Fatalf("a read-only administrator granted an exception: %d", code)
	}

	// A tenant owner's token is not a console session.
	tok := h.tenantToken(orgA, "owner")
	if code := h.raw(http.MethodPost, scopeNamesPath+"/exceptions", map[string]string{"Authorization": "Bearer " + tok}); code != http.StatusUnauthorized && code != http.StatusForbidden {
		t.Fatalf("tenant token reached the console route: %d", code)
	}

	owner := h.newAdmin(admin.AdminRoleSuperAdmin)
	owner.verify()
	owner.closeStepUpWindow()
	if code, _ := owner.do(http.MethodPost, scopeNamesPath+"/exceptions", grant, true); code != http.StatusUnauthorized {
		t.Fatalf("without the step-up: %d", code)
	}
	owner.autoStepUp = true
	bad := []struct {
		name string
		edit func(m map[string]any)
		code string
	}{
		{"no reason", func(m map[string]any) { delete(m, "reason") }, ""},
		{"no reference", func(m map[string]any) { delete(m, "authorization_ref") }, "AUTHORIZATION_REF_REQUIRED"},
		{"past expiry", func(m map[string]any) { m["expires_at"] = "2020-01-01" }, "EXCEPTION_EXPIRY"},
		{"beyond the longest", func(m map[string]any) {
			m["expires_at"] = time.Now().UTC().AddDate(2, 0, 0).Format(time.DateOnly)
		}, "EXCEPTION_EXPIRY"},
		{"the government suffix", func(m map[string]any) { m["name"] = "gov.vn" }, "EXCEPTION_TOO_WIDE"},
		{"not a government name", func(m map[string]any) { m["name"] = "example.com" }, "EXCEPTION_NOT_GOVERNMENT"},
		{"a wildcard", func(m map[string]any) { m["name"] = "*.example.gov.vn" }, "EXCEPTION_NAME_INVALID"},
		{"unknown organization", func(m map[string]any) { m["organization_id"] = shared.NewID().String() }, "ORGANIZATION_NOT_FOUND"},
	}
	for _, b := range bad {
		m := map[string]any{}
		for k, v := range grant {
			m[k] = v
		}
		b.edit(m)
		code, body := owner.do(http.MethodPost, scopeNamesPath+"/exceptions", m, true)
		if code != http.StatusBadRequest || !strings.Contains(body, b.code) {
			t.Errorf("%s: %d %s, want 400 %s", b.name, code, body, b.code)
		}
	}
	if err := g.For(idA).CheckPattern(scopedom.TargetTypeDomain, "sub.example.gov.vn"); !errors.Is(err, scopedom.ErrGovernmentName) {
		t.Fatalf("before the grant: %v", err)
	}

	code, body := owner.do(http.MethodPost, scopeNamesPath+"/exceptions", grant, true)
	if code != http.StatusCreated {
		t.Fatalf("grant: %d %s", code, body)
	}
	ex := decodeJSON[handler.ScopeNameExceptionResponse](t, body)
	if ex.State != scopenames.StateActive || ex.GrantedBy != owner.a.Email() || ex.OrganizationName == "" {
		t.Fatalf("granted: %+v", ex)
	}
	if code, _ := owner.do(http.MethodPost, scopeNamesPath+"/exceptions", grant, true); code != http.StatusConflict {
		t.Fatalf("a second live exception for the same name: %d", code)
	}

	// The guardrails apply it at once, for A and that exact name only.
	if err := g.For(idA).CheckPattern(scopedom.TargetTypeDomain, "sub.example.gov.vn"); err != nil {
		t.Fatalf("organization A after the grant: %v", err)
	}
	if g.For(idA).Denies("https://sub.example.gov.vn/login") {
		t.Fatal("dispatch refused the excepted name")
	}
	for _, c := range []struct {
		g    scopedom.Guardrails
		name string
	}{
		{g.For(idB), "sub.example.gov.vn"},
		{g, "sub.example.gov.vn"},
		{g.For(idA), "example.gov.vn"},
		{g.For(idA), "other.example.gov.vn"},
		{g.For(idA), "*.sub.example.gov.vn"},
	} {
		if err := c.g.CheckPattern(scopedom.TargetTypeDomain, c.name); !errors.Is(err, scopedom.ErrGovernmentName) {
			t.Errorf("%s must stay blocked: %v", c.name, err)
		}
	}

	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1
		AND action = $2 AND severity = 'critical' AND request_body->>'organization_id' = $3
		AND request_body->>'name' = 'sub.example.gov.vn' AND request_body->>'reason' = 'bug bounty program'
		AND request_body->>'authorization_ref' = 'letter 2026-11 ref 42' AND request_body ? 'expires_at_after'`,
		owner.a.ID().String(), scopenames.ActionExceptionGranted, orgA).Scan(&n); err != nil || n != 1 {
		t.Fatalf("grant audit rows %d %v, want 1", n, err)
	}

	// Readers see it in the list.
	code, body = reader.do(http.MethodGet, scopeNamesPath+"/exceptions", nil, false)
	if list := decodeJSON[handler.ScopeNameExceptionListResponse](t, body); code != http.StatusOK || len(list.Items) != 1 {
		t.Fatalf("list: %d %s", code, body)
	}

	// Extend, then revoke: blocked again at once; a revoked one stays revoked.
	newExp := time.Now().UTC().AddDate(0, 0, 60).Format(time.DateOnly)
	if code, body := owner.do(http.MethodPost, scopeNamesPath+"/exceptions/"+ex.ID+"/extend",
		map[string]any{"expires_at": newExp, "reason": "program renewed"}, true); code != http.StatusOK || !strings.Contains(body, newExp) {
		t.Fatalf("extend: %d %s", code, body)
	}
	if code, body := owner.do(http.MethodPost, scopeNamesPath+"/exceptions/"+ex.ID+"/revoke",
		map[string]any{"reason": "program ended"}, true); code != http.StatusOK || !strings.Contains(body, `"state":"revoked"`) {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if !g.For(idA).Denies("sub.example.gov.vn") {
		t.Fatal("a revoked exception still lets dispatch through")
	}
	if code, _ := owner.do(http.MethodPost, scopeNamesPath+"/exceptions/"+ex.ID+"/revoke",
		map[string]any{"reason": "again"}, true); code != http.StatusConflict {
		t.Fatalf("revoke twice: %d", code)
	}
	if code, _ := owner.do(http.MethodPost, scopeNamesPath+"/exceptions/"+ex.ID+"/extend",
		map[string]any{"expires_at": newExp, "reason": "x"}, true); code != http.StatusConflict {
		t.Fatalf("extend a revoked one: %d", code)
	}
	if code, _ := owner.do(http.MethodPost, scopeNamesPath+"/exceptions/"+shared.NewID().String()+"/revoke",
		map[string]any{"reason": "x"}, true); code != http.StatusNotFound {
		t.Fatalf("unknown exception: %d", code)
	}
}

// Turning the rule off is the owner's, audited with the values before and
// after; the operator's names are added to the guardrails at once.
func TestAdminScopeNames_Policy_DB(t *testing.T) {
	h, policy := scopeNamesHarness(t, false)
	g := scopedom.DefaultGuardrails().WithNamePolicy(policy)
	owner := h.newAdmin(admin.AdminRoleSuperAdmin)
	owner.verify()
	owner.autoStepUp = true
	if code, _ := owner.do(http.MethodPut, scopeNamesPath, map[string]any{"government_rule": false, "version": 0}, true); code != http.StatusBadRequest {
		t.Fatalf("no reason: %d", code)
	}
	if code, _ := owner.do(http.MethodPut, scopeNamesPath, map[string]any{"government_rule": true, "names": []string{"not a name"},
		"reason": "x", "version": 0}, true); code != http.StatusBadRequest {
		t.Fatalf("bad name: %d", code)
	}
	code, body := owner.do(http.MethodPut, scopeNamesPath, map[string]any{"government_rule": false,
		"names": []string{"*.Internal.Example.com"}, "max_exception_days": 90, "reason": "government installation", "version": 0}, true)
	if code != http.StatusOK || !jsonHasBool(body, "government_rule", false) || !strings.Contains(body, `"internal.example.com"`) {
		t.Fatalf("save: %d %s", code, body)
	}
	if err := g.CheckPattern(scopedom.TargetTypeDomain, "portal.agency.gov"); err != nil {
		t.Fatalf("rule off: %v", err)
	}
	if err := g.CheckPattern(scopedom.TargetTypeDomain, "a.internal.example.com"); !errors.Is(err, scopedom.ErrDenyList) {
		t.Fatalf("operator name: %v", err)
	}
	if err := g.CheckPattern(scopedom.TargetTypeIPAddress, "169.254.169.254"); !errors.Is(err, scopedom.ErrDenyList) {
		t.Fatalf("metadata address must stay refused: %v", err)
	}
	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM admin_audit_logs WHERE admin_id = $1
		AND action = $2 AND severity = 'critical' AND request_body->>'government_rule_before' = 'on'
		AND request_body->>'government_rule_after' = 'off' AND request_body->>'reason' = 'government installation'`,
		owner.a.ID().String(), scopenames.ActionPolicyChanged).Scan(&n); err != nil || n != 1 {
		t.Fatalf("policy audit rows %d %v, want 1", n, err)
	}
	// A stale form is refused.
	if code, _ := owner.do(http.MethodPut, scopeNamesPath, map[string]any{"government_rule": true, "reason": "x", "version": 0}, true); code != http.StatusConflict {
		t.Fatalf("stale version: %d", code)
	}
}

// On a hosted service a grant and turning the rule off wait for a second
// owner.
func TestAdminScopeNames_SecondApproval_DB(t *testing.T) {
	h, policy := scopeNamesHarness(t, true)
	org := h.organization(0)
	owner := h.newAdmin(admin.AdminRoleSuperAdmin)
	owner.verify()
	owner.autoStepUp = true
	second := h.newAdmin(admin.AdminRoleSuperAdmin)
	second.verify()
	grant := map[string]any{"organization_id": org, "name": "portal.example.gov.vn", "reason": "own installation",
		"authorization_ref": "contract 7", "expires_at": time.Now().UTC().AddDate(0, 0, 10).Format(time.DateOnly)}
	code, body := owner.do(http.MethodPost, scopeNamesPath+"/exceptions", grant, true)
	if code != http.StatusPreconditionRequired || !strings.Contains(body, string(handler.CodeSecondApprovalRequired)) {
		t.Fatalf("grant without approval: %d %s", code, body)
	}
	code, body = owner.do(http.MethodPut, scopeNamesPath, map[string]any{"government_rule": false, "reason": "x", "version": 0}, true)
	if code != http.StatusPreconditionRequired {
		t.Fatalf("rule off without approval: %d %s", code, body)
	}
	if !policy.Snapshot().GovernmentRuleOff && len(policy.Snapshot().Exceptions) == 0 {
		return // nothing applied
	}
	t.Fatal("a refused change reached the guardrails")
}

// A platform admin who is not an owner changes nothing.
func TestAdminScopeNames_NotOwner_DB(t *testing.T) {
	h, _ := scopeNamesHarness(t, false)
	org := h.organization(0)
	ops := h.newAdmin(admin.AdminRoleOpsAdmin)
	ops.verify()
	ops.autoStepUp = true
	grant := map[string]any{"organization_id": org, "name": "sub.example.gov.vn", "reason": "x",
		"authorization_ref": "y", "expires_at": time.Now().UTC().AddDate(0, 0, 3).Format(time.DateOnly)}
	if code, _ := ops.do(http.MethodPost, scopeNamesPath+"/exceptions", grant, true); code != http.StatusForbidden {
		t.Fatalf("a platform admin who is not an owner granted an exception: %d", code)
	}
	if code, _ := ops.do(http.MethodPut, scopeNamesPath, map[string]any{"government_rule": false, "reason": "x"}, true); code != http.StatusForbidden {
		t.Fatalf("a platform admin who is not an owner turned the rule off: %d", code)
	}
}
