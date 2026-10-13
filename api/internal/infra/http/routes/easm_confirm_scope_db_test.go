package routes

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A person's Confirm on the attack surface adds the asset's exact scope
// entry (research/117) through the real routes:
//   - Off (the default): a domain and an address get active exact entries
//     with origin confirmed_asset, each audited as a scope entry creation; a
//     service gets none (it follows its host); a name an entry already
//     covers gets none;
//   - a caller with assets:write but without scope:write confirms
//     ownership only;
//   - another organization's asset id is not found and adds nothing;
//   - the organization's setting off, or Strict, adds nothing.
func TestEASMConfirmAddsScopeEntry_DB(t *testing.T) {
	var scopeSvc *scopeapp.Service
	changeAuditExtraHandlers = func(hs *Handlers, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log)
		attr := postgres.NewAttributionRepository(db)
		assets := postgres.NewAssetRepository(db)
		gate := easmapp.NewActiveGate(attr, assets, scopeSvc, postgres.NewVerifiedDomainNameRepository(db))
		review := easmapp.NewReviewService(attr, nil)
		review.SetCoverage(gate)
		review.SetConfirmScope(easmapp.NewConfirmScope(scopeSvc, ts, assets, gate))
		hs.EASM = handler.NewEASMHandler(easmapp.NewService(postgres.NewEASMSummaryRepository(db), nil), log).
			SetReview(review, auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
	}
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	h := newChangeAuditHarness(t, func(s *scopeapp.Service, sh *handler.ScopeHandler, db *postgres.DB) {
		scopeSvc = s
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		sh.SetSettingsStore(ts)
		s.SetEntryPolicy(ts, postgres.NewMemberLifecycleRepository(db), nil)
		pol := scanpolicy.NewService(postgres.NewScanPolicyRepository(db), nil, nil, nil, nil, log)
		pol.SetSettings(ts)
		s.SetGovernance(pol)
	})
	org, other := h.tenant(), h.tenant()
	owner := h.member(org, "owner")
	admin := h.member(org, "admin")
	ownersOnly := h.member(org, "viewer")
	h.customRoleMember(ownersOnly, org, permission.AssetsRead, permission.AssetsWrite)
	h.mintToken(&ownersOnly, org)
	h.member(other, "owner")

	asset := func(tenant, name, typ string) string {
		var id string
		if err := h.db.QueryRow(`INSERT INTO assets (tenant_id, name, asset_type, status) VALUES ($1, $2, $3, 'active') RETURNING id`,
			tenant, name, typ).Scan(&id); err != nil {
			t.Fatal(err)
		}
		h.exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence) VALUES ($1, $2, 'needs_review', 60)`, id, tenant)
		return id
	}
	decide := func(u policyUser, ids ...string) easmapp.DecisionResult {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"asset_ids": ids, "state": "confirmed"})
		var out easmapp.DecisionResult
		if err := json.Unmarshal([]byte(h.expect(u, http.MethodPost, "/api/v1/easm/candidates/decisions", string(b), http.StatusOK)), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	entries := func(tenant, pattern string) (n int, origin string) {
		t.Helper()
		_ = h.db.QueryRow(`SELECT count(*), COALESCE(max(origin), '') FROM scope_targets WHERE tenant_id = $1 AND pattern = $2`,
			tenant, pattern).Scan(&n, &origin)
		return n, origin
	}

	h.expect(admin, http.MethodPost, "/api/v1/scope/targets", `{"target_type":"domain","pattern":"*.cov.confirm-db.example"}`, http.StatusCreated)
	name := asset(org, "app.confirm-db.example", "subdomain")
	addr := asset(org, "203.0.113.71", "ip_address")
	svc := asset(org, "203.0.113.71:443", "service")
	covered := asset(org, "a.cov.confirm-db.example", "subdomain")
	foreign := asset(other, "x.confirm-db.example", "subdomain")

	out := decide(admin, name, addr, svc, covered, foreign)
	if out.Scope == nil || out.Scope.Skipped != "" {
		t.Fatalf("scope result %+v", out.Scope)
	}
	got := map[string]easmapp.ConfirmedEntry{}
	for _, e := range out.Scope.Entries {
		got[e.AssetID] = e
	}
	if e := got[name]; e.Outcome != easmapp.EntryAdded || e.Status != "active" || e.Pattern != "app.confirm-db.example" || e.TargetID == "" {
		t.Fatalf("name entry %+v", e)
	}
	if e := got[addr]; e.Outcome != easmapp.EntryAdded || e.TargetType != "ip_address" {
		t.Fatalf("address entry %+v", e)
	}
	if _, ok := got[svc]; ok {
		t.Fatal("a service got its own entry")
	}
	if e := got[covered]; e.Outcome != easmapp.EntryCovered {
		t.Fatalf("covered entry %+v", e)
	}
	if _, ok := got[foreign]; ok || len(out.NotFound) != 1 || out.NotFound[0] != foreign {
		t.Fatalf("another organization's asset: %+v / %v", got[foreign], out.NotFound)
	}
	if n, origin := entries(org, "app.confirm-db.example"); n != 1 || origin != "confirmed_asset" {
		t.Fatalf("entry rows %d origin %q", n, origin)
	}
	if n, _ := entries(other, "x.confirm-db.example"); n != 0 {
		t.Fatal("an entry was added in the other organization")
	}
	requireAudited(t, h.auditRows(org, "scope_target."), got[name].TargetID, []auditRow{
		{action: "scope_target.created", actor: admin.id},
	})

	// assets:write without scope:write: ownership only.
	plain := asset(org, "plain.confirm-db.example", "subdomain")
	out = decide(ownersOnly, plain)
	if out.Scope == nil || out.Scope.Skipped != easmapp.ConfirmSkippedNoPermission || len(out.Decided) != 1 {
		t.Fatalf("no scope:write: %+v %+v", out.Scope, out.Decided)
	}
	if n, _ := entries(org, "plain.confirm-db.example"); n != 0 {
		t.Fatal("an entry was added without scope:write")
	}

	// The organization turns the setting off.
	h.expect(owner, http.MethodPut, "/api/v1/scope/settings", `{"confirm_adds_to_scope":false}`, http.StatusOK)
	off := asset(org, "off.confirm-db.example", "subdomain")
	if out = decide(admin, off); out.Scope == nil || out.Scope.Skipped != easmapp.ConfirmSkippedDisabled {
		t.Fatalf("setting off: %+v", out.Scope)
	}
	// Another settings change that does not name the field keeps it off.
	h.expect(owner, http.MethodPut, "/api/v1/scope/settings", `{"one_off_max_days":5}`, http.StatusOK)
	if n, _ := entries(org, "off.confirm-db.example"); n != 0 {
		t.Fatal("an entry was added with the setting off")
	}
	off2 := asset(org, "off2.confirm-db.example", "subdomain")
	if out = decide(admin, off2); out.Scope.Skipped != easmapp.ConfirmSkippedDisabled {
		t.Fatalf("setting turned back on by an unrelated change: %+v", out.Scope)
	}
	h.expect(owner, http.MethodPut, "/api/v1/scope/settings", `{"confirm_adds_to_scope":true}`, http.StatusOK)

	// review_before_inventory (RFC-054 §15): set, kept by a change that does
	// not name it, cleared when named.
	gate := func() string {
		t.Helper()
		var v sql.NullString
		if err := h.db.QueryRow(`SELECT settings->'scope'->>'review_before_inventory' FROM tenants WHERE id = $1`, org).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v.String
	}
	h.expect(owner, http.MethodPut, "/api/v1/scope/settings", `{"review_before_inventory":true}`, http.StatusOK)
	h.expect(owner, http.MethodPut, "/api/v1/scope/settings", `{"one_off_max_days":6}`, http.StatusOK)
	if gate() != "true" {
		t.Fatalf("review_before_inventory = %q after an unrelated change", gate())
	}
	h.expect(owner, http.MethodPut, "/api/v1/scope/settings", `{"review_before_inventory":false}`, http.StatusOK)
	if gate() == "true" {
		t.Fatal("review_before_inventory not cleared")
	}

	// Strict keeps confirmation as ownership only.
	h.exec(`UPDATE tenants SET scan_approval_policy = 'strict' WHERE id = $1`, org)
	strict := asset(org, "strict.confirm-db.example", "subdomain")
	if out = decide(admin, strict); out.Scope == nil || out.Scope.Skipped != easmapp.ConfirmSkippedStrict {
		t.Fatalf("strict: %+v", out.Scope)
	}
	if n, _ := entries(org, "strict.confirm-db.example"); n != 0 {
		t.Fatal("an entry was added under Strict")
	}
}
