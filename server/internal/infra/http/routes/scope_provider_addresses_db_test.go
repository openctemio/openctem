package routes

// The Scope page's provider addresses card (research/531 §6 step 4, B2, B3,
// B5, B6, B7, D3) through the real routes, auth chain and a migrated
// database: what is listed, who may move or keep, what a move writes, the
// audit, the hold, and that another organization sees and changes nothing.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"testing"
	"time"

	scopeapp "github.com/openctemio/openctem/server/internal/app/scope"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/edgeaddr"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/tenant"
)

// holdSettings is the scope settings reader with the hold switch only
// (nil: the stored value is unset, the default).
type holdSettings struct{ hold **bool }

func (s holdSettings) GetScopeSettings(context.Context, string) (*tenant.ScopeSettings, error) {
	return &tenant.ScopeSettings{HoldProviderEntries: *s.hold}, nil
}

// providerFixture is a provider's shared address, a CIDR wholly inside one
// of its published ranges and a wider CIDR that only partly overlaps it,
// read from the shipped dataset so the test follows every refresh.
type providerFixture struct {
	provider          string
	addr, cidr, wider string
}

func microsoft365Fixture(t *testing.T) providerFixture {
	t.Helper()
	for _, p := range edgeaddr.Default().SharedFrontEndPrefixes() {
		if !p.Addr().Is4() || p.Bits() > 28 || p.Bits() < 9 {
			continue
		}
		r, ok := edgeaddr.Default().SharedFrontEnd(p.Addr().String())
		if !ok || r.Provider != "Microsoft 365" {
			continue
		}
		inner := netip.PrefixFrom(p.Addr(), p.Bits()+1).Masked()
		wider := netip.PrefixFrom(p.Addr(), p.Bits()-1).Masked()
		if _, ok := scopedom.SharedProviderEntry(scopedom.TargetTypeCIDR, inner.String()); !ok {
			continue
		}
		if _, ok := scopedom.SharedProviderEntry(scopedom.TargetTypeCIDR, wider.String()); ok {
			continue // the neighbor is published too: try the next prefix
		}
		return providerFixture{provider: r.Provider, addr: p.Addr().Next().String(), cidr: inner.String(), wider: wider.String()}
	}
	t.Fatal("no Microsoft 365 IPv4 prefix usable as a fixture in the dataset")
	return providerFixture{}
}

func TestScopeProviderAddresses_DB(t *testing.T) {
	var hold *bool // unset: the default, on
	var store *postgres.ScopeProviderRepository
	h := newChangeAuditHarness(t, func(s *scopeapp.Service, _ *handler.ScopeHandler, db *postgres.DB) {
		cov := postgres.NewScopeCoverageRepository(db)
		s.SetCoverage(cov, unrestrictedScope{})
		s.SetExclusionMatches(cov)
		store = postgres.NewScopeProviderRepository(db)
		s.SetProviderAddresses(store)
		s.SetEntryPolicy(holdSettings{hold: &hold}, postgres.NewMemberLifecycleRepository(db), nil)
	})
	fx := microsoft365Fixture(t)
	org, other := h.tenant(), h.tenant()
	owner, member := h.member(org, "owner"), h.member(org, "member")
	reader := h.member(org, "viewer")
	h.customRoleMember(reader, org, permission.ScopeRead)
	h.mintToken(&reader, org)
	otherOwner := h.member(other, "owner")

	entry := func(tenantID, typ, pattern, origin string) string {
		t.Helper()
		var id string
		if err := h.db.QueryRowContext(context.Background(), `INSERT INTO scope_targets (tenant_id, target_type, pattern, status, origin)
			VALUES ($1, $2, $3, 'active', $4) RETURNING id`, tenantID, typ, pattern, origin).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	exact := entry(org, "ip_address", fx.addr, "import")
	cidr := entry(org, "cidr", fx.cidr, "review_rule")
	partial := entry(org, "cidr", fx.wider, "manual")
	plain := entry(org, "ip_address", "192.0.2.10", "manual")
	name := entry(org, "domain", "*.provider-card.example.com", "manual")
	otherExact := entry(other, "ip_address", fx.addr, "import")

	// A person-confirmed provider address is listed under the card (B7).
	var assetID string
	if err := h.db.QueryRowContext(context.Background(), `INSERT INTO assets (tenant_id, name, asset_type, status) VALUES ($1, $2, 'ip_address', 'active') RETURNING id`,
		org, fx.addr).Scan(&assetID); err != nil {
		t.Fatal(err)
	}
	h.exec(`INSERT INTO asset_attributions (asset_id, tenant_id, state, confidence, decided_by, decided_at)
		VALUES ($1, $2, 'confirmed', 100, $3, now())`, assetID, org, owner.id)

	card := func(u policyUser) handler.ScopeProviderAddressesResponse {
		t.Helper()
		var out handler.ScopeProviderAddressesResponse
		if err := json.Unmarshal([]byte(h.expect(u, http.MethodGet, "/api/v1/scope/provider-addresses", "", http.StatusOK)), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	c := card(reader)
	if len(c.Groups) != 1 || c.Groups[0].Provider != fx.provider || c.Groups[0].EntryCount != 2 || c.DatasetVersion == "" || !c.Holding {
		t.Fatalf("card = %+v", c)
	}
	listed := map[string]handler.ScopeProviderEntryResponse{}
	for _, e := range c.Groups[0].Entries {
		listed[e.ID] = e
	}
	// The exact address and the CIDR wholly inside are listed with their
	// origin; the partly overlapping CIDR, the documentation address and the
	// name are not (B2).
	if listed[exact].Origin != "import" || listed[cidr].Origin != "review_rule" || listed[cidr].Status != "active" {
		t.Fatalf("listed = %+v", listed)
	}
	for _, id := range []string{partial, plain, name, otherExact} {
		if _, ok := listed[id]; ok {
			t.Fatalf("entry %s listed", id)
		}
	}
	if len(c.Groups[0].Confirmed) != 1 || c.Groups[0].Confirmed[0].AssetID != assetID {
		t.Fatalf("confirmed = %+v", c.Groups[0].Confirmed)
	}
	// The other organization sees only its own entry (B6).
	if oc := card(otherOwner); len(oc.Groups) != 1 || oc.Groups[0].EntryCount != 1 || oc.Groups[0].Entries[0].ID != otherExact ||
		len(oc.Groups[0].Confirmed) != 0 {
		t.Fatalf("other card = %+v", oc)
	}
	// Restricted data scope: a member with no scope rows sees no confirmed
	// address (the entries are configuration and stay listed).
	uid, _ := shared.IDFromString(member.id)
	tid, _ := shared.IDFromString(org)
	if got, err := store.PersonConfirmedAddresses(context.Background(), tid, &shared.DataScope{TenantID: tid, UserID: uid}); err != nil || len(got) != 0 {
		t.Fatalf("restricted confirmed = %+v %v", got, err)
	}

	body := `{"provider":"` + fx.provider + `"}`
	// scope:read alone may neither move nor keep.
	h.expect(reader, http.MethodPost, "/api/v1/scope/provider-addresses/move", body, http.StatusForbidden)
	h.expect(reader, http.MethodPost, "/api/v1/scope/provider-addresses/keep", body, http.StatusForbidden)
	// Unknown provider: 404, nothing written.
	h.expect(owner, http.MethodPost, "/api/v1/scope/provider-addresses/move", `{"provider":"Example CDN"}`, http.StatusNotFound)

	// Preview writes nothing.
	var pv handler.ScopeProviderMoveResponse
	if err := json.Unmarshal([]byte(h.expect(member, http.MethodPost, "/api/v1/scope/provider-addresses/move",
		`{"provider":"`+fx.provider+`","preview":true}`, http.StatusOK)), &pv); err != nil {
		t.Fatal(err)
	}
	if !pv.Preview || pv.Entries != 2 || pv.Exclusions != 2 || pv.Existing != 0 {
		t.Fatalf("preview = %+v", pv)
	}
	countExcl := func(tenantID string) int {
		var n int
		if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM scope_exclusions WHERE tenant_id = $1`, tenantID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if countExcl(org) != 0 {
		t.Fatal("the preview wrote an exclusion")
	}

	// The other organization cannot move this one's entries: its own
	// provider list is its own, and this organization's rows stay.
	h.expect(otherOwner, http.MethodPost, "/api/v1/scope/provider-addresses/move", body, http.StatusOK)
	if countExcl(org) != 0 || countExcl(other) != 1 {
		t.Fatalf("cross-tenant move: org %d other %d exclusions", countExcl(org), countExcl(other))
	}

	// Move (B3): a member with scope:write, no step-up needed.
	var mv handler.ScopeProviderMoveResponse
	if err := json.Unmarshal([]byte(h.expect(member, http.MethodPost, "/api/v1/scope/provider-addresses/move", body, http.StatusOK)), &mv); err != nil {
		t.Fatal(err)
	}
	if mv.Preview || mv.Entries != 2 || mv.Exclusions != 2 || len(mv.ExclusionIDs) != 2 {
		t.Fatalf("move = %+v", mv)
	}
	rows, err := h.db.QueryContext(context.Background(), `SELECT exclusion_type, pattern, kind, origin, reason FROM scope_exclusions WHERE tenant_id = $1 ORDER BY pattern`, org)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	got := map[string]string{}
	for rows.Next() {
		var typ, pattern, kind, origin, reason string
		if err := rows.Scan(&typ, &pattern, &kind, &origin, &reason); err != nil {
			t.Fatal(err)
		}
		if kind != "do_not_scan" || reason == "" {
			t.Fatalf("exclusion %s: kind %s reason %q", pattern, kind, reason)
		}
		got[typ] = origin
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	// One address exclusion and one CIDR exclusion, each with its entry's
	// origin; never a name exclusion.
	if len(got) != 2 || got["ip_address"] != "import" || got["cidr"] != "review_rule" {
		t.Fatalf("exclusions = %+v", got)
	}
	status := func(id string) string {
		var s string
		if err := h.db.QueryRowContext(context.Background(), `SELECT status FROM scope_targets WHERE id = $1`, id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	// The entries are deactivated, never deleted (scope history keeps them);
	// the others are untouched, the other organization's too.
	if status(exact) != "inactive" || status(cidr) != "inactive" {
		t.Fatalf("moved entries: %s %s", status(exact), status(cidr))
	}
	for _, id := range []string{partial, plain, name} {
		if status(id) != "active" {
			t.Fatalf("entry %s changed: %s", id, status(id))
		}
	}
	// Names stay in scope: the exclusion is on the address only
	// (PropagatingAddresses), so a name resolving to it is not excluded.
	if prop := scopeapp.PropagatingAddresses([]string{fx.addr}); len(prop) != 0 {
		t.Fatalf("a shared address propagates to names: %v", prop)
	}
	// Audit (B5): each exclusion and entry, and one summary event.
	if rows := h.auditRows(org, "scope_target.provider_moved"); len(rows) != 1 {
		t.Fatalf("summary events = %d", len(rows))
	}
	requireAudited(t, h.auditRows(org, "scope_target.deactivated"), exact, []auditRow{
		{action: "scope_target.deactivated", actor: member.id, before: map[string]any{"status": "active"}, after: map[string]any{"status": "inactive"}},
	})
	if rows := h.auditRows(org, "scope_exclusion.created"); len(rows) != 2 {
		t.Fatalf("exclusion events = %d", len(rows))
	}
	// Answered: nothing left to decide for this organization.
	if c := card(owner); len(c.Groups) != 1 || c.Groups[0].EntryCount != 0 || len(c.Groups[0].Confirmed) != 1 {
		t.Fatalf("card after move = %+v", c)
	}
}

// Keep scanning (B3, D3): step-up, audited, the entries leave the card and
// are never held; the hold is on by default and off only when the
// organization turns it off.
func TestScopeProviderAddresses_KeepAndHold_DB(t *testing.T) {
	var hold *bool
	var svc *scopeapp.Service
	h := newChangeAuditHarness(t, func(s *scopeapp.Service, _ *handler.ScopeHandler, db *postgres.DB) {
		s.SetCoverage(postgres.NewScopeCoverageRepository(db), unrestrictedScope{})
		s.SetProviderAddresses(postgres.NewScopeProviderRepository(db))
		s.SetEntryPolicy(holdSettings{hold: &hold}, postgres.NewMemberLifecycleRepository(db), nil)
		svc = s
	})
	fx := microsoft365Fixture(t)
	org, other := h.tenant(), h.tenant()
	owner, member := h.member(org, "owner"), h.member(org, "member")
	otherOwner := h.member(other, "owner")
	var id, otherID string
	if err := h.db.QueryRowContext(context.Background(), `INSERT INTO scope_targets (tenant_id, target_type, pattern, status, origin)
		VALUES ($1, 'ip_address', $2, 'active', 'import') RETURNING id`, org, fx.addr).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRowContext(context.Background(), `INSERT INTO scope_targets (tenant_id, target_type, pattern, status, origin)
		VALUES ($1, 'ip_address', $2, 'active', 'import') RETURNING id`, other, fx.addr).Scan(&otherID); err != nil {
		t.Fatal(err)
	}
	tid, _ := shared.IDFromString(org)
	held := func() bool {
		t.Helper()
		ts, err := svc.ListActiveTargets(context.Background(), org)
		if err != nil {
			t.Fatal(err)
		}
		m, err := svc.HeldProviderEntries(context.Background(), tid, ts)
		if err != nil {
			t.Fatal(err)
		}
		eid, _ := shared.IDFromString(id)
		return m[eid]
	}
	if !held() {
		t.Fatal("not held with the setting unset (the default is on) and no answer")
	}
	off, on := false, true
	hold = &off
	if held() {
		t.Fatal("held with the setting turned off")
	}
	hold = &on
	if !held() {
		t.Fatal("not held with the setting on and no answer")
	}

	body := `{"provider":"` + fx.provider + `"}`
	var kept handler.ScopeProviderKeepResponse
	if err := json.Unmarshal([]byte(h.expect(member, http.MethodPost, "/api/v1/scope/provider-addresses/keep", body, http.StatusOK)), &kept); err != nil {
		t.Fatal(err)
	}
	if len(kept.Kept) != 1 || kept.Kept[0].ID != id {
		t.Fatalf("kept = %+v", kept)
	}
	if held() {
		t.Fatal("still held after keep scanning")
	}
	rows := h.auditRows(org, "scope_target.provider_kept")
	if len(rows) != 1 || rows[0].actor != member.id || rows[0].severity != "high" {
		t.Fatalf("keep audit = %+v", rows)
	}
	// The entry left the card; it is still active; the other organization's
	// identical entry is not kept.
	var c handler.ScopeProviderAddressesResponse
	if err := json.Unmarshal([]byte(h.expect(owner, http.MethodGet, "/api/v1/scope/provider-addresses", "", http.StatusOK)), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Groups) != 0 || !c.Holding {
		t.Fatalf("card after keep = %+v", c)
	}
	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM scope_provider_keeps WHERE tenant_id = $1`, other).Scan(&n); err != nil || n != 0 {
		t.Fatalf("other organization kept: %d %v", n, err)
	}
	var oc handler.ScopeProviderAddressesResponse
	if err := json.Unmarshal([]byte(h.expect(otherOwner, http.MethodGet, "/api/v1/scope/provider-addresses", "", http.StatusOK)), &oc); err != nil {
		t.Fatal(err)
	}
	if len(oc.Groups) != 1 || oc.Groups[0].Entries[0].ID != otherID {
		t.Fatalf("other card = %+v", oc)
	}
	// Nothing left to keep: 404.
	h.expect(owner, http.MethodPost, "/api/v1/scope/provider-addresses/keep", body, http.StatusNotFound)
}

// Keep scanning needs a recent re-authentication: a stale session is
// refused before the handler and nothing is recorded.
func TestScopeProviderAddresses_KeepNeedsStepUp_DB(t *testing.T) {
	changeAuditExtraHandlers = func(hs *Handlers, _ *postgres.DB) { hs.StepUp = steppedUpAt(time.Now().Add(-2 * time.Hour)) }
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	h := newChangeAuditHarness(t, func(s *scopeapp.Service, _ *handler.ScopeHandler, db *postgres.DB) {
		s.SetProviderAddresses(postgres.NewScopeProviderRepository(db))
	})
	fx := microsoft365Fixture(t)
	org := h.tenant()
	owner := h.member(org, "owner")
	h.exec(`INSERT INTO scope_targets (tenant_id, target_type, pattern, status, origin) VALUES ($1, 'ip_address', $2, 'active', 'import')`, org, fx.addr)
	out := h.expect(owner, http.MethodPost, "/api/v1/scope/provider-addresses/keep", `{"provider":"`+fx.provider+`"}`, http.StatusForbidden)
	var e struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal([]byte(out), &e)
	if e.Code != "STEP_UP_REQUIRED" {
		t.Fatalf("keep with a stale session: %s", out)
	}
	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT count(*) FROM scope_provider_keeps WHERE tenant_id = $1`, org).Scan(&n); err != nil || n != 0 {
		t.Fatalf("kept without step-up: %d %v", n, err)
	}
	// Moving out of scope only narrows: no step-up.
	h.expect(owner, http.MethodPost, "/api/v1/scope/provider-addresses/move", `{"provider":"`+fx.provider+`"}`, http.StatusOK)
}
