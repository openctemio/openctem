package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/server/internal/app/audit"
	"github.com/openctemio/openctem/server/internal/app/scanpolicy"
	scopeapp "github.com/openctemio/openctem/server/internal/app/scope"
	tenantapp "github.com/openctemio/openctem/server/internal/app/tenant"
	"github.com/openctemio/openctem/server/internal/infra/http/handler"
	"github.com/openctemio/openctem/server/internal/infra/postgres"
	"github.com/openctemio/openctem/server/pkg/domain/scanzone"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/jwt"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// Replacing a scope entry's pattern through the real routes and database
// (docs/architecture/scope-entry-replace.md): the replacement is a new
// entry with the checks and approvals of a new entry; the old entry is
// retired only once the replacement is in effect; another tenant's entry is
// not found; a refused pattern leaves the old entry as it was; one audit
// event names both patterns and the reason; scan zones naming the old range
// are reported (to callers who may read zones), never changed.
func TestScopeReplacePattern_DB(t *testing.T) {
	var zones *postgres.ScanZoneRepository
	h := newChangeAuditHarness(t, func(s *scopeapp.Service, sh *handler.ScopeHandler, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		sh.SetSettingsStore(ts)
		s.SetEntryPolicy(ts, postgres.NewMemberLifecycleRepository(db), nil)
		pol := scanpolicy.NewService(postgres.NewScanPolicyRepository(db), nil, nil, nil, nil, log)
		pol.SetSettings(ts)
		s.SetGovernance(pol)
		zones = postgres.NewScanZoneRepository(db)
		s.SetZones(zones)
	})
	org, other := h.tenant(), h.tenant()
	h.member(org, "owner")
	admin, admin2 := h.member(org, "admin"), h.member(org, "admin")
	otherAdmin := h.member(other, "admin")
	h.member(other, "owner")

	orgID := shared.MustIDFromString(org)
	zone, err := scanzone.NewZone(orgID, "Office", "", false, []string{"192.0.2.0/24", "203.0.113.0/26"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := zones.Create(context.Background(), zone); err != nil {
		t.Fatal(err)
	}

	old := settingsOf(t, h.expect(admin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"cidr","pattern":"192.0.2.0/24","description":"office"}`, http.StatusCreated))
	oldID, _ := old["id"].(string)
	base := "/api/v1/scope/targets/" + oldID

	// Another tenant cannot preview or replace it, and it is unchanged.
	h.expect(otherAdmin, http.MethodPost, base+"/replace/preview", `{"pattern":"198.51.100.0/24","reason":"typo"}`, http.StatusNotFound)
	h.expect(otherAdmin, http.MethodPost, base+"/replace", `{"pattern":"198.51.100.0/24","reason":"typo"}`, http.StatusNotFound)

	// A reason is required.
	h.expect(admin, http.MethodPost, base+"/replace", `{"pattern":"198.51.100.0/24"}`, http.StatusUnprocessableEntity)

	// A guardrail refusal leaves the old entry in effect and adds nothing.
	h.expect(admin, http.MethodPost, base+"/replace", `{"pattern":"0.0.0.0/0","reason":"typo"}`, http.StatusBadRequest)
	if got := settingsOf(t, h.expect(admin, http.MethodGet, base, "", http.StatusOK)); got["status"] != "active" || got["in_effect"] != true {
		t.Fatalf("a refused replacement changed the old entry: %v", got)
	}
	if n := h.count(`SELECT count(*) FROM scope_targets WHERE tenant_id = $1 AND supersedes_id IS NOT NULL`, org); n != 0 {
		t.Fatalf("a refused replacement saved %d row(s)", n)
	}

	// The preview: added and removed coverage, the zone that names the old
	// range with its suggested ranges, nothing saved.
	pv := replaceOf(t, h.expect(admin, http.MethodPost, base+"/replace/preview", `{"pattern":"198.51.100.0/24","reason":"typo"}`, http.StatusOK))
	if !pv.Change.Widens || !pv.Change.Narrows || pv.Change.AddedAddresses != 256 || pv.Change.RemovedAddresses != 256 ||
		len(pv.Change.Added) != 1 || pv.Change.Added[0] != "198.51.100.0/24" || pv.Change.Removed[0] != "192.0.2.0/24" {
		t.Fatalf("preview change: %+v", pv.Change)
	}
	if !pv.OldRetired || pv.New.Status != "active" || len(pv.Zones) != 1 || pv.Zones[0].ID != zone.ID.String() {
		t.Fatalf("preview: %+v", pv)
	}
	if s := pv.Zones[0].Suggested; len(s) != 2 || s[0] != "198.51.100.0/24" || s[1] != "203.0.113.0/26" {
		t.Fatalf("suggested zone ranges: %v", s)
	}
	if n := h.count(`SELECT count(*) FROM scope_targets WHERE tenant_id = $1`, org); n != 1 {
		t.Fatalf("the preview saved rows: %d", n)
	}

	// Off (the default): the replacement takes effect at once and the old
	// entry is superseded, linked both ways. The zone is not changed.
	res := replaceOf(t, h.expect(admin, http.MethodPost, base+"/replace", `{"pattern":"198.51.100.0/24","reason":"typo in the range"}`, http.StatusCreated))
	if !res.OldRetired || res.New.Status != "active" || res.Old.Status != "superseded" ||
		res.New.SupersedesID == nil || *res.New.SupersedesID != oldID || res.Old.SupersededByID == nil || *res.Old.SupersededByID != res.New.ID {
		t.Fatalf("replace: %+v", res)
	}
	if res.New.Description != "office" || res.New.TargetType != "cidr" {
		t.Fatalf("the replacement lost the entry's settings: %+v", res.New)
	}
	got := settingsOf(t, h.expect(admin, http.MethodGet, base, "", http.StatusOK))
	if got["status"] != "superseded" || got["in_effect"] != false || got["pattern"] != "192.0.2.0/24" {
		t.Fatalf("the old entry is not kept as superseded: %v", got)
	}
	if z, err := zones.GetByID(context.Background(), orgID, zone.ID); err != nil || len(z.Ranges) != 2 || z.Ranges[0].String() != "192.0.2.0/24" {
		t.Fatalf("the zone changed without its own call: %v %v", z, err)
	}
	// One audit event names both patterns and the reason.
	var meta map[string]any
	var raw []byte
	if err := h.db.QueryRowContext(context.Background(), `SELECT metadata FROM audit_logs
		WHERE tenant_id = $1 AND action = 'scope_target.replaced' AND resource_id = $2`, org, oldID).Scan(&raw); err != nil {
		t.Fatalf("replace audit: %v", err)
	}
	_ = json.Unmarshal(raw, &meta)
	if meta["old_pattern"] != "192.0.2.0/24" || meta["new_pattern"] != "198.51.100.0/24" || meta["reason"] != "typo in the range" || meta["new_id"] != res.New.ID {
		t.Fatalf("replace audit metadata: %v", meta)
	}
	// A superseded entry is not replaced, activated or deactivated again.
	h.expect(admin, http.MethodPost, base+"/replace", `{"pattern":"198.51.100.0/25","reason":"again"}`, http.StatusConflict)
	h.expect(admin, http.MethodPost, base+"/activate", "", http.StatusConflict)
	h.expect(admin, http.MethodPost, base+"/deactivate", "", http.StatusConflict)

	// A caller with scope:write but without sensors:zones:read gets the
	// zone count, not its name or ranges.
	writer := h.member(org, "member")
	h.tokenWith(&writer, org, "attack_surface:scope:read", "attack_surface:scope:write")
	newBase := "/api/v1/scope/targets/" + res.New.ID
	zone2, _ := scanzone.NewZone(orgID, "Lab", "", false, []string{"198.51.100.0/24"}, nil)
	if err := zones.Create(context.Background(), zone2); err != nil {
		t.Fatal(err)
	}
	hidden := replaceOf(t, h.expect(writer, http.MethodPost, newBase+"/replace/preview", `{"pattern":"198.51.100.0/25","reason":"narrow"}`, http.StatusOK))
	if len(hidden.Zones) != 0 || hidden.ZonesHidden != 1 {
		t.Fatalf("zone details reached a caller without sensors:zones:read: %+v", hidden)
	}
	if hidden.Change.Widens || !hidden.Change.Narrows {
		t.Fatalf("a narrowing read as a widening: %+v", hidden.Change)
	}

	// Strict: the replacement goes through the same approvals as a new
	// entry, even a narrowing. The old entry stays in effect until it is
	// approved, and only one replacement waits at a time.
	h.exec(`UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{scan_governance}', '{"mode":"strict"}') WHERE id = $1`, org)
	pend := replaceOf(t, h.expect(admin, http.MethodPost, newBase+"/replace", `{"pattern":"198.51.100.0/25","reason":"narrow it"}`, http.StatusCreated))
	if pend.OldRetired || pend.New.Status != "pending" || pend.Old.Status != "active" {
		t.Fatalf("Strict: a replacement took effect without its approval: %+v", pend)
	}
	if got := settingsOf(t, h.expect(admin, http.MethodGet, newBase, "", http.StatusOK)); got["in_effect"] != true {
		t.Fatalf("the old entry left effect before its replacement was approved: %v", got)
	}
	h.expect(admin, http.MethodPost, newBase+"/replace", `{"pattern":"198.51.100.0/26","reason":"again"}`, http.StatusConflict)
	// The requester cannot approve; another approver can, and that retires
	// the old entry in the same change.
	h.expect(admin, http.MethodPost, "/api/v1/scope/targets/"+pend.New.ID+"/approve", "", http.StatusForbidden)
	h.expect(admin2, http.MethodPost, "/api/v1/scope/targets/"+pend.New.ID+"/approve", "", http.StatusOK)
	got = settingsOf(t, h.expect(admin, http.MethodGet, newBase, "", http.StatusOK))
	if got["status"] != "superseded" || got["superseded_by_id"] != pend.New.ID {
		t.Fatalf("the approved replacement did not retire the old entry: %v", got)
	}
	if got := settingsOf(t, h.expect(admin, http.MethodGet, "/api/v1/scope/targets/"+pend.New.ID, "", http.StatusOK)); got["status"] != "active" {
		t.Fatalf("approved replacement: %v", got)
	}
}

func (h *authzPolicyHarness) count(q string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

// tokenWith re-mints u's token carrying exactly perms (a role narrower than
// any system role).
func (h *authzPolicyHarness) tokenWith(u *policyUser, tenantID string, perms ...string) {
	h.t.Helper()
	tok, err := h.gen.GenerateTenantScopedAccessTokenWithPermissions(u.id, "authzpol-"+u.id[:8]+"@it.test", "Authz policy IT",
		uuid.NewString(), jwt.TenantMembership{TenantID: tenantID, Role: u.role}, perms, false, 0, "password")
	if err != nil {
		h.t.Fatalf("mint token: %v", err)
	}
	u.token = tok.AccessToken
}

func replaceOf(t *testing.T, body string) handler.ScopeReplaceResponse {
	t.Helper()
	var out handler.ScopeReplaceResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return out
}
