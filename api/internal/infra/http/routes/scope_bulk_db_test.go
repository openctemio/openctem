package routes

import (
	"encoding/json"
	"net/http"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/scanpolicy"
	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// POST /api/v1/scope/targets/bulk through the real routes (RFC-054 §14):
// a member with scope:write adds many entries in one request (Off, the
// default), each audited; an entry the organization already has is answered
// "exists" with its own row; a public suffix is refused on its item; a
// viewer (no scope:write) is refused; another organization's identical
// entry is neither named nor touched.
func TestScopeBulkAdd_DB(t *testing.T) {
	h := newChangeAuditHarness(t, func(s *scopeapp.Service, sh *handler.ScopeHandler, db *postgres.DB) {
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
	h.member(org, "owner")
	member, viewer := h.member(org, "member"), h.member(org, "viewer")
	h.member(other, "owner")
	otherAdmin := h.member(other, "admin")

	// The other organization already has the same name.
	h.expect(otherAdmin, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"api.bulk-db.example"}`, http.StatusCreated)
	existing := decodeID(t, h.expect(member, http.MethodPost, "/api/v1/scope/targets",
		`{"target_type":"domain","pattern":"old.bulk-db.example"}`, http.StatusCreated))

	body := h.expect(member, http.MethodPost, "/api/v1/scope/targets/bulk", `{"items":[
		{"target_type":"domain","pattern":"api.bulk-db.example"},
		{"target_type":"ip_address","pattern":"203.0.113.9"},
		{"target_type":"domain","pattern":"old.bulk-db.example"},
		{"target_type":"domain","pattern":"*.com"}]}`, http.StatusOK)
	var out handler.BulkCreateScopeTargetsResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Created != 2 || out.Existing != 1 || out.Refused != 1 || len(out.Results) != 4 {
		t.Fatalf("counts %+v", out)
	}
	if r := out.Results[0]; r.Result != "created" || r.Status != "active" || r.ID == "" {
		t.Fatalf("first item %+v, want created and active (Off needs no approval)", r)
	}
	if r := out.Results[2]; r.Result != "exists" || r.ID != existing {
		t.Fatalf("existing item %+v, want exists naming %s", r, existing)
	}
	if r := out.Results[3]; r.Result != "refused" || r.Code != "PUBLIC_SUFFIX" {
		t.Fatalf("public suffix item %+v", r)
	}
	requireAudited(t, h.auditRows(org, "scope_target."), out.Results[1].ID, []auditRow{
		{action: "scope_target.created", actor: member.id, after: map[string]any{"pattern": "203.0.113.9", "origin": "import"}},
	})

	// No scope:write: refused before anything is read.
	h.expect(viewer, http.MethodPost, "/api/v1/scope/targets/bulk",
		`{"items":[{"target_type":"domain","pattern":"v.bulk-db.example"}]}`, http.StatusForbidden)
	// Bounds are validated.
	h.expect(member, http.MethodPost, "/api/v1/scope/targets/bulk", `{"items":[]}`, http.StatusUnprocessableEntity)
	h.expect(member, http.MethodPost, "/api/v1/scope/targets/bulk",
		`{"items":[{"target_type":"domain","pattern":"x.bulk-db.example"}],"origin":"system"}`, http.StatusUnprocessableEntity)

	// The other organization still has exactly its own entry.
	var list struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(h.expect(otherAdmin, http.MethodGet, "/api/v1/scope/targets/?search=bulk-db", "", http.StatusOK)), &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 {
		t.Fatalf("other organization sees %d entries, want only its own", list.Total)
	}
}
