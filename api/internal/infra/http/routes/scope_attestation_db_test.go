package routes

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// Keeping a t2 entry through the real routes (RFC-054 §12.5): approvers
// only, one click, audited; another organization reaches nothing.
func TestScopeAttestation_Routes_DB(t *testing.T) {
	h := newChangeAuditHarness(t)
	org := h.tenant()
	admin, member := h.member(org, "admin"), h.member(org, "member")
	stranger := h.member(h.tenant(), "owner")

	id := uuid.NewString()
	h.exec(`INSERT INTO scope_targets (id, tenant_id, target_type, pattern, status, created_by, reason, max_tier,
		approvals_required, approved_at, attestation_requested_at, created_at, updated_at)
		VALUES ($1, $2, 'domain', 'perm.t2.routes.example', 'active', $3, 'contract', 2, 0,
		now() - interval '100 days', now() - interval '3 days', now() - interval '100 days', now())`, id, org, admin.id)
	base := "/api/v1/scope/targets/" + id

	got := settingsOf(t, h.expect(member, http.MethodGet, base, "", http.StatusOK))
	att, _ := got["attestation"].(map[string]any)
	if att == nil || att["requested_at"] == nil || att["downgrade_at"] == nil {
		t.Fatalf("an open attestation request is not shown: %v", got)
	}
	h.expect(member, http.MethodPost, base+"/attest", "", http.StatusForbidden)
	h.expect(stranger, http.MethodPost, base+"/attest", "", http.StatusNotFound)
	got = settingsOf(t, h.expect(admin, http.MethodPost, base+"/attest", "", http.StatusOK))
	att, _ = got["attestation"].(map[string]any)
	if att == nil || att["requested_at"] != nil || att["attested_at"] == nil || got["max_tier"] != "t2" {
		t.Fatalf("after keeping it: %v", got)
	}
	requireAudited(t, h.auditRows(org, "scope_target.attested"), id, []auditRow{
		{action: "scope_target.attested", actor: admin.id, before: map[string]any{"max_tier": "t2"}, after: map[string]any{"max_tier": "t2"}},
	})
}
