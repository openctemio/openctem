package routes

// Lowering a finding approval level, or relaxing the approval policy (which
// includes turning two-person approval off), is for the organization's owner:
// an administrator may raise a level or leave it alone, and is refused when
// the change lowers or relaxes anything. Nothing is written on a refusal.

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestFindingApprovalSettings_LoweringIsOwnerOnly_DB(t *testing.T) {
	h := newAcceptPolicyHarness(t, nil)
	org := h.tenantWithFindings()
	owner, admin := h.member(org, "owner"), h.member(org, "admin")
	const url = "/api/v1/organization/settings/finding-approvals/"

	// An administrator may not lower either level or relax the policy.
	for _, body := range map[string]string{
		"false-positive level": `{"fp_approval":"off"}`,
		"risk acceptance":      `{"accept_approval":"high_and_above"}`,
		"policy relaxation":    `{"policy":{"tiers":{"accepted.critical":"security"}}}`,
		"lowering with other":  `{"backup_contact_email":"a@example.com","fp_approval":"high_and_above"}`,
	} {
		h.expect(admin, http.MethodPatch, url, body, http.StatusForbidden)
	}
	var got struct {
		FP            string `json:"fp_approval"`
		Accept        string `json:"accept_approval"`
		PendingFP     string `json:"pending_fp_approval"`
		PendingAccept string `json:"pending_accept_approval"`
		PendingPolicy any    `json:"pending_policy"`
		BackupContact string `json:"backup_contact_email"`
	}
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodGet, url, "", http.StatusOK)), &got)
	if got.PendingFP != "" || got.PendingAccept != "" || got.PendingPolicy != nil || got.BackupContact != "" {
		t.Fatalf("a refused change left a trace: %+v", got)
	}

	// The owner lowers; the administrator may raise it again, and may keep a
	// level as it is while changing something else.
	h.expect(owner, http.MethodPatch, url, `{"fp_approval":"high_and_above"}`, http.StatusOK)
	_ = json.Unmarshal([]byte(h.expect(admin, http.MethodPatch, url, `{"fp_approval":"all"}`, http.StatusOK)), &got)
	if got.FP != "all" || got.PendingFP != "" {
		t.Fatalf("raising by an administrator: %+v", got)
	}
	h.expect(admin, http.MethodPatch, url, `{"fp_approval":"all","accept_approval":"all","backup_contact_email":"b@example.com"}`, http.StatusOK)
}
