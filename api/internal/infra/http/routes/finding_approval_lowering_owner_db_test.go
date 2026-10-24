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
		"backup contact":       `{"backup_contact_email":"a@example.com"}`,
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
	h.expect(admin, http.MethodPatch, url, `{"fp_approval":"all","accept_approval":"all"}`, http.StatusOK)
}

// The second-look share and the backup contact are owner-only to lower or
// change; an administrator may raise the share, or send the contact as it is.
func TestFindingApprovalSettings_SecondLookAndBackupContactOwnerOnly_DB(t *testing.T) {
	h := newAcceptPolicyHarness(t, nil)
	org := h.tenantWithFindings()
	owner, admin := h.member(org, "owner"), h.member(org, "admin")
	const url = "/api/v1/organization/settings/finding-approvals/"
	var got struct {
		SecondLook    int    `json:"second_look_percent"`
		PendingSecond *int   `json:"pending_second_look_percent"`
		BackupContact string `json:"backup_contact_email"`
	}
	read := func() {
		t.Helper()
		got.PendingSecond = nil
		_ = json.Unmarshal([]byte(h.expect(owner, http.MethodGet, url, "", http.StatusOK)), &got)
	}

	h.expect(owner, http.MethodPatch, url, `{"second_look_percent":5,"backup_contact_email":"first@example.com"}`, http.StatusOK)
	h.expect(admin, http.MethodPatch, url, `{"second_look_percent":2}`, http.StatusForbidden)
	h.expect(admin, http.MethodPatch, url, `{"second_look_percent":0}`, http.StatusForbidden)
	h.expect(admin, http.MethodPatch, url, `{"backup_contact_email":"attacker@example.com"}`, http.StatusForbidden)
	h.expect(admin, http.MethodPatch, url, `{"backup_contact_email":""}`, http.StatusForbidden)
	read()
	if got.SecondLook != 5 || got.PendingSecond != nil || got.BackupContact != "first@example.com" {
		t.Fatalf("a refused change left a trace: %+v", got)
	}

	// Raising the share, and sending the contact unchanged, are allowed.
	h.expect(admin, http.MethodPatch, url, `{"second_look_percent":7,"backup_contact_email":"first@example.com"}`, http.StatusOK)
	// The owner lowers the share (it waits) and changes the contact.
	h.expect(owner, http.MethodPatch, url, `{"second_look_percent":1,"backup_contact_email":"second@example.com"}`, http.StatusOK)
	read()
	if got.PendingSecond == nil || *got.PendingSecond != 1 || got.BackupContact != "second@example.com" {
		t.Fatalf("owner change: %+v", got)
	}
}
