package routes

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Business units were deleted under assets:write, which every member holds,
// and the member list returned every member's email to every member. Owner
// decision 2026-10-02: both are owner/admin only. Members keep creating and
// editing business units, and keep a name-only member list for the assignee
// and owner pickers.

func TestAuthzPolicy_BusinessUnitDeleteIsAdminOnly_DB(t *testing.T) {
	h := newAuthzPolicyHarness(t)
	tid := h.tenant()
	owner, admin, member, viewer := h.member(tid, "owner"), h.member(tid, "admin"), h.member(tid, "member"), h.member(tid, "viewer")

	newBU := func(name string) string {
		t.Helper()
		// A member still creates business units (assets:write).
		body := h.expect(member, http.MethodPost, "/api/v1/business-units", `{"name":"`+name+`"}`, http.StatusCreated)
		var bu struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(body), &bu); err != nil || bu.ID == "" {
			t.Fatalf("create business unit: %v %s", err, body)
		}
		return bu.ID
	}

	id := newBU("bu-delete-gate")
	h.expect(member, http.MethodPut, "/api/v1/business-units/"+id, `{"name":"bu-delete-gate-renamed"}`, http.StatusOK)
	h.expect(member, http.MethodDelete, "/api/v1/business-units/"+id, "", http.StatusForbidden)
	h.expect(viewer, http.MethodDelete, "/api/v1/business-units/"+id, "", http.StatusForbidden)
	h.expect(member, http.MethodGet, "/api/v1/business-units/"+id, "", http.StatusOK) // still there

	h.expect(admin, http.MethodDelete, "/api/v1/business-units/"+id, "", http.StatusNoContent)
	h.expect(owner, http.MethodDelete, "/api/v1/business-units/"+newBU("bu-owner-delete"), "", http.StatusNoContent)

	// Another tenant's admin cannot reach this tenant's unit.
	other := h.member(h.tenant(), "admin")
	id = newBU("bu-cross-tenant")
	if code, _ := h.do(other, http.MethodDelete, "/api/v1/business-units/"+id, ""); code == http.StatusNoContent {
		t.Fatal("an admin of another tenant deleted this tenant's business unit")
	}
	h.expect(member, http.MethodGet, "/api/v1/business-units/"+id, "", http.StatusOK)
}

type memberRow struct {
	UserID      string  `json:"user_id"`
	Name        string  `json:"name"`
	Email       *string `json:"email"`
	LastLoginAt *string `json:"last_login_at"`
}

func (h *authzPolicyHarness) listMembers(u policyUser, tenantID, query string) []memberRow {
	h.t.Helper()
	body := h.expect(u, http.MethodGet, "/api/v1/tenants/"+tenantID+"/members?include=user,roles"+query, "", http.StatusOK)
	var resp struct {
		Data []memberRow `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		h.t.Fatalf("decode member list: %v %s", err, body)
	}
	return resp.Data
}

func TestAuthzPolicy_MemberEmailsAreAdminOnly_DB(t *testing.T) {
	h := newAuthzPolicyHarness(t)
	tid := h.tenant()
	owner, admin, member, viewer := h.member(tid, "owner"), h.member(tid, "admin"), h.member(tid, "member"), h.member(tid, "viewer")
	h.exec(`UPDATE users SET last_login_at = now() WHERE id = $1`, owner.id)
	all := []policyUser{owner, admin, member, viewer}

	// Members and viewers: every member is listed with id and name, no email,
	// no last sign-in.
	for _, u := range []policyUser{member, viewer} {
		rows := h.listMembers(u, tid, "")
		if len(rows) != len(all) {
			t.Fatalf("%s sees %d members, want %d", u.role, len(rows), len(all))
		}
		for _, m := range rows {
			if m.UserID == "" || m.Name == "" {
				t.Errorf("%s: member row without id or name: %+v", u.role, m)
			}
			if m.Email != nil || m.LastLoginAt != nil {
				t.Errorf("%s sees the email or last sign-in of %s", u.role, m.UserID)
			}
		}
		// The basic (no include=user) listing never carried emails; it still works.
		if body := h.expect(u, http.MethodGet, "/api/v1/tenants/"+tid+"/members", "", http.StatusOK); strings.Contains(body, "@it.test") {
			t.Errorf("%s basic member list carries an email: %s", u.role, body)
		}
		// A search cannot confirm an address either.
		if rows := h.listMembers(u, tid, "&search=authzpol-"+owner.id[:8]); len(rows) != 0 {
			t.Errorf("%s: email search matched %d members", u.role, len(rows))
		}
		if rows := h.listMembers(u, tid, "&search=Authz"); len(rows) != len(all) {
			t.Errorf("%s: name search matched %d members, want %d", u.role, len(rows), len(all))
		}
	}

	// Owners and admins see the directory.
	for _, u := range []policyUser{owner, admin} {
		rows := h.listMembers(u, tid, "")
		if len(rows) != len(all) {
			t.Fatalf("%s sees %d members, want %d", u.role, len(rows), len(all))
		}
		for _, m := range rows {
			if m.Email == nil || !strings.HasSuffix(*m.Email, "@it.test") {
				t.Errorf("%s does not see the email of %s", u.role, m.UserID)
			}
			if m.UserID == owner.id && m.LastLoginAt == nil {
				t.Errorf("%s does not see the owner's last sign-in", u.role)
			}
		}
		if rows := h.listMembers(u, tid, "&search=authzpol-"+owner.id[:8]); len(rows) != 1 {
			t.Errorf("%s: email search matched %d members, want 1", u.role, len(rows))
		}
	}

	// Another tenant's owner cannot list this tenant's members.
	outsider := h.member(h.tenant(), "owner")
	h.expect(outsider, http.MethodGet, "/api/v1/tenants/"+tid+"/members?include=user", "", http.StatusForbidden)
}
