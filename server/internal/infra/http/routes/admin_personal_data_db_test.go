package routes

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
)

// A read-only administrator sees counts, never people: an organization's
// member list comes back with counts by role and no names or emails, the
// organization list and page carry the owner count but no owner emails, and
// the cross-organization account search is refused. Every member-list view is
// audited. An ops administrator still sees the people. Requires DATABASE_URL.
func TestAdminReadonlySeesCountsNotPeople_DB(t *testing.T) {
	h := newPlatformUsersHarness(t)
	org := h.organization(0)
	_, email := h.supportUser(org)
	h.exec(`UPDATE tenant_members SET role = 'owner' WHERE tenant_id = $1`, org)

	type userList struct {
		Data []struct {
			Email string `json:"email"`
		} `json:"data"`
		Total    int            `json:"total"`
		ByRole   map[string]int `json:"by_role"`
		Redacted bool           `json:"redacted"`
	}
	type orgView struct {
		OwnerEmails []string `json:"owner_emails"`
		OwnerCount  int      `json:"owner_count"`
	}

	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	code, body := reader.do(http.MethodGet, "/api/v1/admin/tenants/"+org+"/users", nil, false)
	var ul userList
	if code != http.StatusOK || json.Unmarshal([]byte(body), &ul) != nil {
		t.Fatalf("readonly member list: %d %s", code, body)
	}
	if !ul.Redacted || len(ul.Data) != 0 || ul.Total != 1 || ul.ByRole["owner"] != 1 || strings.Contains(body, email) {
		t.Fatalf("readonly member list leaks people or lost the counts: %s", body)
	}
	if found, _ := h.auditRow("organization.users_view", org); !found {
		t.Fatal("a member-list view must be audited")
	}
	code, body = reader.do(http.MethodGet, "/api/v1/admin/tenants/"+org, nil, false)
	var ov orgView
	if code != http.StatusOK || json.Unmarshal([]byte(body), &ov) != nil || len(ov.OwnerEmails) != 0 || ov.OwnerCount != 1 || strings.Contains(body, email) {
		t.Fatalf("readonly organization view: %d %s", code, body)
	}
	if code, body = reader.do(http.MethodGet, "/api/v1/admin/tenants?search=auditchain", nil, false); code != http.StatusOK || strings.Contains(body, email) {
		t.Fatalf("readonly organization list leaks an owner email: %d %s", code, body)
	}
	for _, path := range []string{"/api/v1/admin/platform-users?q=" + email, "/api/v1/admin/platform-users/" + org} {
		if code, _ := reader.do(http.MethodGet, path, nil, false); code != http.StatusForbidden {
			t.Fatalf("readonly %s: %d, want 403", path, code)
		}
	}

	ops := h.newAdmin(admin.AdminRoleOpsAdmin)
	ops.verify()
	code, body = ops.do(http.MethodGet, "/api/v1/admin/tenants/"+org+"/users", nil, false)
	ul = userList{}
	if code != http.StatusOK || json.Unmarshal([]byte(body), &ul) != nil || ul.Redacted || len(ul.Data) != 1 || ul.Data[0].Email != email {
		t.Fatalf("ops member list: %d %s", code, body)
	}
	code, body = ops.do(http.MethodGet, "/api/v1/admin/tenants/"+org, nil, false)
	ov = orgView{}
	if code != http.StatusOK || json.Unmarshal([]byte(body), &ov) != nil || len(ov.OwnerEmails) != 1 || ov.OwnerEmails[0] != email {
		t.Fatalf("ops organization view: %d %s", code, body)
	}
	if code, _ := ops.do(http.MethodGet, "/api/v1/admin/platform-users?q="+email, nil, false); code != http.StatusOK {
		t.Fatalf("ops account search: %d", code)
	}
}
