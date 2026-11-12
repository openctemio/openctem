package routes

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// The account directory is for support work on people, not a roster of the
// platform's own administrators: below super_admin an account linked to a
// platform administrator is neither listed (rows and tab counts) nor
// readable (404, as if it did not exist). A super admin still sees it.
// Requires DATABASE_URL.
func TestAdminDirectoryHidesAdminLinkedAccountsBelowSuper_DB(t *testing.T) {
	h := newPlatformUsersHarness(t)
	super := h.newAdmin(admin.AdminRoleSuperAdmin)
	super.verify()
	ops := h.newAdmin(admin.AdminRoleOpsAdmin)
	ops.verify()
	org := h.organization(0)
	plainID, plainEmail := h.supportUser(org)
	superID, opsID := super.userID.String(), ops.userID.String()
	superEmail := "auditchain-admin-" + superID + "@it.test"

	type page struct {
		Total  int            `json:"total"`
		Counts map[string]int `json:"counts"`
		Data   []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	list := func(c *consoleAdmin, q, state string) page {
		t.Helper()
		code, body := c.do(http.MethodGet, "/api/v1/admin/platform-users?q="+q+"&state="+state, nil, false)
		var p page
		if code != http.StatusOK || json.Unmarshal([]byte(body), &p) != nil {
			t.Fatalf("list %q: %d %s", q, code, body)
		}
		return p
	}
	has := func(p page, id string) bool {
		for _, r := range p.Data {
			if r.ID == id {
				return true
			}
		}
		return false
	}

	// Ordinary accounts are found by both roles.
	for name, c := range map[string]*consoleAdmin{"ops": ops, "super": super} {
		if p := list(c, plainEmail, "all"); !has(p, plainID) {
			t.Fatalf("%s lost the ordinary account", name)
		}
	}
	// An administrator's own account: super sees it, ops does not (rows,
	// total, the platform_admins tab and its count).
	if p := list(super, superEmail, "all"); !has(p, superID) {
		t.Fatal("super admin must find an administrator's account")
	}
	pOps := list(ops, superEmail, "all")
	if has(pOps, superID) || pOps.Total != 0 || pOps.Counts["all"] != 0 {
		t.Fatalf("ops sees an admin-linked account in the list: %+v", pOps)
	}
	if p := list(ops, superEmail, "platform_admins"); len(p.Data) != 0 || p.Counts["platform_admins"] != 0 {
		t.Fatalf("ops sees the platform_admins tab content: %+v", p)
	}
	if p := list(super, superEmail, "platform_admins"); !has(p, superID) {
		t.Fatalf("super admin lost the platform_admins tab: %+v", p)
	}
	// Reading one account: 404 for ops (also on a peer ops admin), 200 for super.
	for _, id := range []string{superID, opsID} {
		code, body := ops.do(http.MethodGet, "/api/v1/admin/platform-users/"+id, nil, false)
		if code != http.StatusNotFound || strings.Contains(body, "@") {
			t.Fatalf("ops reading admin-linked %s: %d %s", id, code, body)
		}
	}
	if code, _ := super.do(http.MethodGet, "/api/v1/admin/platform-users/"+opsID, nil, false); code != http.StatusOK {
		t.Fatalf("super admin reading an ops admin's account: %d", code)
	}
	if code, _ := ops.do(http.MethodGet, "/api/v1/admin/platform-users/"+plainID, nil, false); code != http.StatusOK {
		t.Fatalf("ops reading an ordinary account: %d", code)
	}
}

// Reads of the account directory are throttled per administrator, so a script
// cannot page through every person on the platform.
func TestAdminDirectoryReadsAreThrottled_DB(t *testing.T) {
	h := newChainHarness(t, func(h *Handlers, db *postgres.DB, _ *adminconsole.Service) {
		log := logger.NewNop()
		dir := postgres.NewPlatformUserDirectory(db)
		h.AdminPlatformUser = handler.NewAdminPlatformUserHandler(dir, nil, log)
		h.AdminDirectoryReadLimiter = middleware.NewAdminMappingRateLimiter(middleware.AdminMappingRateLimitConfig{WriteRequestsPerMin: 3}, log)
	})
	ops := h.newAdmin(admin.AdminRoleOpsAdmin)
	ops.verify()
	var last int
	for i := 0; i < 5; i++ {
		last, _ = ops.do(http.MethodGet, "/api/v1/admin/platform-users", nil, false)
		if last == http.StatusTooManyRequests {
			if i < 3 {
				t.Fatalf("throttled after only %d reads", i)
			}
			return
		}
	}
	t.Fatalf("5 reads in a minute were not throttled (last status %d)", last)
}

// The owners' addresses of an organization are on its own page only, for
// ops_admin and above, and that view is audited; the list shows the owners'
// domains. A read-only administrator gets the owner count and nothing about
// them, and not the free-text suspension reason.
func TestAdminOrganizationOwnerEmailsAndReason_DB(t *testing.T) {
	h := newPlatformUsersHarness(t)
	org := h.organization(0)
	_, email := h.supportUser(org)
	h.exec(`UPDATE tenant_members SET role = 'owner' WHERE tenant_id = $1`, org)
	h.exec(`UPDATE tenants SET status = 'suspended', suspended_at = now(), suspended_reason = 'abuse report 4411, see ticket' WHERE id = $1`, org)
	domain := email[strings.Index(email, "@")+1:]

	type view struct {
		OwnerEmails     []string `json:"owner_emails"`
		OwnerDomains    []string `json:"owner_domains"`
		OwnerCount      int      `json:"owner_count"`
		SuspendedReason string   `json:"suspended_reason"`
	}
	one := func(c *consoleAdmin) (view, string) {
		t.Helper()
		code, body := c.do(http.MethodGet, "/api/v1/admin/tenants/"+org, nil, false)
		var v view
		if code != http.StatusOK || json.Unmarshal([]byte(body), &v) != nil {
			t.Fatalf("organization view: %d %s", code, body)
		}
		return v, body
	}
	listed := func(c *consoleAdmin) (view, string) {
		t.Helper()
		code, body := c.do(http.MethodGet, "/api/v1/admin/tenants?search=auditchain&status=suspended&per_page=100", nil, false)
		var l struct {
			Data []struct {
				ID string `json:"id"`
				view
			} `json:"data"`
		}
		if code != http.StatusOK || json.Unmarshal([]byte(body), &l) != nil {
			t.Fatalf("organization list: %d %s", code, body)
		}
		for _, o := range l.Data {
			if o.ID == org {
				return o.view, body
			}
		}
		t.Fatalf("the organization is not in the list: %s", body)
		return view{}, ""
	}

	ops := h.newAdmin(admin.AdminRoleOpsAdmin)
	ops.verify()
	v, _ := one(ops)
	if len(v.OwnerEmails) != 1 || v.OwnerEmails[0] != email || v.SuspendedReason == "" {
		t.Fatalf("ops organization view: %+v", v)
	}
	if found, _ := h.auditRow("organization.view", org); !found {
		t.Fatal("viewing an organization's page (owner addresses) must be audited")
	}
	lv, lbody := listed(ops)
	if len(lv.OwnerEmails) != 0 || strings.Contains(lbody, email) || len(lv.OwnerDomains) != 1 || lv.OwnerDomains[0] != domain || lv.OwnerCount != 1 {
		t.Fatalf("ops list leaks an owner address or lost the domain: %s", lbody)
	}

	reader := h.newAdmin(admin.AdminRoleReadonly)
	reader.verify()
	rv, rbody := one(reader)
	if len(rv.OwnerEmails) != 0 || len(rv.OwnerDomains) != 0 || rv.OwnerCount != 1 || rv.SuspendedReason != "" || strings.Contains(rbody, "abuse report") {
		t.Fatalf("read-only organization view leaks: %s", rbody)
	}
	lr, lrbody := listed(reader)
	if len(lr.OwnerDomains) != 0 || lr.SuspendedReason != "" || strings.Contains(lrbody, "abuse report") || strings.Contains(lrbody, domain) {
		t.Fatalf("read-only organization list leaks: %s", lrbody)
	}
}
