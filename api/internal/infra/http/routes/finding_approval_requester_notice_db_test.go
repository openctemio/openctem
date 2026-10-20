package routes

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// The person who asked for a false-positive or accepted-risk decision is told
// how it ended (research 215, B4): in-app, with the finding title and the
// outcome, never the justification or the reason of a rejection. Not told
// when they left or can no longer read the finding, and not about their own
// withdrawal; another organization's members are never reached.
func TestFindingApprovals_RequesterToldOfDecision_DB(t *testing.T) {
	rec := &approvalNoticeRecorder{}
	h := newFindingApprovalHarness(t, withDataScope, func(svc *finding.VulnerabilityService, _ *handler.VulnerabilityHandler, db *postgres.DB) {
		svc.SetApprovalNotifier(postgres.NewScopeActorRepository(db), rec, rec, "https://console.example.com")
		svc.SetAssigneeChecker(postgres.NewAccessControlRepository(db))
	})
	org := h.tenantWithFindings()
	h.member(org, "owner")
	admin := h.member(org, "admin")
	requester := h.member(org, "member")
	h.customRoleMember(requester, org, permission.FindingsWrite, permission.FindingsRead)
	h.mintToken(&requester, org)

	scoped := func(title string) (string, string) {
		f, asset := h.scopedFinding(org)
		h.exec(`UPDATE findings SET status = 'confirmed', title = $2 WHERE id = $1`, f, title)
		h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`, requester.id, org, asset)
		return f, asset
	}
	toRequester := func() []notificationdom.NotificationParams {
		var out []notificationdom.NotificationParams
		for _, p := range rec.inApp {
			if p.AudienceID != nil && p.AudienceID.String() == requester.id && strings.HasPrefix(p.Title, "Your ") {
				out = append(out, p)
			}
		}
		return out
	}

	// Approved.
	f1, _ := scoped("Approved finding title")
	a1 := h.requestStatus(requester, f1, "false_positive")
	rec.reset()
	h.expect(admin, http.MethodPost, "/api/v1/approvals/"+a1+"/approve", "", http.StatusOK)
	got := toRequester()
	if len(got) != 1 || got[0].Title != "Your false positive request was approved" || got[0].Body != "Approved finding title" ||
		got[0].NotificationType != notificationdom.TypeFindingApproval || got[0].URL != "/findings/"+f1 {
		t.Fatalf("approved notice: %+v", got)
	}
	if strings.Contains(got[0].Body+got[0].Title, "the input is a constant") {
		t.Fatalf("the notice carries the justification: %+v", got[0])
	}

	// Rejected: the reason stays out of the notice.
	f2, _ := scoped("Rejected finding title")
	a2 := h.requestStatus(requester, f2, "accepted")
	rec.reset()
	h.expect(admin, http.MethodPost, "/api/v1/approvals/"+a2+"/reject", `{"reason":"SECRET-REJECT-REASON"}`, http.StatusOK)
	got = toRequester()
	if len(got) != 1 || got[0].Title != "Your accepted risk request was rejected" || strings.Contains(got[0].Body+got[0].Title, "SECRET-REJECT-REASON") {
		t.Fatalf("rejected notice: %+v", got)
	}

	// A requester who can no longer read the finding is not told, and neither
	// is anyone else on their behalf.
	f3, asset3 := scoped("Out of sight finding title")
	a3 := h.requestStatus(requester, f3, "false_positive")
	h.exec(`DELETE FROM user_accessible_assets WHERE user_id = $1 AND asset_id = $2`, requester.id, asset3)
	rec.reset()
	h.expect(admin, http.MethodPost, "/api/v1/approvals/"+a3+"/approve", "", http.StatusOK)
	if got := toRequester(); len(got) != 0 {
		t.Fatalf("requester without scope was told: %+v", got)
	}
	for _, p := range rec.inApp {
		if strings.Contains(p.Body, "Out of sight finding title") {
			t.Fatalf("a notice names a finding outside the requester's scope: %+v", p)
		}
	}

	// A requester who left is not told.
	f4, _ := scoped("Left finding title")
	a4 := h.requestStatus(requester, f4, "false_positive")
	h.exec(`UPDATE tenant_members SET status = 'suspended', suspended_at = now() WHERE tenant_id = $1 AND user_id = $2`, org, requester.id)
	rec.reset()
	h.expect(admin, http.MethodPost, "/api/v1/approvals/"+a4+"/reject", `{"reason":"gone"}`, http.StatusOK)
	if got := toRequester(); len(got) != 0 {
		t.Fatalf("suspended requester was told: %+v", got)
	}
	h.exec(`UPDATE tenant_members SET status = 'active', suspended_at = NULL WHERE tenant_id = $1 AND user_id = $2`, org, requester.id)

	// The requester's own withdrawal tells nobody.
	f5, _ := scoped("Withdrawn finding title")
	a5 := h.requestStatus(requester, f5, "false_positive")
	rec.reset()
	h.expect(requester, http.MethodPost, "/api/v1/approvals/"+a5+"/cancel", "", http.StatusOK)
	if got := toRequester(); len(got) != 0 {
		t.Fatalf("withdrawal produced a decision notice: %+v", got)
	}
	if recipients := rec.recipients(); slices.Contains(recipients, requester.id) {
		t.Fatalf("recipients after a withdrawal: %v", recipients)
	}
}
