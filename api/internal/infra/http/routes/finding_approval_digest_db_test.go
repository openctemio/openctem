package routes

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// The daily digest counts, per approver, only the requests they may decide
// (never their own, the finding in their data scope), names titles they can
// see, skips approvers with nothing to decide or who muted it, reaches no
// other organization, and goes at most once a day.
func TestFindingApprovals_DailyDigest_DB(t *testing.T) {
	rec := &approvalNoticeRecorder{}
	h := newFindingApprovalHarness(t, withDataScope, func(svc *finding.VulnerabilityService, _ *handler.VulnerabilityHandler, db *postgres.DB) {
		svc.SetApprovalNotifier(postgres.NewScopeActorRepository(db), rec, rec, "https://console.example.com")
		svc.SetApprovalDigestPreferences(postgres.NewNotificationRepository(db))
	})
	org, other := h.tenantWithFindings(), h.tenantWithFindings()
	h.t.Cleanup(func() {
		for _, id := range []string{org, other} {
			h.exec(`DELETE FROM finding_approval_digest_sent WHERE tenant_id = $1`, id)
			h.exec(`DELETE FROM notification_preferences WHERE tenant_id = $1`, id)
		}
	})
	owner, admin, muted := h.member(org, "owner"), h.member(org, "admin"), h.member(org, "admin")
	scoped, blind := h.member(org, "member"), h.member(org, "member")
	otherOwner := h.member(other, "owner")
	h.customRoleMember(scoped, org, permission.FindingsApprove, permission.FindingsRead)
	h.customRoleMember(blind, org, permission.FindingsApprove, permission.FindingsRead)
	h.exec(`INSERT INTO notification_preferences (tenant_id, user_id, muted_types) VALUES ($1, $2, $3::jsonb)`,
		org, muted.id, `["`+notificationdom.TypeFindingApprovalDigest+`"]`)

	f1, a1 := h.scopedFinding(org)
	f2, _ := h.scopedFinding(org)
	f3, _ := h.scopedFinding(org)
	h.exec(`UPDATE findings SET status = 'confirmed', title = 'title of ' || id::text WHERE tenant_id = $1`, org)
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`, scoped.id, org, a1)
	h.requestStatus(admin, f1, "false_positive")
	h.requestStatus(admin, f2, "false_positive")
	h.requestStatus(owner, f3, "accepted")
	of, _ := h.scopedFinding(other)
	h.exec(`UPDATE findings SET status = 'confirmed' WHERE id = $1`, of)
	h.requestStatus(otherOwner, of, "false_positive")

	rec.reset()
	n, err := h.svc.SendApprovalDigests(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range rec.inApp {
		if p.NotificationType != notificationdom.TypeFindingApprovalDigest || p.URL != "/findings/approvals" {
			t.Fatalf("notice: %+v", p)
		}
		if p.TenantID.String() == org {
			got[p.AudienceID.String()] = p.Title
		}
	}
	want := map[string]string{owner.id: "2 ", admin.id: "1 ", scoped.id: "1 "}
	for id, prefix := range want {
		if !strings.HasPrefix(got[id], prefix) {
			t.Fatalf("digest of %s: %q, want prefix %q (all: %v)", id, got[id], prefix, got)
		}
	}
	for _, id := range []string{blind.id, muted.id, otherOwner.id} {
		if _, told := got[id]; told {
			t.Fatalf("%s got a digest it should not", id)
		}
	}
	if n < 3 {
		t.Fatalf("digests sent %d", n)
	}
	// The in-scope approver's email names only the finding they can see.
	for i, to := range rec.emails {
		if len(to) == 1 && to[0] == emailOf(scoped) {
			if !strings.Contains(rec.bodies[i], f1) || strings.Contains(rec.bodies[i], f2) || strings.Contains(rec.bodies[i], f3) {
				t.Fatalf("scoped approver's digest: %s", rec.bodies[i])
			}
		}
	}
	// At most once a day.
	rec.reset()
	if n, err := h.svc.SendApprovalDigests(context.Background()); err != nil || n != 0 || len(rec.inApp) != 0 {
		t.Fatalf("second run sent %d (%v)", n, err)
	}
}
