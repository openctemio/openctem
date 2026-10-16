package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// approvalNoticeRecorder records in-app notices and emails to approvers.
type approvalNoticeRecorder struct {
	mu     sync.Mutex
	inApp  []notificationdom.NotificationParams
	emails [][]string
	bodies []string
}

func (r *approvalNoticeRecorder) Notify(_ context.Context, p notificationdom.NotificationParams) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inApp = append(r.inApp, p)
	return nil
}

func (r *approvalNoticeRecorder) SendFindingApprovalMail(_ context.Context, _ string, to []string, _, body string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.emails = append(r.emails, slices.Clone(to))
	r.bodies = append(r.bodies, body)
}

func (r *approvalNoticeRecorder) reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.inApp, r.emails, r.bodies = nil, nil, nil
}

func (r *approvalNoticeRecorder) recipients() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []string{}
	for _, p := range r.inApp {
		out = append(out, p.AudienceID.String())
	}
	slices.Sort(out)
	return out
}

// withDataScope wires the data-scope enforcer as in cmd/server (the caller
// from the request context).
func withDataScope(svc *finding.VulnerabilityService, _ *handler.VulnerabilityHandler, db *postgres.DB) {
	svc.SetDataScope(datascope.New(postgres.NewDataScopeRepository(db),
		func(ctx context.Context) datascope.Caller {
			return datascope.Caller{UserID: middleware.GetUserID(ctx), IsAdmin: middleware.IsAdmin(ctx)}
		}, logger.NewNop()))
}

func emailOf(u policyUser) string { return "authzpol-" + u.id[:8] + "@it.test" }

// A new request notifies, in-app and by email, exactly the members who may
// decide it: approvers (owner, admin, a custom role with findings:approve)
// whose data scope holds the finding, never the requester, never an approver
// outside the finding's scope, never another organization. The email names
// the finding but not the justification. Reminders go to the same people, at
// most once an hour, and are audited.
func TestFindingApprovals_NotifyEligibleApprovers_DB(t *testing.T) {
	rec := &approvalNoticeRecorder{}
	h := newFindingApprovalHarness(t, withDataScope, func(svc *finding.VulnerabilityService, _ *handler.VulnerabilityHandler, db *postgres.DB) {
		svc.SetApprovalNotifier(postgres.NewScopeActorRepository(db), rec, rec, "https://console.example.com")
	})
	org, other := h.tenantWithFindings(), h.tenantWithFindings()
	owner, admin := h.member(org, "owner"), h.member(org, "admin")
	inScope, outOfScope, requester := h.member(org, "member"), h.member(org, "member"), h.member(org, "member")
	otherOwner := h.member(other, "owner")
	h.customRoleMember(inScope, org, permission.FindingsApprove, permission.FindingsRead)
	h.customRoleMember(outOfScope, org, permission.FindingsApprove, permission.FindingsRead)
	h.customRoleMember(requester, org, permission.FindingsWrite, permission.FindingsRead)
	for _, u := range []*policyUser{&inScope, &outOfScope, &requester} {
		h.mintToken(u, org)
	}
	fid, asset := h.scopedFinding(org)
	h.exec(`UPDATE findings SET status = 'confirmed' WHERE id = $1`, fid)
	for _, u := range []policyUser{inScope, requester} {
		h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`, u.id, org, asset)
	}

	a := h.requestStatus(requester, fid, "false_positive")
	want := []string{owner.id, admin.id, inScope.id}
	slices.Sort(want)
	if got := rec.recipients(); !slices.Equal(got, want) {
		t.Fatalf("in-app recipients %v, want %v (owner, admin, in-scope approver)", got, want)
	}
	for _, p := range rec.inApp {
		if p.NotificationType != notificationdom.TypeFindingApproval || p.TenantID.String() != org || p.URL != "/findings/approvals" {
			t.Fatalf("notice: %+v", p)
		}
	}
	if len(rec.emails) != 1 {
		t.Fatalf("emails: %v", rec.emails)
	}
	gotMail := rec.emails[0]
	slices.Sort(gotMail)
	wantMail := []string{emailOf(owner), emailOf(admin), emailOf(inScope)}
	slices.Sort(wantMail)
	if !slices.Equal(gotMail, wantMail) {
		t.Fatalf("email recipients %v, want %v", gotMail, wantMail)
	}
	if strings.Contains(rec.bodies[0], "the input is a constant") || !strings.Contains(rec.bodies[0], "https://console.example.com/findings/approvals") {
		t.Fatalf("email body: %s", rec.bodies[0])
	}

	// Reminders: the same people, once an hour, audited; another
	// organization reaches nothing.
	rec.reset()
	h.expect(otherOwner, http.MethodPost, "/api/v1/approvals/"+a+"/remind", "", http.StatusNotFound)
	var out struct {
		Reminded int `json:"reminded"`
	}
	if err := json.Unmarshal([]byte(h.expect(requester, http.MethodPost, "/api/v1/approvals/"+a+"/remind", "", http.StatusOK)), &out); err != nil || out.Reminded != 3 {
		t.Fatalf("remind: %+v %v", out, err)
	}
	if got := rec.recipients(); !slices.Equal(got, want) {
		t.Fatalf("reminder recipients %v, want %v", got, want)
	}
	h.expect(requester, http.MethodPost, "/api/v1/approvals/"+a+"/remind", "", http.StatusConflict)
	requireAudited(t, h.auditRows(org, "finding_approval.reminded"), a, []auditRow{{action: "finding_approval.reminded", actor: requester.id}})

	// An approver who requests is never told about their own request.
	rec.reset()
	f2, asset2 := h.scopedFinding(org)
	h.exec(`UPDATE findings SET status = 'confirmed' WHERE id = $1`, f2)
	_ = asset2
	h.requestStatus(admin, f2, "accepted")
	if got := rec.recipients(); slices.Contains(got, admin.id) || !slices.Contains(got, owner.id) || slices.Contains(got, inScope.id) {
		t.Fatalf("recipients of the admin's request: %v (admin excluded, owner included, approver without scope excluded)", got)
	}

	// An AI triage proposal (requested by nobody) notifies every eligible approver.
	rec.reset()
	f3, asset3 := h.scopedFinding(org)
	h.exec(`UPDATE findings SET status = 'confirmed', severity = 'medium' WHERE id = $1`, f3)
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`, inScope.id, org, asset3)
	ok, err := h.svc.ProposeFalsePositiveFromAI(context.Background(), shared.MustIDFromString(org), shared.MustIDFromString(f3), 0.95, "a test fixture")
	if err != nil || !ok {
		t.Fatalf("AI proposal: %v %v", ok, err)
	}
	if got := rec.recipients(); !slices.Equal(got, want) {
		t.Fatalf("AI proposal recipients %v, want %v", got, want)
	}
}

// Requests made by VEX statements are announced from the outbox (the
// requests table), off the ingest path: once per tenant and approver per
// run, counting and naming only the findings in that approver's data scope;
// an approver who can see none is not told, another organization's members
// never are, and a claimed request is never announced twice.
func TestFindingApprovals_VEXRequestsBatchedPerApprover_DB(t *testing.T) {
	rec := &approvalNoticeRecorder{}
	h := newFindingApprovalHarness(t, withDataScope, func(svc *finding.VulnerabilityService, _ *handler.VulnerabilityHandler, db *postgres.DB) {
		svc.SetApprovalNotifier(postgres.NewScopeActorRepository(db), rec, rec, "https://console.example.com")
	})
	org, other := h.tenantWithFindings(), h.tenantWithFindings()
	owner := h.member(org, "owner")
	scoped, blind := h.member(org, "member"), h.member(org, "member")
	otherOwner := h.member(other, "owner")
	h.customRoleMember(scoped, org, permission.FindingsApprove, permission.FindingsRead)
	h.customRoleMember(blind, org, permission.FindingsApprove, permission.FindingsRead)
	f1, a1 := h.scopedFinding(org)
	f2, _ := h.scopedFinding(org)
	f3, _ := h.scopedFinding(org)
	of, _ := h.scopedFinding(other)
	h.exec(`UPDATE findings SET title = 'finding ' || id::text WHERE tenant_id IN ($1, $2)`, org, other)
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`, scoped.id, org, a1)
	vex := func(tenant, findingID string) {
		h.exec(`INSERT INTO finding_status_approvals (tenant_id, finding_id, requested_status, requested_by_actor, justification, status)
			VALUES ($1, $2, 'false_positive', 'vex', 'not affected', 'pending')`, tenant, findingID)
	}
	for _, f := range []string{f1, f2, f3} {
		vex(org, f)
	}
	vex(other, of)

	n, err := h.svc.DispatchVEXRequestNotices(context.Background())
	if err != nil || n < 4 {
		t.Fatalf("dispatched %d (%v)", n, err)
	}
	got := map[string]string{}
	for _, p := range rec.inApp {
		got[p.AudienceID.String()] = p.Title
		if p.URL != "/findings/approvals" {
			t.Fatalf("notice: %+v", p)
		}
		if p.TenantID.String() == other && p.AudienceID.String() != otherOwner.id {
			t.Fatalf("another organization's request reached %s", p.AudienceID)
		}
	}
	if !strings.HasPrefix(got[owner.id], "3 ") || !strings.HasPrefix(got[scoped.id], "1 ") || !strings.HasPrefix(got[otherOwner.id], "1 ") {
		t.Fatalf("counts per approver: %v", got)
	}
	if _, told := got[blind.id]; told {
		t.Fatal("an approver who can see none of the findings was told")
	}
	for i, to := range rec.emails {
		if len(to) == 1 && to[0] == emailOf(scoped) {
			if !strings.Contains(rec.bodies[i], f1) || strings.Contains(rec.bodies[i], f2) || strings.Contains(rec.bodies[i], f3) {
				t.Fatalf("in-scope approver's email: %s", rec.bodies[i])
			}
		}
	}
	// Claimed once: the next run announces nothing.
	rec.reset()
	if n, err := h.svc.DispatchVEXRequestNotices(context.Background()); err != nil || n != 0 || len(rec.inApp) != 0 {
		t.Fatalf("second run: %d %v %d notices", n, err, len(rec.inApp))
	}
}

// Without a data-scope enforcer no finding counts as visible (fail closed):
// nobody is told rather than everybody.
func TestFindingApprovals_VEXNoticeFailsClosedWithoutScope_DB(t *testing.T) {
	rec := &approvalNoticeRecorder{}
	h := newFindingApprovalHarness(t, func(svc *finding.VulnerabilityService, _ *handler.VulnerabilityHandler, db *postgres.DB) {
		svc.SetApprovalNotifier(postgres.NewScopeActorRepository(db), rec, rec, "https://console.example.com")
	})
	org := h.tenantWithFindings()
	h.member(org, "owner")
	f, _ := h.scopedFinding(org)
	h.exec(`INSERT INTO finding_status_approvals (tenant_id, finding_id, requested_status, requested_by_actor, justification, status)
		VALUES ($1, $2, 'false_positive', 'vex', 'not affected', 'pending')`, org, f)
	if _, err := h.svc.DispatchVEXRequestNotices(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(rec.inApp) != 0 || len(rec.emails) != 0 {
		t.Fatalf("told %d in-app, %d emails without a scope check", len(rec.inApp), len(rec.emails))
	}
}
