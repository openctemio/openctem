package routes

// The organization's risk acceptance approval level (accept_approval: all,
// high_and_above, off; api/docs/architecture/finding-status-lifecycle.md,
// "Approval levels"): level gating on the request path, the 24-hour wait on a
// lowering, no bulk, group or automation path, the approvals digest entry,
// the material-change review flag and the sole member's own approval.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func newAcceptPolicyHarness(t *testing.T, rec *approvalNoticeRecorder,
	extra ...func(*finding.VulnerabilityService, *handler.VulnerabilityHandler, *postgres.DB),
) *findingApprovalHarness {
	return newFindingApprovalHarness(t, append(extra, func(svc *finding.VulnerabilityService, vh *handler.VulnerabilityHandler, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		actors := postgres.NewScopeActorRepository(db)
		svc.SetSoloApproval(actors, nil, ts)
		if rec != nil {
			svc.SetApprovalNotifier(actors, rec, rec, "https://console.example.com")
		}
		vh.SetFindingApprovalSettings(ts)
	})...)
}

type acceptOut struct {
	ID           string  `json:"id"`
	Status       string  `json:"status"`
	SinglePerson bool    `json:"single_person"`
	ExpiresAt    *string `json:"expires_at"`
}

// requestAcceptance posts an accepted-risk request ending in 30 days.
func requestAcceptance(h *findingApprovalHarness, u policyUser, findingID string) acceptOut {
	h.t.Helper()
	end := time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339)
	body := `{"requested_status":"accepted","closure_reason":"risk_accepted","justification":"compensating control in place","expires_at":"` + end + `"}`
	var out acceptOut
	if err := json.Unmarshal([]byte(h.expect(u, http.MethodPost, "/api/v1/findings/"+findingID+"/approvals/", body, http.StatusCreated)), &out); err != nil {
		h.t.Fatal(err)
	}
	return out
}

// Each level against each kind of finding: all (default) always needs a
// second person; high_and_above lets one person accept a finding that is not
// material and never a critical, high, KEV, P0/P1, validated, crown-jewel or
// internet-exposed one; off lets one person accept any. Only a holder of
// findings:approve decides alone; the acceptance still ends within the cap,
// is marked single_person, audited and on the timeline; the false-positive
// level is independent; another organization's level never applies.
func TestFindingAcceptPolicy_LevelsGateAcceptance_DB(t *testing.T) {
	h := newAcceptPolicyHarness(t, nil)
	org, other := h.tenantWithFindings(), h.tenantWithFindings()
	admin := h.member(org, "admin")
	writer := h.member(org, "member")
	h.customRoleMember(writer, org, permission.FindingsWrite, permission.FindingsRead)
	h.mintToken(&writer, org)
	setFPLevel(h, other, `{"accept_approval":"off"}`)

	cases := []struct {
		level  string
		single map[string]bool
	}{
		{"", map[string]bool{"critical": false, "high": false, "medium": false, "low": false}},
		{`{"accept_approval":"all","fp_approval":"off"}`, map[string]bool{"critical": false, "high": false, "medium": false, "low": false}},
		{`{"accept_approval":"high_and_above"}`, map[string]bool{"critical": false, "high": false, "medium": true, "low": true}},
		{`{"accept_approval":"off"}`, map[string]bool{"critical": true, "high": true, "medium": true, "low": true}},
	}
	for _, c := range cases {
		if c.level != "" {
			setFPLevel(h, org, c.level)
		}
		for sev, want := range c.single {
			f := h.newFinding(org, sev)
			got := requestAcceptance(h, admin, f)
			if got.SinglePerson != want || (want && got.Status != "approved") || (!want && got.Status != "pending") {
				t.Fatalf("level %s, %s: %+v, want single %v", c.level, sev, got, want)
			}
			wantFinding := "confirmed"
			if want {
				wantFinding = "accepted"
				if got.ExpiresAt == nil {
					t.Fatalf("level %s, %s: a single-person acceptance has no end", c.level, sev)
				}
				var end time.Time
				if err := h.db.QueryRowContext(context.Background(), `SELECT acceptance_expires_at FROM findings WHERE id = $1`, f).Scan(&end); err != nil {
					t.Fatalf("acceptance end on the finding: %v", err)
				}
				if time.Until(end) > 31*24*time.Hour || time.Until(end) < 29*24*time.Hour {
					t.Fatalf("acceptance end %v", end)
				}
			}
			if s := findingStatusOf(h, f); s != wantFinding {
				t.Fatalf("level %s, %s: finding %s, want %s", c.level, sev, s, wantFinding)
			}
		}
	}

	// high_and_above: a medium finding that is material still needs a second person.
	setFPLevel(h, org, `{"accept_approval":"high_and_above"}`)
	for _, q := range []string{
		`UPDATE findings SET is_in_kev = true WHERE id = $1`,
		`UPDATE findings SET priority_class = 'P1' WHERE id = $1`,
		`UPDATE findings SET validation_outcome = 'reproducible' WHERE id = $1`,
	} {
		f := h.newFinding(org, "medium")
		h.exec(q, f)
		if got := requestAcceptance(h, admin, f); got.Status != "pending" {
			t.Fatalf("%s: a material finding was accepted alone", q)
		}
	}
	for _, q := range []string{
		`UPDATE assets SET is_crown_jewel = true WHERE id = $1`,
		`UPDATE assets SET is_internet_accessible = true WHERE id = $1`,
	} {
		f, asset := h.scopedFinding(org)
		h.exec(`UPDATE findings SET severity = 'low', status = 'confirmed' WHERE id = $1`, f)
		h.exec(q, asset)
		if got := requestAcceptance(h, admin, f); got.Status != "pending" {
			t.Fatalf("%s: a finding on such an asset was accepted alone", q)
		}
	}

	// off: a member without findings:approve still needs a second person, and
	// the false-positive level (all) still applies to false positives.
	setFPLevel(h, org, `{"accept_approval":"off"}`)
	f := h.newFinding(org, "low")
	if got := requestAcceptance(h, writer, f); got.Status != "pending" {
		t.Fatal("a member without findings:approve accepted a risk alone")
	}
	fp := h.newFinding(org, "low")
	if status, _, _ := requestFP(h, admin, fp); status != "pending" {
		t.Fatal("the risk acceptance level decided a false positive")
	}
	// The policy endpoint says the same as the request path.
	var pol struct {
		AcceptApproval string `json:"accept_approval"`
		CanDecideAlone bool   `json:"can_decide_alone"`
		Evaluation     struct {
			Tier string `json:"tier"`
		} `json:"evaluation"`
	}
	f2 := h.newFinding(org, "critical")
	_ = json.Unmarshal([]byte(h.expect(admin, http.MethodGet, "/api/v1/findings/"+f2+"/approvals/policy?status=accepted", "", http.StatusOK)), &pol)
	if pol.AcceptApproval != "off" || !pol.CanDecideAlone || pol.Evaluation.Tier != "single" {
		t.Fatalf("policy under off: %+v", pol)
	}

	// The other organization's level ("off") does not reach this one.
	setFPLevel(h, org, `{"accept_approval":"all"}`)
	if got := requestAcceptance(h, admin, h.newFinding(org, "low")); got.Status != "pending" {
		t.Fatal("another organization's level applied")
	}
	otherOwner := h.member(other, "owner")
	h.expect(otherOwner, http.MethodGet, "/api/v1/findings/"+f2+"/approvals/policy?status=accepted", "", http.StatusNotFound)

	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.single_person_decided'`, org); n == 0 {
		t.Fatal("single-person acceptances are not audited")
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_activities WHERE tenant_id = $1 AND activity_type = 'approval_approved'
		AND changes->>'single_person' = 'true' AND changes ? 'accept_approval' AND changes ? 'acceptance_end'`, org); n == 0 {
		t.Fatal("single-person acceptances are not on the timeline with their level and end")
	}
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action LIKE 'finding_approval.%'`, other); n != 0 {
		t.Fatalf("rows leaked into the other organization: %d", n)
	}
}

// Lowering the risk acceptance level through the API (PATCH) waits 24 hours,
// shown in the response; raising is immediate and cancels the wait. Only an
// owner or administrator may change it (a custom role with settings:write
// may not), every change is audited at high severity, and the approvers
// (owners and administrators among them) are told of a lowering.
func TestFindingAcceptPolicy_LoweringWaits24Hours_DB(t *testing.T) {
	rec := &approvalNoticeRecorder{}
	h := newAcceptPolicyHarness(t, rec)
	org := h.tenantWithFindings()
	owner, admin := h.member(org, "owner"), h.member(org, "admin")
	settingsWriter := h.member(org, "member")
	h.customRoleMember(settingsWriter, org, permission.SettingsWrite, permission.SettingsRead, permission.FindingsRead, permission.FindingsApprove)
	h.mintToken(&settingsWriter, org)
	const url = "/api/v1/organization/settings/finding-approvals/"

	h.expect(settingsWriter, http.MethodPatch, url, `{"accept_approval":"off"}`, http.StatusForbidden)
	h.expect(owner, http.MethodPatch, url, `{"accept_approval":"sometimes"}`, http.StatusUnprocessableEntity)

	var got struct {
		AcceptApproval string  `json:"accept_approval"`
		FPApproval     string  `json:"fp_approval"`
		Pending        string  `json:"pending_accept_approval"`
		PendingAt      *string `json:"pending_accept_approval_at"`
	}
	rec.reset()
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodPatch, url, `{"accept_approval":"off"}`, http.StatusOK)), &got)
	if got.AcceptApproval != "all" || got.Pending != "off" || got.PendingAt == nil || got.FPApproval != "all" {
		t.Fatalf("lowering: %+v", got)
	}
	at, _ := time.Parse(time.RFC3339, *got.PendingAt)
	if d := time.Until(at); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("a lowering takes effect in %v, want 24 hours", d)
	}
	told := false
	for _, p := range rec.inApp {
		if p.AudienceID != nil && p.AudienceID.String() == admin.id && strings.Contains(p.Body, "risk acceptance approval level") {
			told = true
		}
		if p.AudienceID != nil && p.AudienceID.String() == owner.id {
			t.Fatal("the administrator who made the change was told about it")
		}
	}
	if !told {
		t.Fatalf("the other administrator was not told: %+v", rec.inApp)
	}
	// Not yet in force.
	if r := requestAcceptance(h, owner, h.newFinding(org, "low")); r.Status != "pending" {
		t.Fatal("a lowering took effect before 24 hours")
	}
	// 24 hours later it is in force.
	h.exec(`UPDATE tenants SET settings = jsonb_set(settings, '{finding_approvals,pending_accept_approval_at}', to_jsonb(to_char((now() - interval '1 minute') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))) WHERE id = $1`, org)
	if r := requestAcceptance(h, owner, h.newFinding(org, "low")); r.Status != "approved" || !r.SinglePerson {
		t.Fatalf("after 24 hours: %+v", r)
	}
	// Raising is immediate.
	got.Pending, got.PendingAt = "", nil
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodPatch, url, `{"accept_approval":"all"}`, http.StatusOK)), &got)
	if got.AcceptApproval != "all" || got.Pending != "" {
		t.Fatalf("raising: %+v", got)
	}
	if r := requestAcceptance(h, owner, h.newFinding(org, "low")); r.Status != "pending" {
		t.Fatal("raising the level was not immediate")
	}
	// A lowering canceled within the 24 hours never takes effect.
	h.expect(owner, http.MethodPatch, url, `{"accept_approval":"high_and_above"}`, http.StatusOK)
	got.Pending = ""
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodPatch, url, `{"cancel_pending":true}`, http.StatusOK)), &got)
	if got.Pending != "" || got.AcceptApproval != "all" {
		t.Fatalf("a canceled lowering is still pending: %+v", got)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.settings_changed'
		AND severity IN ('high', 'critical') AND changes IS NOT NULL`, org); n < 4 {
		t.Fatalf("settings changes audited at high or critical: %d", n)
	}
	// Each lowering (two people to one) is audited critical.
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.settings_changed'
		AND severity = 'critical' AND metadata->>'loosened' = 'true'`, org); n < 2 {
		t.Fatalf("lowerings audited critical: %d", n)
	}
}

// No bypass: under off, a bulk status move to accepted is refused and a
// group exception over a remediation task still waits for its approvers.
func TestFindingAcceptPolicy_NoBulkOrGroupPath_DB(t *testing.T) {
	h := newGroupExceptionHarness(t)
	org := h.org()
	requester := h.member(org, "admin")
	h.member(org, "admin")
	setFPLevel(h.findingApprovalHarness, org, `{"accept_approval":"off"}`)

	bulk := h.newFinding(org, "low")
	code, _ := h.do(requester, http.MethodPost, "/api/v1/findings/bulk/status",
		`{"finding_ids":["`+bulk+`"],"status":"accepted","resolution":"bulk acceptance"}`)
	if code == http.StatusOK && findingStatusOf(h.findingApprovalHarness, bulk) == "accepted" {
		t.Fatal("a bulk move accepted a risk under off")
	}
	if s := findingStatusOf(h.findingApprovalHarness, bulk); s != "confirmed" {
		t.Fatalf("bulk move left the finding %s", s)
	}

	low, _ := h.findingOnAsset(org, "low")
	medium, _ := h.findingOnAsset(org, "medium")
	task := h.task(org, low, medium)
	var b batchOut
	_ = json.Unmarshal([]byte(h.expect(requester, http.MethodPost, "/api/v1/remediation/tasks/"+task+"/exception", h.acceptBodyAt(task, 30), http.StatusCreated)), &b)
	if b.Status != "pending" || b.Tier == "single" || b.Required < 1 {
		t.Fatalf("group exception under off: %+v", b)
	}
	for _, f := range []string{low, medium} {
		if s := findingStatusOf(h.findingApprovalHarness, f); s == "accepted" {
			t.Fatal("a group exception accepted a risk without a second person")
		}
	}
}

// A single-person acceptance is in the next approvals digest of every other
// approver who can see the finding (not of the person who decided), and a
// later material change (severity up, KEV added, new evidence) raises a
// review flag on it; an acceptance a second person approved gets no such
// flag from the triggers.
func TestFindingAcceptPolicy_DigestAndMaterialChange_DB(t *testing.T) {
	rec := &approvalNoticeRecorder{}
	h := newAcceptPolicyHarness(t, rec, withDataScope)
	org := h.tenantWithFindings()
	owner, admin := h.member(org, "owner"), h.member(org, "admin")
	h.t.Cleanup(func() {
		ctx := context.Background()
		_, _ = h.db.ExecContext(ctx, `DELETE FROM finding_decision_reviews WHERE tenant_id = $1`, org)
		_, _ = h.db.ExecContext(ctx, `DELETE FROM finding_evidence WHERE tenant_id = $1`, org)
		_, _ = h.db.ExecContext(ctx, `DELETE FROM finding_approval_digest_sent WHERE tenant_id = $1`, org)
	})
	setFPLevel(h, org, `{"accept_approval":"off"}`)

	sev := h.newFinding(org, "low")
	h.exec(`UPDATE findings SET title = 'single person acceptance ' || id::text WHERE id = $1`, sev)
	if r := requestAcceptance(h, admin, sev); r.Status != "approved" {
		t.Fatal("not decided alone")
	}

	rec.reset()
	if _, err := h.svc.SendApprovalDigests(context.Background()); err != nil {
		t.Fatal(err)
	}
	var ownerDigest, adminDigest string
	for _, p := range rec.inApp {
		if p.NotificationType != notificationdom.TypeFindingApprovalDigest || p.TenantID.String() != org || p.AudienceID == nil {
			continue
		}
		switch p.AudienceID.String() {
		case owner.id:
			ownerDigest = p.Title + " " + p.Body
		case admin.id:
			adminDigest = p.Title + " " + p.Body
		}
	}
	if !strings.Contains(ownerDigest, "one person") || !strings.Contains(ownerDigest, sev) {
		t.Fatalf("the other approver's digest does not name the decision: %q", ownerDigest)
	}
	if adminDigest != "" {
		t.Fatalf("the person who decided got their own decision in a digest: %q", adminDigest)
	}

	flags := func(findingID string) int {
		return h.countRows(`SELECT COUNT(*) FROM finding_decision_reviews WHERE finding_id = $1 AND decision_status = 'accepted'
			AND reason = 'material_change_single_person' AND cleared_at IS NULL`, findingID)
	}
	h.exec(`UPDATE findings SET severity = 'critical' WHERE id = $1`, sev)
	if flags(sev) != 1 {
		t.Fatal("severity raised: no review flag")
	}
	if findingStatusOf(h, sev) != "accepted" {
		t.Fatal("the review flag reversed the decision")
	}
	kev := h.newFinding(org, "low")
	requestAcceptance(h, admin, kev)
	h.exec(`UPDATE findings SET is_in_kev = true WHERE id = $1`, kev)
	if flags(kev) != 1 {
		t.Fatal("KEV added: no review flag")
	}
	ev := h.newFinding(org, "low")
	requestAcceptance(h, admin, ev)
	h.exec(`INSERT INTO finding_evidence (tenant_id, finding_id, origin, kind, content, content_sha256)
		VALUES ($1, $2, 'detection', 'http_exchange', '{}'::jsonb, 'sha256:x')`, org, ev)
	if flags(ev) != 1 {
		t.Fatal("new evidence: no review flag")
	}

	// Four-eyes acceptance: no trigger flag.
	setFPLevel(h, org, `{"accept_approval":"all"}`)
	fe := h.newFinding(org, "low")
	r := requestAcceptance(h, admin, fe)
	h.expect(owner, http.MethodPost, "/api/v1/approvals/"+r.ID+"/approve", "", http.StatusOK)
	h.exec(`UPDATE findings SET severity = 'critical' WHERE id = $1`, fe)
	if flags(fe) != 0 {
		t.Fatal("a four-eyes acceptance was flagged by the triggers")
	}
}

// The sole member of an organization: under the default level an accepted
// risk stays pending (refused before any code is spent); under
// high_and_above a material acceptance (which waits for a second person)
// can be approved by its requester with an authenticator code, and its end
// is cut to the self-approval limit; under off it still waits for that
// self-approval (nobody else would ever see a risk the only member accepts
// alone), while a member of a larger organization decides alone under off.
func TestFindingAcceptPolicy_SoleMemberNotBlocked_DB(t *testing.T) {
	h := newSoloHarness(t)
	org := h.tenantWithFindings()
	owner := h.member(org, "owner")
	end := time.Now().Add(120 * 24 * time.Hour)

	f := h.newFinding(org, "high")
	a := h.requestAccept(owner, f, end)
	h.selfApprove(owner, a, "111111", http.StatusForbidden)
	if !h.codes.valid["111111"] {
		t.Fatal("an authenticator code was spent on a refused acceptance")
	}

	setFPLevel(h.findingApprovalHarness, org, `{"accept_approval":"high_and_above"}`)
	out := h.selfApprove(owner, a, "111111", http.StatusOK)
	if out["status"] != "approved" || out["end_shortened"] != true {
		t.Fatalf("self-approval under high_and_above: %+v", out)
	}
	if findingStatusOf(h.findingApprovalHarness, f) != "accepted" {
		t.Fatal("the finding was not accepted")
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE id = $1 AND self_approved
		AND expires_at <= now() + interval '91 days'`, a); n != 1 {
		t.Fatal("the self-approved acceptance was not cut to the self-approval limit")
	}

	setFPLevel(h.findingApprovalHarness, org, `{"accept_approval":"off"}`)
	f2 := h.newFinding(org, "critical")
	var r acceptOut
	body := `{"requested_status":"accepted","closure_reason":"no_fix_available","justification":"vendor patch next quarter","expires_at":"` +
		end.UTC().Format(time.RFC3339) + `"}`
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodPost, "/api/v1/findings/"+f2+"/approvals/", body, http.StatusCreated)), &r)
	if r.Status != "pending" || r.SinglePerson {
		t.Fatalf("sole member under off accepted a risk alone without an authenticator code: %+v", r)
	}
	var pol struct {
		CanDecideAlone bool `json:"can_decide_alone"`
	}
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodGet, "/api/v1/findings/"+h.newFinding(org, "low")+"/approvals/policy?status=accepted", "", http.StatusOK)), &pol)
	if pol.CanDecideAlone {
		t.Fatal("the policy endpoint tells the only member an acceptance applies at once")
	}
	if findingStatusOf(h.findingApprovalHarness, f2) != "confirmed" {
		t.Fatal("the sole member's acceptance applied before the self-approval")
	}
	out = h.selfApprove(owner, r.ID, "222222", http.StatusOK)
	if out["status"] != "approved" || out["end_shortened"] != true {
		t.Fatalf("self-approval under off: %+v", out)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE id = $1 AND self_approved
		AND expires_at <= now() + interval '91 days'`, r.ID); n != 1 {
		t.Fatal("the sole member's acceptance under off was not cut to the self-approval limit")
	}
	// Once a second person is active, the level lets a member decide alone.
	h.member(org, "admin")
	f3 := h.newFinding(org, "critical")
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodPost, "/api/v1/findings/"+f3+"/approvals/", body, http.StatusCreated)), &r)
	if r.Status != "approved" || !r.SinglePerson {
		t.Fatalf("a member of a two-person organization under off: %+v", r)
	}
}
