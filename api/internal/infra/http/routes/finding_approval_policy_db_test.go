package routes

// Route tests of the approval policy on finding requests
// (api/docs/rfcs/RFC-111-approval-policy.md): tiers by risk, two approvers,
// step-up, asset owners excluded, the security pool, the organization's
// policy (tightening at once, relaxing after 24 hours, never below the
// floor), actor requests, and tenant isolation.

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// approverStepUp answers step-up checks as passed unless refuse is set.
type approverStepUp struct{ refuse atomic.Bool }

func (g *approverStepUp) RequireRecentAuth(context.Context, string) error {
	if g.refuse.Load() {
		return middleware.ErrStepUpRequired
	}
	return nil
}

type approvalPolicyHarness struct {
	*findingApprovalHarness
	stepUp *approverStepUp
}

func newApprovalPolicyHarness(t *testing.T) *approvalPolicyHarness {
	gate := &approverStepUp{}
	h := newFindingApprovalHarness(t, func(svc *finding.VulnerabilityService, vh *handler.VulnerabilityHandler, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		actors := postgres.NewScopeActorRepository(db)
		svc.SetSoloApproval(actors, nil, ts)
		svc.SetApprovalNotifier(actors, nil, nil, "")
		svc.SetStepUpGate(gate)
		vh.SetFindingApprovalSettings(ts)
	})
	return &approvalPolicyHarness{findingApprovalHarness: h, stepUp: gate}
}

// findingOnAsset inserts a confirmed finding of severity on a new asset and
// answers both ids.
func (h *approvalPolicyHarness) findingOnAsset(tenantID, severity string) (findingID, assetID string) {
	h.t.Helper()
	findingID, assetID = uuid.NewString(), uuid.NewString()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'domain')`, assetID, tenantID, "ap-"+assetID[:8]+".example")
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
	        VALUES ($1, $2, $3, 'sast', 'approval-policy', 'm', $4, $5, 'confirmed')`, findingID, tenantID, assetID, severity, "fp-"+findingID)
	return findingID, assetID
}

func (h *approvalPolicyHarness) group(tenantID string, members ...policyUser) string {
	h.t.Helper()
	id := uuid.NewString()
	h.exec(`INSERT INTO groups (id, tenant_id, name, slug, group_type) VALUES ($1, $2, $3, $3, 'security_team')`, id, tenantID, "sec-"+id[:8])
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM group_members WHERE group_id = $1`, id)
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM groups WHERE id = $1`, id)
	})
	for _, m := range members {
		// Long-standing members: a person added less than a day ago does not
		// count as the pool's.
		h.exec(`INSERT INTO group_members (group_id, user_id, joined_at) VALUES ($1, $2, now() - interval '48 hours')`, id, m.id)
	}
	return id
}

type approvalOut struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Tier      string `json:"tier"`
	Required  int    `json:"approvals_required"`
	Collected int    `json:"approvals_collected"`
}

func (h *approvalPolicyHarness) requestAccept(u policyUser, findingID string) approvalOut {
	h.t.Helper()
	var out approvalOut
	body := `{"requested_status":"accepted","closure_reason":"compensating_control","justification":"WAF rule 9412 blocks the vulnerable path"}`
	if err := json.Unmarshal([]byte(h.expect(u, http.MethodPost, "/api/v1/findings/"+findingID+"/approvals/", body, http.StatusCreated)), &out); err != nil {
		h.t.Fatal(err)
	}
	return out
}

func (h *approvalPolicyHarness) approve(u policyUser, approvalID string, want int) (approvalOut, string) {
	h.t.Helper()
	resp := h.expect(u, http.MethodPost, "/api/v1/approvals/"+approvalID+"/approve", "", want)
	var out approvalOut
	if want == http.StatusOK {
		if err := json.Unmarshal([]byte(resp), &out); err != nil {
			h.t.Fatal(err)
		}
	}
	return out, resp
}

func refusalReason(t *testing.T, body string) (code, reason string) {
	t.Helper()
	var e struct {
		Code    string            `json:"code"`
		Details map[string]string `json:"details"`
	}
	_ = json.Unmarshal([]byte(body), &e)
	return e.Code, e.Details["reason"]
}

// A critical finding's acceptance needs two approvers (dual): the first
// sign-off leaves it pending, the same person cannot sign twice, the second
// applies it. A medium finding's acceptance needs one. The timeline and the
// audit log record each sign-off.
func TestApprovalPolicy_DualForCriticalAcceptance_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org := h.tenantWithFindings()
	requester := h.member(org, "member")
	h.customRoleMember(requester, org, permission.FindingsWrite, permission.FindingsRead)
	h.mintToken(&requester, org)
	a1, a2 := h.member(org, "admin"), h.member(org, "admin")

	crit, _ := h.findingOnAsset(org, "critical")
	req := h.requestAccept(requester, crit)
	if req.Status != "pending" || req.Tier != "dual" || req.Required != 2 {
		t.Fatalf("critical acceptance request: %+v", req)
	}
	first, _ := h.approve(a1, req.ID, http.StatusOK)
	if first.Status != "pending" || first.Collected != 1 || first.Required != 2 {
		t.Fatalf("after one sign-off: %+v", first)
	}
	if findingStatusOf(h.findingApprovalHarness, crit) != "confirmed" {
		t.Fatal("one sign-off applied a dual request")
	}
	_, body := h.approve(a1, req.ID, http.StatusForbidden)
	if code, reason := refusalReason(t, body); code != "APPROVER_NOT_ELIGIBLE" || reason != "already_signed" {
		t.Fatalf("second sign-off by the same person: %s %s", code, reason)
	}
	second, _ := h.approve(a2, req.ID, http.StatusOK)
	if second.Status != "approved" || findingStatusOf(h.findingApprovalHarness, crit) != "accepted" {
		t.Fatalf("after two sign-offs: %+v", second)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM approval_signoffs WHERE tenant_id = $1 AND subject_id = $2`, org, req.ID); n != 2 {
		t.Fatalf("sign-offs recorded: %d", n)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'approval_signed'`, crit); n != 1 {
		t.Fatalf("approval_signed timeline entries: %d", n)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.signed'`, org); n != 1 {
		t.Fatalf("finding_approval.signed audit rows: %d", n)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_status_approvals WHERE id = $1 AND decision_facts->>'severity' = 'critical'`, req.ID); n != 1 {
		t.Fatal("the decision facts were not stored")
	}

	// A KEV low finding is critical too.
	kev, _ := h.findingOnAsset(org, "low")
	h.exec(`UPDATE findings SET is_in_kev = true WHERE id = $1`, kev)
	if r := h.requestAccept(requester, kev); r.Tier != "dual" {
		t.Fatalf("KEV acceptance tier %s", r.Tier)
	}
	// A medium finding's acceptance needs one other person.
	med, _ := h.findingOnAsset(org, "medium")
	r := h.requestAccept(requester, med)
	if r.Tier != "peer" || r.Required != 1 {
		t.Fatalf("medium acceptance: %+v", r)
	}
	if out, _ := h.approve(a1, r.ID, http.StatusOK); out.Status != "approved" {
		t.Fatalf("medium acceptance after one approval: %+v", out)
	}
}

// Security and dual tiers need the approver's recent re-authentication;
// without it the approval is refused with STEP_UP_REQUIRED and nothing is
// recorded. A peer tier does not ask for it.
func TestApprovalPolicy_StepUpByTier_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org := h.tenantWithFindings()
	requester := h.member(org, "admin")
	approver := h.member(org, "admin")
	high, _ := h.findingOnAsset(org, "high")
	req := h.requestAccept(requester, high)
	if req.Tier != "security" {
		t.Fatalf("high acceptance tier %s", req.Tier)
	}
	h.stepUp.refuse.Store(true)
	_, body := h.approve(approver, req.ID, http.StatusForbidden)
	if code, _ := refusalReason(t, body); code != "STEP_UP_REQUIRED" {
		t.Fatalf("security approval without step-up: %s", body)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM approval_signoffs WHERE subject_id = $1`, req.ID); n != 0 {
		t.Fatal("a refused approval was recorded")
	}
	low, _ := h.findingOnAsset(org, "low")
	lowReq := h.requestAccept(requester, low)
	if out, _ := h.approve(approver, lowReq.ID, http.StatusOK); out.Status != "approved" {
		t.Fatal("a peer approval asked for step-up")
	}
	h.stepUp.refuse.Store(false)
	if out, _ := h.approve(approver, req.ID, http.StatusOK); out.Status != "approved" {
		t.Fatal("security approval with step-up failed")
	}
}

// The owners of a finding's asset never approve its decisions, directly or
// through an owner group, and never decide a false positive alone even when
// the organization's level would let them.
func TestApprovalPolicy_AssetOwnerExcluded_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org := h.tenantWithFindings()
	requester := h.member(org, "admin")
	owner, groupOwner, other := h.member(org, "admin"), h.member(org, "admin"), h.member(org, "admin")
	f, asset := h.findingOnAsset(org, "medium")
	h.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type) VALUES ($1, $2, 'primary')`, asset, owner.id)
	g := h.group(org, groupOwner)
	h.exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'secondary')`, asset, g)
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM asset_owners WHERE asset_id = $1`, asset)
	})

	req := h.requestAccept(requester, f)
	for _, u := range []policyUser{owner, groupOwner} {
		_, body := h.approve(u, req.ID, http.StatusForbidden)
		if code, reason := refusalReason(t, body); code != "APPROVER_NOT_ELIGIBLE" || reason != "asset_owner" {
			t.Fatalf("asset owner approval: %s", body)
		}
	}
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.approval_refused'`, org); n != 2 {
		t.Fatalf("refusals audited: %d", n)
	}
	if out, _ := h.approve(other, req.ID, http.StatusOK); out.Status != "approved" {
		t.Fatal("an independent approver could not approve")
	}

	// Level off: the owner's own false positive still needs a second person.
	setFPLevel(h.findingApprovalHarness, org, `{"fp_approval":"off"}`)
	f2, asset2 := h.findingOnAsset(org, "low")
	h.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type) VALUES ($1, $2, 'primary')`, asset2, owner.id)
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM asset_owners WHERE asset_id = $1`, asset2)
	})
	if status, single, _ := requestFP(h.findingApprovalHarness, owner, f2); status != "pending" || single {
		t.Fatalf("asset owner decided a false positive alone: %s %v", status, single)
	}
	f3, _ := h.findingOnAsset(org, "low")
	if status, single, _ := requestFP(h.findingApprovalHarness, other, f3); status != "approved" || !single {
		t.Fatalf("a non-owner under level off: %s %v", status, single)
	}
}

// With a security pool, a security-tier approval must come from the pool;
// an approver outside it is refused. A dual request needs one pool member
// among its two approvers.
func TestApprovalPolicy_SecurityPool_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org := h.tenantWithFindings()
	owner := h.member(org, "owner")
	requester, outsider, outsider2, sec := h.member(org, "admin"), h.member(org, "admin"), h.member(org, "admin"), h.member(org, "admin")
	g := h.group(org, sec)
	h.expect(owner, http.MethodPut, "/api/v1/organization/settings/finding-approvals/",
		`{"policy":{"security_pool_group_id":"`+g+`"}}`, http.StatusOK)

	high, _ := h.findingOnAsset(org, "high")
	req := h.requestAccept(requester, high)
	_, body := h.approve(outsider, req.ID, http.StatusForbidden)
	if _, reason := refusalReason(t, body); reason != "not_in_security_pool" {
		t.Fatalf("approver outside the pool: %s", body)
	}
	if out, _ := h.approve(sec, req.ID, http.StatusOK); out.Status != "approved" {
		t.Fatal("pool member could not approve")
	}
	if n := h.countRows(`SELECT COUNT(*) FROM approval_signoffs WHERE subject_id = $1 AND security_pool AND NOT pool_fallback`, req.ID); n != 1 {
		t.Fatal("the pool sign-off was not recorded as such")
	}

	crit, _ := h.findingOnAsset(org, "critical")
	dual := h.requestAccept(requester, crit)
	if out, _ := h.approve(outsider, dual.ID, http.StatusOK); out.Status != "pending" {
		t.Fatal("first non-pool sign-off of a dual request")
	}
	_, body = h.approve(outsider2, dual.ID, http.StatusForbidden)
	if _, reason := refusalReason(t, body); reason != "not_in_security_pool" {
		t.Fatalf("second non-pool sign-off: %s", body)
	}
	if out, _ := h.approve(sec, dual.ID, http.StatusOK); out.Status != "approved" {
		t.Fatal("pool member completing a dual request")
	}
}

// A two-person organization cannot complete a dual request: the approval
// answers 409 NO_ELIGIBLE_APPROVER. Relaxing critical acceptances to the
// floor (security) waits 24 hours; once in force one approver suffices.
func TestApprovalPolicy_PolicyChanges_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org, other := h.tenantWithFindings(), h.tenantWithFindings()
	owner, admin := h.member(org, "owner"), h.member(org, "admin")
	const url = "/api/v1/organization/settings/finding-approvals/"

	crit, _ := h.findingOnAsset(org, "critical")
	req := h.requestAccept(admin, crit)
	_, body := h.approve(owner, req.ID, http.StatusConflict)
	if code, _ := refusalReason(t, body); code != "NO_ELIGIBLE_APPROVER" {
		t.Fatalf("dual in a two-person organization: %s", body)
	}

	// Below the floor: refused.
	h.expect(owner, http.MethodPut, url, `{"policy":{"tiers":{"accepted.high":"peer"}}}`, http.StatusBadRequest)
	// A group of another organization: refused.
	foreign := h.group(other)
	h.expect(owner, http.MethodPut, url, `{"policy":{"security_pool_group_id":"`+foreign+`"}}`, http.StatusBadRequest)

	// Relaxing: pending for 24 hours, the stricter policy applies meanwhile.
	var got struct {
		Policy          struct{ Tiers map[string]string }  `json:"policy"`
		PendingPolicy   *struct{ Tiers map[string]string } `json:"pending_policy"`
		PendingPolicyAt *string                            `json:"pending_policy_at"`
		Floors          map[string]string                  `json:"floors"`
	}
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodPut, url, `{"policy":{"tiers":{"accepted.critical":"security"}}}`, http.StatusOK)), &got)
	if got.PendingPolicy == nil || got.PendingPolicy.Tiers["accepted.critical"] != "security" || got.PendingPolicyAt == nil {
		t.Fatalf("relaxation not pending: %+v", got)
	}
	if got.Floors["accepted.critical"] != "security" || got.Floors["accepted.standard"] != "peer" {
		t.Fatalf("floors: %v", got.Floors)
	}
	crit2, _ := h.findingOnAsset(org, "critical")
	if r := h.requestAccept(admin, crit2); r.Tier != "dual" {
		t.Fatalf("relaxation applied before 24 hours: %s", r.Tier)
	}
	h.exec(`UPDATE tenants SET settings = jsonb_set(settings, '{finding_approvals,pending_policy_at}', to_jsonb(to_char((now() - interval '1 minute') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))) WHERE id = $1`, org)
	crit3, _ := h.findingOnAsset(org, "critical")
	r := h.requestAccept(admin, crit3)
	if r.Tier != "security" {
		t.Fatalf("relaxation after 24 hours: %s", r.Tier)
	}
	if out, _ := h.approve(owner, r.ID, http.StatusOK); out.Status != "approved" {
		t.Fatal("one approver under the relaxed policy")
	}

	// Tightening is immediate: medium acceptances to dual.
	h.expect(owner, http.MethodPut, url, `{"policy":{"tiers":{"accepted.critical":"security","accepted.standard":"dual"}}}`, http.StatusOK)
	med, _ := h.findingOnAsset(org, "medium")
	if r := h.requestAccept(admin, med); r.Tier != "dual" {
		t.Fatalf("tightening not immediate: %s", r.Tier)
	}
	// The other organization keeps the defaults.
	otherAdmin := h.member(other, "admin")
	om, _ := h.findingOnAsset(other, "medium")
	if r := h.requestAccept(otherAdmin, om); r.Tier != "peer" {
		t.Fatalf("another organization's policy applied: %s", r.Tier)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.settings_changed'`, org); n < 2 {
		t.Fatalf("policy changes audited: %d", n)
	}
}

// The policy endpoint explains the decision (tier, approvers, step-up,
// cap); another organization gets 404 for the finding and its approvals.
func TestApprovalPolicy_EvaluationAndIsolation_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org, other := h.tenantWithFindings(), h.tenantWithFindings()
	admin := h.member(org, "admin")
	_ = h.member(org, "admin")
	outsider := h.member(other, "owner")
	crit, _ := h.findingOnAsset(org, "critical")
	var pol struct {
		Evaluation struct {
			Tier              string   `json:"tier"`
			Required          int      `json:"approvals_required"`
			StepUp            bool     `json:"step_up"`
			MaxAcceptanceDays int      `json:"max_acceptance_days"`
			Reasons           []string `json:"reasons"`
			Satisfiable       bool     `json:"satisfiable"`
		} `json:"evaluation"`
	}
	_ = json.Unmarshal([]byte(h.expect(admin, http.MethodGet, "/api/v1/findings/"+crit+"/approvals/policy?status=accepted", "", http.StatusOK)), &pol)
	if pol.Evaluation.Tier != "dual" || pol.Evaluation.Required != 2 || !pol.Evaluation.StepUp || pol.Evaluation.MaxAcceptanceDays != 365 {
		t.Fatalf("evaluation: %+v", pol.Evaluation)
	}
	h.expect(outsider, http.MethodGet, "/api/v1/findings/"+crit+"/approvals/policy?status=accepted", "", http.StatusNotFound)
	h.expect(admin, http.MethodGet, "/api/v1/findings/"+crit+"/approvals/policy?status=resolved", "", http.StatusBadRequest)

	req := h.requestAccept(admin, crit)
	h.expect(outsider, http.MethodPost, "/api/v1/approvals/"+req.ID+"/approve", "", http.StatusNotFound)
	if n := h.countRows(`SELECT COUNT(*) FROM approval_signoffs WHERE subject_id = $1`, req.ID); n != 0 {
		t.Fatal("another organization signed off")
	}
}

// Bypass attempts: a direct status change and a bulk status change to
// accepted or false positive are refused; a VEX (actor) request on a
// critical finding is evaluated as dual at decision time, so one approver
// does not apply it.
func TestApprovalPolicy_Bypasses_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org := h.tenantWithFindings()
	admin, a2, a3 := h.member(org, "admin"), h.member(org, "admin"), h.member(org, "admin")
	crit, _ := h.findingOnAsset(org, "critical")

	for _, st := range []string{"accepted", "false_positive"} {
		code, _ := h.do(admin, http.MethodPatch, "/api/v1/findings/"+crit+"/status", `{"status":"`+st+`","closure_reason":"risk_accepted","resolution":"x"}`)
		if code < 400 {
			t.Fatalf("PATCH /status to %s answered %d", st, code)
		}
	}
	if findingStatusOf(h.findingApprovalHarness, crit) != "confirmed" {
		t.Fatal("a direct status change hid the finding")
	}

	vexID := uuid.NewString()
	h.exec(`INSERT INTO finding_status_approvals (id, tenant_id, finding_id, requested_status, requested_by_actor, justification, status, closure_reason)
	        VALUES ($1, $2, $3, 'false_positive', 'vex', 'vendor statement: not affected', 'pending', 'component_not_present')`, vexID, org, crit)
	setFPLevel(h.findingApprovalHarness, org, `{"policy":{"tiers":{"false_positive.critical":"dual"}}}`)
	// An actor-made request needs one sign-off more than the tier asks:
	// dual (2) + 1.
	a4 := h.member(org, "admin")
	if out, _ := h.approve(a2, vexID, http.StatusOK); out.Status != "pending" || out.Collected != 1 {
		t.Fatalf("one approval applied a dual VEX request: %+v", out)
	}
	if out, _ := h.approve(a3, vexID, http.StatusOK); out.Status != "pending" || out.Collected != 2 {
		t.Fatalf("two approvals applied an actor-made dual request: %+v", out)
	}
	if out, _ := h.approve(a4, vexID, http.StatusOK); out.Status != "approved" {
		t.Fatal("three approvals did not apply the VEX request")
	}
	_ = admin
}

// A request a ticket (or VEX, or AI triage) makes has no person behind it, so
// the person who moved the ticket could otherwise approve it alone: it needs
// one sign-off more than the same request made by a person (peer: two).
func TestApprovalPolicy_ActorRequestNeedsAnExtraSignoff_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org := h.tenantWithFindings()
	a1, a2 := h.member(org, "admin"), h.member(org, "admin")
	medium, _ := h.findingOnAsset(org, "medium")
	id := uuid.NewString()
	h.exec(`INSERT INTO finding_status_approvals (id, tenant_id, finding_id, requested_status, requested_by_actor, justification, status, closure_reason, expires_at)
	        VALUES ($1, $2, $3, 'accepted', 'ticket', 'jira SEC-1 was closed without a fix', 'pending', 'risk_accepted', now() + interval '30 days')`, id, org, medium)
	if out, _ := h.approve(a1, id, http.StatusOK); out.Status != "pending" || out.Required != 2 {
		t.Fatalf("one approver completed a ticket's request: %+v", out)
	}
	if out, _ := h.approve(a2, id, http.StatusOK); out.Status != "approved" {
		t.Fatal("two approvers did not apply the ticket's request")
	}
}

// Pool membership is read when someone signs: a person added to the security
// pool group less than 24 hours ago does not count as the pool's. With a
// strict pool nobody else may stand in, so the request waits.
func TestApprovalPolicy_FreshPoolMemberDoesNotCount_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org := h.tenantWithFindings()
	owner := h.member(org, "owner")
	requester, sec := h.member(org, "admin"), h.member(org, "admin")
	g := h.group(org)
	h.exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)`, g, sec.id) // joined now
	h.expect(owner, http.MethodPut, "/api/v1/organization/settings/finding-approvals/",
		`{"policy":{"security_pool_group_id":"`+g+`","security_pool_strict":true}}`, http.StatusOK)

	high, _ := h.findingOnAsset(org, "high")
	req := h.requestAccept(requester, high)
	_, body := h.approve(sec, req.ID, http.StatusConflict)
	if code, _ := refusalReason(t, body); code != "NO_ELIGIBLE_APPROVER" {
		t.Fatalf("a pool member added a moment ago signed: %s", body)
	}
	h.exec(`UPDATE group_members SET joined_at = now() - interval '25 hours' WHERE group_id = $1 AND user_id = $2`, g, sec.id)
	if out, _ := h.approve(sec, req.ID, http.StatusOK); out.Status != "approved" {
		t.Fatal("a pool member of more than a day could not sign")
	}
}

// Two approvers signing a dual request at the same moment: the request row
// is locked, so it is applied exactly once with both sign-offs.
func TestApprovalPolicy_ConcurrentSignoffs_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org := h.tenantWithFindings()
	requester, a1, a2 := h.member(org, "admin"), h.member(org, "admin"), h.member(org, "admin")
	for i := 0; i < 5; i++ {
		crit, _ := h.findingOnAsset(org, "critical")
		req := h.requestAccept(requester, crit)
		codes := make(chan int, 2)
		for _, u := range []policyUser{a1, a2} {
			go func(u policyUser) {
				code, _ := h.do(u, http.MethodPost, "/api/v1/approvals/"+req.ID+"/approve", "")
				codes <- code
			}(u)
		}
		c1, c2 := <-codes, <-codes
		// Both succeed, or one loses the race on the version (409) and may
		// retry; never a lost sign-off with the request still pending.
		if c1 != http.StatusOK && c2 != http.StatusOK {
			t.Fatalf("round %d: both sign-offs failed (%d, %d)", i, c1, c2)
		}
		if c1 != http.StatusOK || c2 != http.StatusOK {
			loser := a1
			if c1 == http.StatusOK {
				loser = a2
			}
			h.approve(loser, req.ID, http.StatusOK)
		}
		if findingStatusOf(h.findingApprovalHarness, crit) != "accepted" {
			t.Fatalf("round %d: not applied after two sign-offs", i)
		}
		if n := h.countRows(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'approval_approved'`, crit); n != 1 {
			t.Fatalf("round %d: applied %d times", i, n)
		}
		if n := h.countRows(`SELECT COUNT(*) FROM approval_signoffs WHERE subject_id = $1`, req.ID); n != 2 {
			t.Fatalf("round %d: %d sign-offs", i, n)
		}
	}
}

// A ticket's request to accept a risk ends within the organization's cap for
// the finding, not only the platform's: with 7 days set for standard
// findings, the proposed end is at most 7 days away.
func TestApprovalPolicy_TicketRequestEndFollowsTheOrganizationCap_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org := h.tenantWithFindings()
	owner := h.member(org, "owner")
	h.expect(owner, http.MethodPut, "/api/v1/organization/settings/finding-approvals/",
		`{"policy":{"max_acceptance_days":{"standard":7}}}`, http.StatusOK)
	low, _ := h.findingOnAsset(org, "low")
	tid, err := shared.IDFromString(org)
	if err != nil {
		t.Fatal(err)
	}
	fid, _ := shared.IDFromString(low)
	out, err := h.svc.RequestTicketDisposition(context.Background(), tid, []shared.ID{fid}, vulnerability.FindingStatusAccepted, "jira", "SEC-9", "acct-1")
	if err != nil || len(out.Requested) != 1 {
		t.Fatalf("request: %v %+v", err, out)
	}
	var days float64
	if err := h.db.QueryRowContext(context.Background(),
		`SELECT EXTRACT(EPOCH FROM (expires_at - now())) / 86400 FROM finding_status_approvals WHERE finding_id = $1`, low).Scan(&days); err != nil {
		t.Fatal(err)
	}
	if days > 7.01 || days < 6 {
		t.Fatalf("the proposed end is %.2f days away; the organization's cap is 7", days)
	}
}

// PUT cancel_pending drops a waiting lowering of the false-positive level and
// keeps the level in force; it needs settings:write like any change.
func TestApprovalSettings_CancelPending_DB(t *testing.T) {
	h := newApprovalPolicyHarness(t)
	org := h.tenantWithFindings()
	owner, member := h.member(org, "owner"), h.member(org, "member")
	const path = "/api/v1/organization/settings/finding-approvals/"
	h.expect(owner, http.MethodPut, path, `{"fp_approval":"off"}`, http.StatusOK)
	var st struct {
		FPApproval        string `json:"fp_approval"`
		PendingFPApproval string `json:"pending_fp_approval"`
	}
	read := func() {
		st.FPApproval, st.PendingFPApproval = "", ""
		if err := json.Unmarshal([]byte(h.expect(owner, http.MethodGet, path, "", http.StatusOK)), &st); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if st.PendingFPApproval != "off" || st.FPApproval != "all" {
		t.Fatalf("lowering did not wait: %+v", st)
	}
	if code, _ := h.do(member, http.MethodPut, path, `{"cancel_pending":true}`); code != http.StatusForbidden {
		t.Fatalf("a member canceled a change: %d", code)
	}
	h.expect(owner, http.MethodPut, path, `{"cancel_pending":true}`, http.StatusOK)
	read()
	if st.PendingFPApproval != "" || st.FPApproval != "all" {
		t.Fatalf("pending change not canceled: %+v", st)
	}
}
