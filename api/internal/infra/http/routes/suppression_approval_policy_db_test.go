package routes

// Suppression rules under the approval policy
// (api/docs/rfcs/RFC-111-approval-policy.md): a rule needs a reason code and
// a note; its tier is that of the worst open finding it matches; asset
// owners of matched findings never approve; security and dual tiers need
// step-up; a dual rule needs two approvers; an edit voids earlier
// sign-offs; another organization reaches nothing.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/suppression"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type rulePolicyHarness struct {
	*authzPolicyHarness
	stepUp *approverStepUp
}

func newRulePolicyHarness(t *testing.T) *rulePolicyHarness {
	gate := &approverStepUp{}
	changeAuditExtraHandlers = func(hs *Handlers, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		vuln := finding.NewVulnerabilityService(postgres.NewVulnerabilityRepository(db), postgres.NewFindingRepository(db), log)
		vuln.SetApprovalRepository(postgres.NewFindingApprovalRepository(db))
		vuln.SetSoloApproval(postgres.NewScopeActorRepository(db), nil, ts)
		repo := postgres.NewSuppressionRepository(db)
		svc := suppression.NewService(repo, log)
		svc.SetApproverDirectory(repo)
		svc.SetApprovalPolicy(finding.NewRulePolicyEvaluator(vuln, repo))
		svc.SetStepUpGate(gate)
		sh := handler.NewSuppressionHandler(svc, log)
		sh.SetAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log))
		hs.Suppression = sh
	}
	t.Cleanup(func() { changeAuditExtraHandlers = nil })
	return &rulePolicyHarness{authzPolicyHarness: newChangeAuditHarness(t), stepUp: gate}
}

func (h *rulePolicyHarness) org() string {
	id := h.tenant()
	h.t.Cleanup(func() {
		for _, q := range []string{
			`DELETE FROM finding_suppressions WHERE suppression_rule_id IN (SELECT id FROM suppression_rules WHERE tenant_id = $1)`,
			`DELETE FROM suppression_rule_audit WHERE suppression_rule_id IN (SELECT id FROM suppression_rules WHERE tenant_id = $1)`,
			`DELETE FROM suppression_rules WHERE tenant_id = $1`,
			`DELETE FROM finding_activities WHERE tenant_id = $1`,
			`DELETE FROM findings WHERE tenant_id = $1`,
		} {
			_, _ = h.db.ExecContext(context.Background(), q, id)
		}
	})
	return id
}

// matchedFinding inserts an open semgrep finding of rule ruleID on a new
// asset; it answers the finding and asset ids.
func (h *rulePolicyHarness) matchedFinding(tenantID, ruleID, severity string) (string, string) {
	h.t.Helper()
	f, a := uuid.NewString(), uuid.NewString()
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'repository')`, a, tenantID, "repo-"+a[:8])
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, rule_id, file_path, message, severity, fingerprint, status)
	        VALUES ($1, $2, $3, 'sast', 'semgrep', $4, 'src/x.go', 'm', $5, $6, 'confirmed')`, f, tenantID, a, ruleID, severity, "fp-"+f)
	return f, a
}

type ruleOut struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	UpdatedAt string `json:"updated_at"`
	Tier      string `json:"tier"`
	Required  int    `json:"approvals_required"`
	Collected int    `json:"approvals_collected"`
	Reason    string `json:"reason_code"`
}

func (h *rulePolicyHarness) createRule(u policyUser, typ, reason, ruleID string, want int) ruleOut {
	h.t.Helper()
	body := `{"name":"rule ` + ruleID + `","suppression_type":"` + typ + `","reason_code":"` + reason +
		`","description":"the matched code is generated test scaffolding","tool_name":"semgrep","rule_id":"` + ruleID +
		`","expires_at":"` + time.Now().UTC().Add(20*24*time.Hour).Format(time.RFC3339) + `"}`
	resp := h.expect(u, http.MethodPost, "/api/v1/suppressions", body, want)
	var out ruleOut
	if want == http.StatusCreated {
		_ = json.Unmarshal([]byte(resp), &out)
	}
	return out
}

func (h *rulePolicyHarness) getRule(u policyUser, id string) ruleOut {
	h.t.Helper()
	var out ruleOut
	_ = json.Unmarshal([]byte(h.expect(u, http.MethodGet, "/api/v1/suppressions/"+id, "", http.StatusOK)), &out)
	return out
}

func (h *rulePolicyHarness) approveRule(u policyUser, id string, want int) (ruleOut, string) {
	h.t.Helper()
	cur := h.getRule(u, id)
	resp := h.expect(u, http.MethodPost, "/api/v1/suppressions/"+id+"/approve", `{"reviewed_updated_at":"`+cur.UpdatedAt+`"}`, want)
	var out ruleOut
	if want == http.StatusOK {
		_ = json.Unmarshal([]byte(resp), &out)
	}
	return out, resp
}

func TestRulePolicy_ReasonCodeAndNote_DB(t *testing.T) {
	h := newRulePolicyHarness(t)
	org := h.org()
	admin := h.member(org, "admin")
	h.createRule(admin, "false_positive", "", "go.a", http.StatusBadRequest)
	h.createRule(admin, "false_positive", "risk_accepted", "go.a", http.StatusBadRequest) // a code of the other type
	h.createRule(admin, "accepted_risk", "test_or_example_code", "go.a", http.StatusBadRequest)
	h.expect(admin, http.MethodPost, "/api/v1/suppressions",
		`{"name":"n","suppression_type":"false_positive","reason_code":"detection_error","tool_name":"semgrep","rule_id":"go.a"}`, http.StatusBadRequest)
	if r := h.createRule(admin, "wont_fix", "wont_fix", "go.a", http.StatusCreated); r.Reason != "wont_fix" || r.Tier != "peer" {
		t.Fatalf("created rule: %+v", r)
	}
}

// A false-positive rule matching a critical finding is the security tier
// (step-up); the owner of the matched finding's asset may not approve.
func TestRulePolicy_TierByWorstMatchAndOwners_DB(t *testing.T) {
	h := newRulePolicyHarness(t)
	org := h.org()
	requester, owner, approver := h.member(org, "admin"), h.member(org, "admin"), h.member(org, "admin")
	low, _ := h.matchedFinding(org, "go.mixed", "low")
	crit, asset := h.matchedFinding(org, "go.mixed", "critical")
	h.exec(`INSERT INTO asset_owners (asset_id, user_id, ownership_type) VALUES ($1, $2, 'primary')`, asset, owner.id)
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM asset_owners WHERE asset_id = $1`, asset)
	})

	r := h.createRule(requester, "false_positive", "test_or_example_code", "go.mixed", http.StatusCreated)
	if r.Tier != "security" || r.Required != 1 {
		t.Fatalf("rule over a critical finding: %+v", r)
	}
	_, body := h.approveRule(owner, r.ID, http.StatusForbidden)
	if code, reason := refusalReason(t, body); code != "APPROVER_NOT_ELIGIBLE" || reason != "asset_owner" {
		t.Fatalf("owner approval: %s", body)
	}
	h.stepUp.refuse.Store(true)
	_, body = h.approveRule(approver, r.ID, http.StatusForbidden)
	if code, _ := refusalReason(t, body); code != "STEP_UP_REQUIRED" {
		t.Fatalf("approval without step-up: %s", body)
	}
	h.stepUp.refuse.Store(false)
	if out, _ := h.approveRule(approver, r.ID, http.StatusOK); out.Status != "approved" {
		t.Fatalf("approval: %+v", out)
	}
	for _, f := range []string{low, crit} {
		var st string
		_ = h.db.QueryRowContext(context.Background(), `SELECT status FROM findings WHERE id = $1`, f).Scan(&st)
		if st != "false_positive" {
			t.Fatalf("matched finding %s: %s", f, st)
		}
	}
	if n := countAudit(h.authzPolicyHarness, org, "suppression_rule.approval_refused"); n != 1 {
		t.Fatalf("refusal audited %d times", n)
	}

	// A rule matching only low findings is peer, without step-up.
	h.matchedFinding(org, "go.low", "low")
	lowRule := h.createRule(requester, "false_positive", "detection_error", "go.low", http.StatusCreated)
	if lowRule.Tier != "peer" {
		t.Fatalf("low rule tier %s", lowRule.Tier)
	}
	h.stepUp.refuse.Store(true)
	if out, _ := h.approveRule(approver, lowRule.ID, http.StatusOK); out.Status != "approved" {
		t.Fatal("a peer rule asked for step-up")
	}
	h.stepUp.refuse.Store(false)
}

// An accepted-risk rule over a critical finding needs two approvers; an
// edit after the first sign-off voids it; a sign-off by the same person
// twice is refused; another organization reaches nothing.
func TestRulePolicy_DualAndEditVoidsSignoffs_DB(t *testing.T) {
	h := newRulePolicyHarness(t)
	org, other := h.org(), h.org()
	requester, a1, a2 := h.member(org, "admin"), h.member(org, "admin"), h.member(org, "admin")
	outsider := h.member(other, "owner")
	h.matchedFinding(org, "go.kev", "critical")

	r := h.createRule(requester, "accepted_risk", "compensating_control", "go.kev", http.StatusCreated)
	if r.Tier != "dual" || r.Required != 2 {
		t.Fatalf("accepted-risk rule over a critical finding: %+v", r)
	}
	h.expect(outsider, http.MethodPost, "/api/v1/suppressions/"+r.ID+"/approve", `{"reviewed_updated_at":"`+r.UpdatedAt+`"}`, http.StatusNotFound)

	if out, _ := h.approveRule(a1, r.ID, http.StatusOK); out.Status != "pending" || out.Collected != 1 {
		t.Fatalf("first sign-off: %+v", out)
	}
	_, body := h.approveRule(a1, r.ID, http.StatusForbidden)
	if _, reason := refusalReason(t, body); reason != "already_signed" {
		t.Fatalf("second sign-off by the same person: %s", body)
	}
	// An edit voids the earlier sign-off.
	cur := h.getRule(requester, r.ID)
	h.expect(requester, http.MethodPut, "/api/v1/suppressions/"+r.ID, `{"description":"the matched code is generated test scaffolding (edited)"}`, http.StatusOK)
	if after := h.getRule(requester, r.ID); after.Collected != 0 || after.UpdatedAt == cur.UpdatedAt {
		t.Fatalf("after an edit: %+v", after)
	}
	if out, _ := h.approveRule(a2, r.ID, http.StatusOK); out.Status != "pending" {
		t.Fatalf("one sign-off after the edit applied the rule: %+v", out)
	}
	if out, _ := h.approveRule(a1, r.ID, http.StatusOK); out.Status != "approved" {
		t.Fatalf("two sign-offs after the edit: %+v", out)
	}
	if n := countAudit(h.authzPolicyHarness, org, "suppression_rule.signed"); n != 2 {
		t.Fatalf("partial sign-offs audited: %d", n)
	}
}

func countAudit(h *authzPolicyHarness, tenantID, action string) int {
	h.t.Helper()
	var n int
	if err := h.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = $2`, tenantID, action).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}
