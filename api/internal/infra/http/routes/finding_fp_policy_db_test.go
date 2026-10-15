package routes

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/app/finding"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/handler"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func newFPPolicyHarness(t *testing.T) *findingApprovalHarness {
	return newFindingApprovalHarness(t, func(svc *finding.VulnerabilityService, vh *handler.VulnerabilityHandler, db *postgres.DB) {
		log := logger.NewNop()
		ts := tenantapp.NewTenantService(postgres.NewTenantRepository(db), log,
			tenantapp.WithTenantAuditService(auditapp.NewAuditService(postgres.NewAuditRepository(db), log)))
		actors := postgres.NewScopeActorRepository(db)
		svc.SetSoloApproval(actors, nil, ts)
		vh.SetFindingApprovalSettings(ts)
	})
}

// setFPLevel writes the organization's level directly (a lowering through
// the API waits 24 hours; that rule has its own test).
func setFPLevel(h *findingApprovalHarness, tenantID, section string) {
	h.t.Helper()
	h.exec(`UPDATE tenants SET settings = jsonb_set(COALESCE(settings, '{}'::jsonb), '{finding_approvals}', $2::jsonb) WHERE id = $1`, tenantID, section)
}

// requestFP posts a false-positive request and answers the request's status
// ("approved" when decided alone, "pending" when a second person decides).
func requestFP(h *findingApprovalHarness, u policyUser, findingID string) (status string, singlePerson bool, id string) {
	h.t.Helper()
	body := `{"requested_status":"false_positive","closure_reason":"test_or_example_code","justification":"fixture used only by unit tests"}`
	var out struct {
		ID           string `json:"id"`
		Status       string `json:"status"`
		SinglePerson bool   `json:"single_person"`
	}
	if err := json.Unmarshal([]byte(h.expect(u, http.MethodPost, "/api/v1/findings/"+findingID+"/approvals/", body, http.StatusCreated)), &out); err != nil {
		h.t.Fatal(err)
	}
	return out.Status, out.SinglePerson, out.ID
}

func findingStatusOf(h *findingApprovalHarness, id string) string {
	h.t.Helper()
	var s string
	if err := h.db.QueryRowContext(context.Background(), `SELECT status FROM findings WHERE id = $1`, id).Scan(&s); err != nil {
		h.t.Fatal(err)
	}
	return s
}

// Each level against each severity: all (default) always needs a second
// person; high_and_above lets one person decide medium and low but never
// critical or high (nor KEV, P0/P1, a validated exploit, a crown-jewel or
// internet-exposed asset); off lets one person decide any. Only a holder of
// findings:approve may decide alone; an accepted risk always needs a second
// person; another organization's level never applies.
func TestFindingFPPolicy_LevelsBySeverity_DB(t *testing.T) {
	h := newFPPolicyHarness(t)
	org, other := h.tenantWithFindings(), h.tenantWithFindings()
	admin := h.member(org, "admin")
	writer := h.member(org, "member")
	h.customRoleMember(writer, org, permission.FindingsWrite, permission.FindingsRead)
	h.mintToken(&writer, org)
	setFPLevel(h, other, `{"fp_approval":"off"}`)

	cases := []struct {
		level  string
		single map[string]bool
	}{
		{"", map[string]bool{"critical": false, "high": false, "medium": false, "low": false}},
		{`{"fp_approval":"all"}`, map[string]bool{"critical": false, "high": false, "medium": false, "low": false}},
		{`{"fp_approval":"high_and_above"}`, map[string]bool{"critical": false, "high": false, "medium": true, "low": true}},
		{`{"fp_approval":"off"}`, map[string]bool{"critical": true, "high": true, "medium": true, "low": true}},
	}
	for _, c := range cases {
		if c.level != "" {
			setFPLevel(h, org, c.level)
		}
		for sev, want := range c.single {
			f := h.newFinding(org, sev)
			status, single, _ := requestFP(h, admin, f)
			if single != want || (want && status != "approved") || (!want && status != "pending") {
				t.Fatalf("level %s, %s: status %s single %v, want single %v", c.level, sev, status, single, want)
			}
			wantFinding := "confirmed"
			if want {
				wantFinding = "false_positive"
			}
			if got := findingStatusOf(h, f); got != wantFinding {
				t.Fatalf("level %s, %s: finding %s, want %s", c.level, sev, got, wantFinding)
			}
		}
	}

	// high_and_above: a medium finding that is material still needs a second person.
	setFPLevel(h, org, `{"fp_approval":"high_and_above"}`)
	for _, q := range []string{
		`UPDATE findings SET is_in_kev = true WHERE id = $1`,
		`UPDATE findings SET priority_class = 'P1' WHERE id = $1`,
		`UPDATE findings SET validation_outcome = 'reproducible' WHERE id = $1`,
	} {
		f := h.newFinding(org, "medium")
		h.exec(q, f)
		if status, _, _ := requestFP(h, admin, f); status != "pending" {
			t.Fatalf("%s: a material medium finding was decided alone", q)
		}
	}
	for _, q := range []string{
		`UPDATE assets SET is_crown_jewel = true WHERE id = $1`,
		`UPDATE assets SET is_internet_accessible = true WHERE id = $1`,
	} {
		f, asset := h.scopedFinding(org)
		h.exec(`UPDATE findings SET severity = 'low', status = 'confirmed' WHERE id = $1`, f)
		h.exec(q, asset)
		if status, _, _ := requestFP(h, admin, f); status != "pending" {
			t.Fatalf("%s: a finding on such an asset was decided alone", q)
		}
	}

	// off: a member without findings:approve still needs a second person.
	setFPLevel(h, org, `{"fp_approval":"off"}`)
	f := h.newFinding(org, "low")
	if status, _, _ := requestFP(h, writer, f); status != "pending" {
		t.Fatal("a member without findings:approve decided a false positive alone")
	}
	// off: an accepted risk is still four-eyes.
	fa := h.newFinding(org, "low")
	var acc struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal([]byte(h.expect(admin, http.MethodPost, "/api/v1/findings/"+fa+"/approvals/",
		`{"requested_status":"accepted","closure_reason":"risk_accepted","justification":"low impact"}`, http.StatusCreated)), &acc)
	if acc.Status != "pending" || findingStatusOf(h, fa) != "confirmed" {
		t.Fatalf("an accepted risk was decided alone: %+v", acc)
	}

	// The other organization's level ("off") does not reach this one.
	setFPLevel(h, org, `{"fp_approval":"all"}`)
	f2 := h.newFinding(org, "low")
	if status, _, _ := requestFP(h, admin, f2); status != "pending" {
		t.Fatal("another organization's level applied")
	}
	otherOwner := h.member(other, "owner")
	h.expect(otherOwner, http.MethodGet, "/api/v1/findings/"+f2+"/approvals/policy", "", http.StatusNotFound)

	// Audit: a single-person decision is its own audited action.
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.single_person_decided'`, org); n == 0 {
		t.Fatal("single-person decisions are not audited")
	}
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action LIKE 'finding_approval.%'`, other); n != 0 {
		t.Fatalf("rows leaked into the other organization: %d", n)
	}
}

// Lowering the level through the API waits 24 hours (shown in the response
// and the policy); raising it is immediate and cancels a pending lowering.
// The change needs settings:write, is audited with before and after.
func TestFindingFPPolicy_LoweringWaits24Hours_DB(t *testing.T) {
	h := newFPPolicyHarness(t)
	org := h.tenantWithFindings()
	owner := h.member(org, "owner")
	writer := h.member(org, "member")
	h.customRoleMember(writer, org, permission.FindingsWrite, permission.FindingsRead, permission.FindingsApprove)
	h.mintToken(&writer, org)
	const url = "/api/v1/organization/settings/finding-approvals/"

	h.expect(writer, http.MethodPut, url, `{"fp_approval":"off"}`, http.StatusForbidden)
	h.expect(owner, http.MethodPut, url, `{"fp_approval":"sometimes"}`, http.StatusUnprocessableEntity)

	var got struct {
		FPApproval string  `json:"fp_approval"`
		Pending    string  `json:"pending_fp_approval"`
		PendingAt  *string `json:"pending_fp_approval_at"`
	}
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodPut, url, `{"fp_approval":"off"}`, http.StatusOK)), &got)
	if got.FPApproval != "all" || got.Pending != "off" || got.PendingAt == nil {
		t.Fatalf("lowering: %+v", got)
	}
	at, _ := time.Parse(time.RFC3339, *got.PendingAt)
	if d := time.Until(at); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("a lowering takes effect in %v, want 24 hours", d)
	}
	// Not yet in force.
	f := h.newFinding(org, "low")
	if status, _, _ := requestFP(h, owner, f); status != "pending" {
		t.Fatal("a lowering took effect before 24 hours")
	}
	var pol struct {
		Single  bool   `json:"single_person"`
		Pending string `json:"pending_fp_approval"`
	}
	f2 := h.newFinding(org, "low")
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodGet, "/api/v1/findings/"+f2+"/approvals/policy", "", http.StatusOK)), &pol)
	if pol.Single || pol.Pending != "off" {
		t.Fatalf("policy before the delay: %+v", pol)
	}
	// 24 hours later it is in force.
	h.exec(`UPDATE tenants SET settings = jsonb_set(settings, '{finding_approvals,pending_fp_approval_at}', to_jsonb(to_char((now() - interval '1 minute') AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'))) WHERE id = $1`, org)
	if status, single, _ := requestFP(h, owner, f2); status != "approved" || !single {
		t.Fatalf("after 24 hours: %s %v", status, single)
	}
	// Raising is immediate.
	got.Pending, got.PendingAt = "", nil
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodPut, url, `{"fp_approval":"all"}`, http.StatusOK)), &got)
	if got.FPApproval != "all" || got.Pending != "" {
		t.Fatalf("raising: %+v", got)
	}
	f3 := h.newFinding(org, "low")
	if status, _, _ := requestFP(h, owner, f3); status != "pending" {
		t.Fatal("raising the level was not immediate")
	}
	// A lowering raised back within the 24 hours never takes effect.
	h.expect(owner, http.MethodPut, url, `{"fp_approval":"high_and_above"}`, http.StatusOK)
	got.Pending, got.PendingAt = "", nil
	_ = json.Unmarshal([]byte(h.expect(owner, http.MethodPut, url, `{"fp_approval":"all"}`, http.StatusOK)), &got)
	if got.Pending != "" {
		t.Fatalf("a cancelled lowering is still pending: %+v", got)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding_approval.settings_changed'
		AND changes IS NOT NULL`, org); n < 3 {
		t.Fatalf("settings changes audited: %d", n)
	}
}

// A false positive one person decided gets a review flag when the finding
// later becomes material (severity up, KEV added, new evidence); a four-eyes
// false positive does not. A second-look share flags decisions too.
func TestFindingFPPolicy_MaterialChangeReviewFlag_DB(t *testing.T) {
	h := newFPPolicyHarness(t)
	org := h.tenantWithFindings()
	admin, owner := h.member(org, "admin"), h.member(org, "owner")
	h.t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM finding_decision_reviews WHERE tenant_id = $1`, org)
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM finding_evidence WHERE tenant_id = $1`, org)
	})
	setFPLevel(h, org, `{"fp_approval":"off"}`)
	flags := func(findingID string) int {
		return h.countRows(`SELECT COUNT(*) FROM finding_decision_reviews WHERE finding_id = $1 AND reason = 'material_change_single_person' AND cleared_at IS NULL`, findingID)
	}

	sev := h.newFinding(org, "low")
	if status, _, _ := requestFP(h, admin, sev); status != "approved" {
		t.Fatal("not decided alone")
	}
	h.exec(`UPDATE findings SET severity = 'critical' WHERE id = $1`, sev)
	if flags(sev) != 1 {
		t.Fatal("severity raised: no review flag")
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_activities WHERE finding_id = $1 AND activity_type = 'decision_review'`, sev); n != 1 {
		t.Fatalf("review timeline entries: %d", n)
	}
	if findingStatusOf(h, sev) != "false_positive" {
		t.Fatal("the review flag reversed the decision")
	}

	kev := h.newFinding(org, "low")
	requestFP(h, admin, kev)
	h.exec(`UPDATE findings SET severity = 'info' WHERE id = $1`, kev) // lowering never flags
	h.exec(`UPDATE findings SET is_in_kev = true WHERE id = $1`, kev)
	if flags(kev) != 1 {
		t.Fatal("KEV added: no review flag")
	}

	ev := h.newFinding(org, "low")
	requestFP(h, admin, ev)
	h.exec(`INSERT INTO finding_evidence (tenant_id, finding_id, origin, kind, content, content_sha256)
		VALUES ($1, $2, 'detection', 'http_exchange', '{}'::jsonb, 'sha256:x')`, org, ev)
	if flags(ev) != 1 {
		t.Fatal("new evidence: no review flag")
	}

	// Four-eyes false positive: no flag.
	setFPLevel(h, org, `{"fp_approval":"all"}`)
	fe := h.newFinding(org, "low")
	_, _, id := requestFP(h, admin, fe)
	h.expect(owner, http.MethodPost, "/api/v1/approvals/"+id+"/approve", "", http.StatusOK)
	h.exec(`UPDATE findings SET severity = 'critical' WHERE id = $1`, fe)
	if flags(fe) != 0 {
		t.Fatal("a four-eyes false positive was flagged")
	}

	// Second look: with the share forced to every decision, each is flagged.
	setFPLevel(h, org, `{"fp_approval":"off","second_look_percent":100}`)
	sl := h.newFinding(org, "low")
	requestFP(h, admin, sl)
	if n := h.countRows(`SELECT COUNT(*) FROM finding_decision_reviews WHERE finding_id = $1 AND reason = 'second_look_sample'`, sl); n != 1 {
		t.Fatalf("second-look flags: %d", n)
	}
}
