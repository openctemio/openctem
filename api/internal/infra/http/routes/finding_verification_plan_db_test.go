package routes

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type verificationPlanBody struct {
	Tier                 string `json:"tier"`
	Requirement          string `json:"requirement"`
	SecondPersonRequired bool   `json:"second_person_required"`
	ProofPresent         bool   `json:"proof_present"`
	Methods              []struct {
		Kind        string `json:"kind"`
		Available   bool   `json:"available"`
		Recommended bool   `json:"recommended"`
		Reason      string `json:"reason"`
	} `json:"methods"`
	Evidence struct {
		Checklist struct {
			State             string `json:"state"`
			CompletedBy       string `json:"completed_by"`
			CompletedByCaller bool   `json:"completed_by_caller"`
			Fresh             bool   `json:"fresh"`
		} `json:"checklist"`
	} `json:"evidence"`
}

// GET /findings/{id}/verification over the real routes: a critical secret
// says rotation proof first and why a retest, a covered scan and a
// reachability check cannot verify it; completing the checklist records who,
// so the completer is told another person must resolve; read-only callers may
// ask; out of scope and another tenant's finding are 404; nothing is written.
func TestFindingVerificationPlan_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	// The evidence reads use the service's database handle, wired in
	// production with the outbox.
	h.vuln.SetOutboxService(h.db, nil)
	fa := h.findingA
	h.exec(`UPDATE findings SET status = 'confirmed', severity = 'critical', finding_type = 'secret', priority_class = NULL,
		is_in_kev = false, last_seen_at = NOW() - interval '1 day', last_reopened_at = NULL WHERE id = $1`, fa.String())
	h.exec(`DELETE FROM finding_verification_checklists WHERE finding_id = $1`, fa.String())
	readOnly := []string{permission.FindingsRead.String()}

	get := func(user shared.ID, perms []string, id string) (int, verificationPlanBody, string) {
		status, body := h.doPerms(user, perms, http.MethodGet, "/api/v1/findings/"+id+"/verification", nil)
		var out verificationPlanBody
		_ = json.Unmarshal([]byte(body), &out)
		return status, out, body
	}
	method := func(p verificationPlanBody, kind string) (bool, bool, string) {
		for _, m := range p.Methods {
			if m.Kind == kind {
				return m.Available, m.Recommended, m.Reason
			}
		}
		t.Fatalf("no %s method in %+v", kind, p.Methods)
		return false, false, ""
	}

	status, plan, body := get(h.memberA, readOnly, fa.String())
	if status != http.StatusOK || plan.Tier != "critical" || plan.Requirement != "second_person_or_retest" || !plan.SecondPersonRequired || plan.ProofPresent {
		t.Fatalf("plan = %d %.500s", status, body)
	}
	if ok, rec, _ := method(plan, "rotation_proof"); !ok || !rec {
		t.Errorf("secret: rotation proof available=%v recommended=%v, want both", ok, rec)
	}
	if ok, _, reason := method(plan, "retest"); ok || reason != "secret_needs_rotation" {
		t.Errorf("secret retest = %v %q, want unavailable secret_needs_rotation", ok, reason)
	}
	if ok, _, reason := method(plan, "covered_scan"); ok || reason != "absence_not_proof_for_secrets" {
		t.Errorf("secret covered scan = %v %q", ok, reason)
	}
	if ok, _, reason := method(plan, "safe_check"); ok || reason != "not_for_secrets" {
		t.Errorf("secret safe check = %v %q", ok, reason)
	}
	if plan.Evidence.Checklist.State != "none" {
		t.Errorf("checklist state = %q, want none", plan.Evidence.Checklist.State)
	}

	// The member completes the checklist: they are told another person must
	// resolve; the owner sees the proof present.
	h.completeChecklistViaAPI(h.memberA, fa)
	_, mine, _ := get(h.memberA, readOnly, fa.String())
	if mine.Evidence.Checklist.State != "complete" || !mine.Evidence.Checklist.CompletedByCaller || !mine.Evidence.Checklist.Fresh ||
		mine.Evidence.Checklist.CompletedBy != h.memberA.String() || !mine.ProofPresent {
		t.Errorf("completer's plan = %+v", mine)
	}
	_, owners, _ := get(h.owner, readOnly, fa.String())
	if owners.Evidence.Checklist.CompletedByCaller || !owners.ProofPresent {
		t.Errorf("owner's plan = %+v", owners)
	}

	// A medium network finding: a note is enough; the retest says why not.
	h.exec(`UPDATE findings SET severity = 'medium', finding_type = 'vulnerability' WHERE id = $1`, fa.String())
	_, medium, _ := get(h.memberA, readOnly, fa.String())
	if medium.Tier != "standard" || medium.Requirement != "note" || medium.SecondPersonRequired {
		t.Errorf("medium plan = %+v", medium)
	}

	// Out of the member's data scope, and another tenant's finding: 404.
	other, otherAsset, otherFinding := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "vp-other-"+other.String())
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'vp-other.example.com', 'domain')`, otherAsset.String(), other.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'dast', 't', 'm', 'high', $1::text, 'confirmed')`, otherFinding.String(), other.String(), otherAsset.String())
	for name, c := range map[string]struct {
		user shared.ID
		id   string
	}{"out of scope": {h.memberA, h.findingB.String()}, "another tenant": {h.owner, otherFinding.String()}} {
		if status, _, body := get(c.user, readOnly, c.id); status != http.StatusNotFound {
			t.Errorf("%s: %d %.200s, want 404", name, status, body)
		}
	}
	if n := h.countRows(`SELECT count(*) FROM finding_retests WHERE finding_id = $1`, fa.String()); n != 0 {
		t.Errorf("the plan recorded %d retests", n)
	}
}
