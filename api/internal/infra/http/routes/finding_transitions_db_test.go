package routes

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

type transitionsBody struct {
	Status      string `json:"status"`
	Transitions []struct {
		To       string   `json:"to"`
		Allowed  bool     `json:"allowed"`
		Mode     string   `json:"mode"`
		Requires []string `json:"requires"`
		Blocked  []struct {
			Code   string            `json:"code"`
			Params map[string]string `json:"params"`
		} `json:"blocked"`
	} `json:"transitions"`
}

type evaluateBody struct {
	Results []struct {
		FindingID string `json:"finding_id"`
		NotFound  bool   `json:"not_found"`
		Decision  *struct {
			Allowed bool `json:"allowed"`
			Blocked []struct {
				Code string `json:"code"`
			} `json:"blocked"`
		} `json:"decision"`
	} `json:"results"`
}

// GET /findings/{id}/transitions answers the caller's allowed moves from the
// same engine every status path uses: a member without findings:verify sees
// resolve blocked with the permission it needs, a verifier sees it allowed
// with a note required, a disposition is a request. Out of scope or another
// tenant's finding: 404. The dry run answers per finding and never changes
// one.
func TestFindingTransitions_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	fa := h.findingA.String()
	h.exec(`UPDATE findings SET status = 'fix_applied' WHERE id = $1`, fa)
	readOnly := []string{permission.FindingsRead.String()}

	get := func(user shared.ID, perms []string, id string) (int, transitionsBody, string) {
		status, body := h.doPerms(user, perms, http.MethodGet, "/api/v1/findings/"+id+"/transitions", nil)
		var out transitionsBody
		_ = json.Unmarshal([]byte(body), &out)
		return status, out, body
	}
	move := func(b transitionsBody, to string) (allowed bool, blocked []string, requires []string) {
		for _, tr := range b.Transitions {
			if tr.To == to {
				for _, bl := range tr.Blocked {
					blocked = append(blocked, bl.Code+":"+bl.Params["permission"])
				}
				return tr.Allowed, blocked, tr.Requires
			}
		}
		t.Fatalf("no move to %s in %+v", to, b)
		return false, nil, nil
	}

	status, member, body := get(h.memberA, rgMemberPerms, fa)
	if status != http.StatusOK || member.Status != "fix_applied" {
		t.Fatalf("member transitions = %d %.300s", status, body)
	}
	if ok, blocked, _ := move(member, "resolved"); ok || len(blocked) != 1 || blocked[0] != "missing_permission:findings:verify" {
		t.Errorf("member resolve = %v %v, want blocked by findings:verify", ok, blocked)
	}
	if ok, _, _ := move(member, "in_progress"); !ok {
		t.Errorf("member reject-to-in_progress refused")
	}
	_, verifier, _ := get(h.memberA, rgVerifierPerms(), fa)
	if ok, blocked, requires := move(verifier, "resolved"); !ok || len(blocked) != 0 || len(requires) != 1 || requires[0] != "note" {
		t.Errorf("verifier resolve = %v %v %v, want allowed with a note", ok, blocked, requires)
	}
	// A read-only caller may ask; every move says what it lacks.
	_, ro, _ := get(h.memberA, readOnly, fa)
	if ok, blocked, _ := move(ro, "in_progress"); ok || len(blocked) == 0 {
		t.Errorf("read-only move allowed: %v %v", ok, blocked)
	}

	// Out of the member's data scope, and another tenant's finding: 404.
	other, otherAsset, otherFinding := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, other.String(), "tr-other-"+other.String())
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, 'tr-other.example.com', 'domain')`, otherAsset.String(), other.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status)
		VALUES ($1::uuid, $2, $3, 'dast', 't', 'm', 'high', $1::text, 'confirmed')`, otherFinding.String(), other.String(), otherAsset.String())
	for name, c := range map[string]struct {
		user shared.ID
		id   string
	}{"out of scope": {h.memberA, h.findingB.String()}, "another tenant": {h.owner, otherFinding.String()}} {
		if status, _, body := get(c.user, rgVerifierPerms(), c.id); status != http.StatusNotFound {
			t.Errorf("%s: %d %.200s, want 404", name, status, body)
		}
	}

	// The dry run: per finding, out of scope and another tenant's are not_found,
	// and nothing moves.
	status, body = h.doPerms(h.memberA, rgMemberPerms, http.MethodPost, "/api/v1/findings/transitions/preview",
		map[string]any{"finding_ids": []string{fa, h.findingB.String(), otherFinding.String()}, "to": "resolved"})
	var ev evaluateBody
	if status != http.StatusOK || json.Unmarshal([]byte(body), &ev) != nil || len(ev.Results) != 3 {
		t.Fatalf("evaluate = %d %.300s", status, body)
	}
	if r := ev.Results[0]; r.NotFound || r.Decision == nil || r.Decision.Allowed ||
		len(r.Decision.Blocked) == 0 || r.Decision.Blocked[0].Code != "missing_permission" {
		t.Errorf("own finding = %+v, want blocked by a missing permission", r)
	}
	for _, r := range ev.Results[1:] {
		if !r.NotFound || r.Decision != nil {
			t.Errorf("%s = %+v, want not_found", r.FindingID, r)
		}
	}
	if st, _, _ := h.closure(h.findingA); st != "fix_applied" {
		t.Errorf("the dry run moved the finding to %s", st)
	}
	// Bad input is refused.
	for _, b := range []map[string]any{{"finding_ids": []string{fa}, "to": "validated_fixed"}, {"finding_ids": []string{}, "to": "resolved"}} {
		if status, body := h.doPerms(h.memberA, rgMemberPerms, http.MethodPost, "/api/v1/findings/transitions/preview", b); status != http.StatusBadRequest && status != http.StatusUnprocessableEntity {
			t.Errorf("evaluate %v = %d %.200s, want 400 or 422", b, status, body)
		}
	}
}

// Requesting a false positive is a move of the same engine, so the request
// itself is data-scoped: a finding outside the caller's scope is 404.
func TestRequestApproval_OutOfScopeIsNotFound_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	status, body := h.doPerms(h.memberA, rgMemberPerms, http.MethodPost, "/api/v1/findings/"+h.findingB.String()+"/approvals",
		map[string]any{"requested_status": "false_positive", "justification": "not real", "closure_reason": "detection_error"})
	if status != http.StatusNotFound {
		t.Errorf("out-of-scope request = %d %.300s, want 404", status, body)
	}
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM finding_status_approvals WHERE finding_id = $1`, h.findingB.String()).Scan(&n); err != nil || n != 0 {
		t.Errorf("approvals on the out-of-scope finding = %d (%v), want 0", n, err)
	}
}
