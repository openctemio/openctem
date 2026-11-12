package routes

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// The verification checklist over the real routes, services and a migrated
// database: completing it records who and when, so the transition engine's
// "completed by another person" gate can open Resolved for a critical finding;
// unticking an item clears that record; the read writes nothing; tenant, data
// scope and status limit who can edit what. The older tests wrote
// completed_by/completed_at with raw SQL, which hid that the API never did.

func checklistPerms() []string {
	return append(rgMemberPerms, permission.VerificationChecklistsRead.String(), permission.VerificationChecklistsWrite.String())
}

var allChecklistItems = map[string]any{ //nolint:gochecknoglobals // test fixture
	"exposure_cleared": true, "evidence_attached": true, "register_updated": true,
}

func (h *gsHarness) putChecklist(user shared.ID, finding shared.ID, body map[string]any) (int, map[string]any, string) {
	h.t.Helper()
	code, raw := h.doPerms(user, checklistPerms(), http.MethodPut, "/api/v1/verification-checklists/"+finding.String(), body)
	out := map[string]any{}
	_ = json.Unmarshal([]byte(raw), &out)
	return code, out, raw
}

// completeChecklistViaAPI completes the checklist of a finding through the
// route, as a person would.
func (h *gsHarness) completeChecklistViaAPI(user, finding shared.ID) {
	h.t.Helper()
	code, out, raw := h.putChecklist(user, finding, allChecklistItems)
	if code != http.StatusOK || out["is_complete"] != true || out["completed_by"] != user.String() || out["completed_at"] == nil {
		h.t.Fatalf("complete checklist: %d %s", code, raw)
	}
}

// verifyAction is the verifier's resolve of a fix_applied finding, decided by
// the transition engine with the evidence loaded from the database.
func (h *gsHarness) verifyAction(user, finding shared.ID) (int, string) {
	h.t.Helper()
	return h.doPerms(user, rgVerifierPerms(), http.MethodPost, "/api/v1/findings/actions/verify",
		map[string]any{"finding_ids": []string{finding.String()}, "note": "checked"})
}

func TestVerificationChecklist_CompletionRecordsWhoAndUnlocksResolve_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	fa := h.findingA
	h.exec(`UPDATE findings SET status = 'fix_applied', severity = 'critical', priority_class = NULL, is_in_kev = false,
		last_seen_at = NOW() - interval '1 day', last_reopened_at = NULL WHERE id = $1`, fa.String())
	h.exec(`DELETE FROM finding_verification_checklists WHERE finding_id = $1`, fa.String())
	resolve := func(user shared.ID) (int, string) {
		return h.verifyAction(user, fa)
	}

	// A partial checklist records nobody.
	code, out, raw := h.putChecklist(h.memberA, fa, map[string]any{"exposure_cleared": true})
	if code != http.StatusOK || out["is_complete"] != false || out["completed_by"] != nil {
		t.Fatalf("partial: %d %s", code, raw)
	}
	// The completer cannot resolve a critical finding on their own checklist.
	h.completeChecklistViaAPI(h.memberA, fa)
	if code, body := resolve(h.memberA); h.statusOf(fa) != "fix_applied" {
		t.Fatalf("completer resolved their own critical finding: %d %s", code, body)
	}
	// A different person can: this is the gate the raw-SQL tests used to fake.
	if code, body := resolve(h.memberFull); h.statusOf(fa) != "resolved" {
		t.Fatalf("second person resolve: %d %s (status %s)", code, body, h.statusOf(fa))
	}
	if st, method, by := h.closure(fa); st != "resolved" || method != "fixed/security_review" || by != h.memberFull.String() {
		t.Fatalf("closure = %s %s %s, want resolved / fixed/security_review / the second person", st, method, by)
	}
	// The edit is audited (who completed, no notes text).
	if n := h.auditCount("finding.verification_checklist_updated", fa.String()); n != 2 {
		t.Fatalf("checklist audit rows = %d, want 2 (the partial and the complete edit)", n)
	}
}

func TestVerificationChecklist_UntickClearsCompletion_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	fa := h.findingA
	h.exec(`UPDATE findings SET status = 'fix_applied', severity = 'critical', priority_class = NULL, is_in_kev = false,
		last_seen_at = NOW() - interval '1 day', last_reopened_at = NULL WHERE id = $1`, fa.String())
	h.exec(`DELETE FROM finding_verification_checklists WHERE finding_id = $1`, fa.String())
	h.completeChecklistViaAPI(h.memberA, fa)

	code, out, raw := h.putChecklist(h.memberA, fa, map[string]any{"evidence_attached": false})
	if code != http.StatusOK || out["is_complete"] != false || out["completed_by"] != nil || out["completed_at"] != nil {
		t.Fatalf("untick: %d %s", code, raw)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_verification_checklists WHERE finding_id = $1 AND (completed_by IS NOT NULL OR completed_at IS NOT NULL)`, fa.String()); n != 0 {
		t.Fatalf("completion not cleared in the row")
	}
	// And the second person is blocked again.
	if code, body := h.verifyAction(h.memberFull, fa); h.statusOf(fa) != "fix_applied" {
		t.Fatalf("resolved on a checklist that was unticked: %d %s", code, body)
	}
	// A notes-only edit of a complete checklist keeps who completed it.
	h.completeChecklistViaAPI(h.memberA, fa)
	code, out, raw = h.putChecklist(h.memberFull, fa, map[string]any{"notes": "see PR"})
	if code != http.StatusOK || out["completed_by"] != h.memberA.String() {
		t.Fatalf("notes edit changed the completer: %d %s", code, raw)
	}
	// Re-ticking by someone else records them.
	h.putChecklist(h.memberA, fa, map[string]any{"register_updated": false})
	code, out, raw = h.putChecklist(h.memberFull, fa, map[string]any{"register_updated": true})
	if code != http.StatusOK || out["completed_by"] != h.memberFull.String() {
		t.Fatalf("re-complete: %d %s", code, raw)
	}
}

func TestVerificationChecklist_GetIsReadOnly_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	fa := h.findingA
	h.exec(`DELETE FROM finding_verification_checklists WHERE finding_id = $1`, fa.String())
	code, raw := h.doPerms(h.memberA, checklistPerms(), http.MethodGet, "/api/v1/verification-checklists/"+fa.String(), nil)
	if code != http.StatusOK || !strings.Contains(raw, `"is_complete":false`) {
		t.Fatalf("get: %d %s", code, raw)
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_verification_checklists WHERE finding_id = $1`, fa.String()); n != 0 {
		t.Fatalf("GET created %d checklist rows", n)
	}
}

func TestVerificationChecklist_ScopeTenantAndStatus_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	// Out of data scope: memberA's scope is asset A1, finding B is on B1.
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		code, raw := h.doPerms(h.memberA, checklistPerms(), m, "/api/v1/verification-checklists/"+h.findingB.String(), allChecklistItems)
		if code != http.StatusNotFound {
			t.Errorf("%s out-of-scope finding = %d %s, want 404", m, code, raw)
		}
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_verification_checklists WHERE finding_id = $1`, h.findingB.String()); n != 0 {
		t.Errorf("an out-of-scope edit created a checklist row")
	}
	// Another tenant's finding reads as missing.
	otherTenant, otherAsset, otherFinding := shared.NewID(), shared.NewID(), shared.NewID()
	h.exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, otherTenant.String(), "vc-other-"+otherTenant.String())
	t.Cleanup(func() { h.exec(`DELETE FROM tenants WHERE id = $1`, otherTenant.String()) })
	h.exec(`INSERT INTO assets (id, tenant_id, name, asset_type, status) VALUES ($1, $2, 'vc-other.example.com', 'domain', 'active')`,
		otherAsset.String(), otherTenant.String())
	h.exec(`INSERT INTO findings (id, tenant_id, asset_id, source, severity, status, title, fingerprint, finding_type, tool_name, message)
		VALUES ($1, $2, $3, 'dast', 'critical', 'fix_applied', 'other tenant', $4, 'vulnerability', 'nuclei', 'm')`,
		otherFinding.String(), otherTenant.String(), otherAsset.String(), "vc-"+otherFinding.String())
	for _, m := range []string{http.MethodGet, http.MethodPut} {
		if code, raw := h.doPerms(h.memberFull, checklistPerms(), m, "/api/v1/verification-checklists/"+otherFinding.String(), allChecklistItems); code != http.StatusNotFound {
			t.Errorf("%s other tenant's finding = %d %s, want 404", m, code, raw)
		}
	}
	if n := h.countRows(`SELECT COUNT(*) FROM finding_verification_checklists WHERE finding_id = $1`, otherFinding.String()); n != 0 {
		t.Errorf("a cross-tenant edit created a checklist row")
	}
	// A closed finding takes no edit.
	h.exec(`UPDATE findings SET status = 'resolved' WHERE id = $1`, h.findingA.String())
	if code, raw := h.doPerms(h.memberA, checklistPerms(), http.MethodPut, "/api/v1/verification-checklists/"+h.findingA.String(), allChecklistItems); code != http.StatusBadRequest {
		t.Errorf("edit on a resolved finding = %d %s, want 400", code, raw)
	}
	// Permissions: read does not edit.
	h.exec(`UPDATE findings SET status = 'fix_applied' WHERE id = $1`, h.findingA.String())
	if code, raw := h.doPerms(h.memberA, append(rgMemberPerms, permission.VerificationChecklistsRead.String()), http.MethodPut,
		"/api/v1/verification-checklists/"+h.findingA.String(), allChecklistItems); code != http.StatusForbidden {
		t.Errorf("PUT with read only = %d %s, want 403", code, raw)
	}
}
