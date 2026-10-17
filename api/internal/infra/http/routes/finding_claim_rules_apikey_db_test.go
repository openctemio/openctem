package routes

import (
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// An organization API key has no user. It gets the same claim and close rules
// as a person (never an exemption): without findings:fix_apply, without a
// note, or at all (a fix claim is a person's) it cannot mark a fix applied,
// and it cannot resolve without a note. Nothing is written.
func TestClaimRules_OrgAPIKeyWithoutAUser(t *testing.T) {
	h := newGroupScopeHarness(t)
	fa := h.findingA.String()
	h.exec(`UPDATE findings SET status = 'in_progress' WHERE id = $1`, fa)
	var noUser shared.ID // the key carries no user
	status := func(perms []string, body map[string]any) (int, string) {
		return h.doPerms(noUser, perms, http.MethodPatch, "/api/v1/findings/"+fa+"/status", body)
	}
	statusOnly := []string{permission.FindingsRead.String(), permission.FindingsStatus.String()}

	if code, body := status(statusOnly, map[string]any{"status": "fix_applied", "resolution": "patched"}); code != http.StatusForbidden {
		t.Errorf("key with findings:status only claims a fix = %d %.200s, want 403 (findings:fix_apply)", code, body)
	}
	withFixApply := append(append([]string{}, statusOnly...), permission.FindingsFixApply.String())
	if code, body := status(withFixApply, map[string]any{"status": "fix_applied"}); code != http.StatusBadRequest {
		t.Errorf("key claims a fix without a note = %d %.200s, want 400", code, body)
	}
	if code, body := status(withFixApply, map[string]any{"status": "fix_applied", "resolution": "patched"}); code != http.StatusForbidden {
		t.Errorf("key claims a fix with a note = %d %.200s, want 403 (a fix claim is a person's)", code, body)
	}
	withVerify := append(append([]string{}, statusOnly...), permission.FindingsVerify.String())
	if code, body := status(withVerify, map[string]any{"status": "resolved"}); code != http.StatusBadRequest {
		t.Errorf("key resolves without a note = %d %.200s, want 400", code, body)
	}
	// The bulk path: the same refusals.
	bulkPerms := append(append([]string{}, withFixApply...), permission.FindingsBulkUpdate.String())
	if code, body := h.doPerms(noUser, bulkPerms, http.MethodPost, "/api/v1/findings/bulk/status",
		map[string]any{"finding_ids": []string{fa}, "status": "fix_applied", "resolution": "patched"}); code != http.StatusForbidden {
		t.Errorf("key bulk-claims a fix = %d %.200s, want 403", code, body)
	}
	if st, _, _ := h.closure(h.findingA); st != "in_progress" {
		t.Fatalf("a refused move changed the finding to %s", st)
	}
}
