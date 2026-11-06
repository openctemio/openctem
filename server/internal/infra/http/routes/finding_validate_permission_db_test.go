package routes

import (
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// POST /findings/{id}/validate (the reachability check) needs findings:verify,
// the permission of a retest: findings:write alone is refused, so a
// remediation owner cannot run the check on their own fix.
func TestFindingValidate_NeedsVerifyPermission_DB(t *testing.T) {
	h := newGroupScopeHarness(t)
	path := "/api/v1/findings/" + h.findingA.String() + "/validate"

	writeOnly := []string{permission.FindingsRead.String(), permission.FindingsWrite.String()}
	if code, body := h.doPerms(h.memberA, writeOnly, http.MethodPost, path, nil); code != http.StatusForbidden {
		t.Fatalf("findings:write only: %d %.200s, want 403", code, body)
	}
	verify := []string{permission.FindingsRead.String(), permission.FindingsVerify.String()}
	if code, body := h.doPerms(h.memberA, verify, http.MethodPost, path, nil); code == http.StatusForbidden || code == http.StatusNotFound {
		t.Fatalf("findings:verify: %d %.200s, want past the permission gate", code, body)
	}
}
