package routes

// The resolve gate over the real routes, middleware, services and a migrated
// database: a member who holds findings:fix_apply, findings:bulk_update and
// findings:write but NOT findings:verify cannot close a fix_applied finding
// through PATCH /findings/{id}/status, POST /findings/bulk/status or
// POST /findings/remediation-groups/{key}/resolve. A findings:verify holder
// can, and every such close records resolution_method and resolved_by.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// rgMemberPerms is the built-in Member's finding grant: fix_apply and
// bulk_update, no verify.
var rgMemberPerms = []string{ //nolint:gochecknoglobals // test fixture
	permission.FindingsRead.String(), permission.FindingsWrite.String(), permission.FindingsStatus.String(),
	permission.FindingsTriage.String(), permission.FindingsBulkUpdate.String(), permission.FindingsFixApply.String(),
}

func rgVerifierPerms() []string {
	return append(append([]string{}, rgMemberPerms...), permission.FindingsVerify.String())
}

func (h *gsHarness) doPerms(user shared.ID, perms []string, method, path string, body any) (int, string) {
	h.t.Helper()
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, bytes.NewReader(b))
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-User", user.String())
	req.Header.Set("X-Test-Perms", strings.Join(perms, ","))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func (h *gsHarness) closure(id shared.ID) (status, method, by string) {
	h.t.Helper()
	var m, b sql.NullString
	if err := h.db.QueryRow(`SELECT status, resolution_method, resolved_by::text FROM findings WHERE id = $1`, id.String()).
		Scan(&status, &m, &b); err != nil {
		h.t.Fatal(err)
	}
	return status, m.String, b.String
}

func TestResolveGate_MemberWithoutVerifyCannotClose(t *testing.T) {
	h := newGroupScopeHarness(t)
	const key = "rg-test-upgrade-lib"
	h.exec(`UPDATE findings SET status = 'fix_applied' WHERE id = $1`, h.findingA.String())
	h.exec(`INSERT INTO finding_remediation_keys (finding_id, tenant_id, remediation_key, title) VALUES ($1, $2, $3, 'upgrade lib')`,
		h.findingA.String(), h.tenant.String(), key)

	fa := h.findingA.String()
	attempts := []struct {
		name, method, path string
		body               any
	}{
		{"single", http.MethodPatch, "/api/v1/findings/" + fa + "/status", map[string]any{"status": "resolved", "resolution": "fixed"}},
		{"bulk", http.MethodPost, "/api/v1/findings/bulk/status", map[string]any{"finding_ids": []string{fa}, "status": "resolved"}},
		{"group", http.MethodPost, "/api/v1/findings/remediation-groups/" + key + "/resolve", map[string]any{"status": "resolved"}},
	}
	for _, a := range attempts {
		status, body := h.doPerms(h.memberA, rgMemberPerms, a.method, a.path, a.body)
		if status != http.StatusForbidden {
			t.Errorf("%s resolve by a member without findings:verify = %d %.300s, want 403", a.name, status, body)
		}
		if st, _, _ := h.closure(h.findingA); st != "fix_applied" {
			t.Fatalf("%s: the member closed the finding (status %s)", a.name, st)
		}
	}

	// The member's own step (fix_applied) and the group's default stay open to them.
	if status, body := h.doPerms(h.memberA, rgMemberPerms, http.MethodPost,
		"/api/v1/findings/remediation-groups/"+key+"/resolve", map[string]any{}); status != http.StatusOK {
		t.Errorf("group resolve to the fix_applied default = %d %.300s, want 200", status, body)
	}

	// Each route, for a findings:verify holder: resolved, with method and actor.
	for _, a := range attempts {
		h.exec(`UPDATE findings SET status = 'fix_applied', resolution_method = NULL, resolved_by = NULL, resolved_at = NULL WHERE id = $1`, fa)
		status, body := h.doPerms(h.memberA, rgVerifierPerms(), a.method, a.path, a.body)
		if status != http.StatusOK {
			t.Fatalf("%s resolve with findings:verify = %d %.300s, want 200", a.name, status, body)
		}
		st, method, by := h.closure(h.findingA)
		if st != "resolved" || method != "admin_direct" || by != h.memberA.String() {
			t.Errorf("%s: status=%s method=%q resolved_by=%q, want resolved / admin_direct / the actor", a.name, st, method, by)
		}
	}

	// A reopen clears the method, so a later close never inherits it.
	if status, body := h.doPerms(h.memberA, rgVerifierPerms(), http.MethodPatch, "/api/v1/findings/"+fa+"/status",
		map[string]any{"status": "confirmed"}); status != http.StatusOK {
		t.Fatalf("reopen = %d %.300s", status, body)
	}
	if st, method, _ := h.closure(h.findingA); st != "confirmed" || method != "" {
		t.Errorf("after reopen: status=%s method=%q, want confirmed with no method", st, method)
	}
}
