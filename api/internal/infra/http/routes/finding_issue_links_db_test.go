package routes

// GET /api/v1/findings/{id}/issue-links and DELETE …/issue-links/{other}
// over the real routes, handler, service, repository and a migrated
// database: a same-issue group is shown only through the caller's data
// scope (no member, id or count of an asset outside it), unlinking needs
// findings:triage and both findings in scope, ends the pair for good and is
// recorded on both timelines and in the audit log.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func (h *dsHarness) issueLink(primary, member shared.ID, rule string) {
	h.t.Helper()
	h.exec(`INSERT INTO finding_issue_links (tenant_id, primary_id, member_id, rule, basis) VALUES ($1, $2, $3, $4, '{secret}')`,
		h.tenant.String(), primary.String(), member.String(), rule)
}

func (h *dsHarness) issueCall(method string, user shared.ID, admin bool, perms []string, path string) (int, string) {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, h.srv.URL+path, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	req.Header.Set("X-Test-User", user.String())
	if admin {
		req.Header.Set("X-Test-Admin", "1")
	}
	if perms != nil {
		req.Header.Set("X-Test-Perms", strings.Join(perms, ","))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func groupIDs(t *testing.T, body string) []string {
	t.Helper()
	var resp struct {
		Members []struct {
			ID string `json:"id"`
		} `json:"members"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode %q: %v", body, err)
	}
	ids := make([]string, 0, len(resp.Members))
	for _, m := range resp.Members {
		ids = append(ids, m.ID)
	}
	return ids
}

func TestIssueLinks_GroupIsScopedAndUnlinkIsAudited(t *testing.T) {
	h := newDSHarness(t)
	a2 := h.dupFinding(h.assetA, "secret", "new")
	// findingA (asset A) is the primary; a2 (asset A) and findingB (asset B,
	// outside memberA's scope) are members.
	h.issueLink(h.findingA, a2, "secret_value")
	h.issueLink(h.findingA, h.findingB, "secret_value")

	path := "/api/v1/findings/" + h.findingA.String() + "/issue-links"
	status, body := h.issueCall(http.MethodGet, h.owner, true, nil, path)
	if status != http.StatusOK || len(groupIDs(t, body)) != 3 {
		t.Fatalf("owner sees %d %s, want the 3 members", status, body)
	}
	if strings.Contains(body, "secret_value\"") && strings.Contains(body, "hmac") {
		t.Fatal("the response names a secret hash")
	}

	// memberA sees only the members on asset A: no id, no count of B.
	status, body = h.issueCall(http.MethodGet, h.memberA, false, nil, path)
	if status != http.StatusOK {
		t.Fatalf("memberA GET = %d %s", status, body)
	}
	ids := groupIDs(t, body)
	if len(ids) != 2 || strings.Contains(body, h.findingB.String()) {
		t.Fatalf("memberA sees %v, want findingA and a2 only", ids)
	}
	// The out-of-scope finding itself: 404.
	if status, _ := h.issueCall(http.MethodGet, h.memberA, false, nil, "/api/v1/findings/"+h.findingB.String()+"/issue-links"); status != http.StatusNotFound {
		t.Fatalf("memberA GET out-of-scope finding = %d, want 404", status)
	}
	// A member with no scope row: 404.
	if status, _ := h.issueCall(http.MethodGet, h.memberFree, false, nil, path); status != http.StatusNotFound {
		t.Fatalf("memberFree GET = %d, want 404", status)
	}
	// A finding id of no tenant's: 404.
	if status, _ := h.issueCall(http.MethodGet, h.owner, true, nil, "/api/v1/findings/"+shared.NewID().String()+"/issue-links"); status != http.StatusNotFound {
		t.Fatalf("unknown finding = %d, want 404", status)
	}

	// Unlink: without findings:triage, 403.
	del := path + "/" + a2.String()
	readOnly := []string{permission.FindingsRead.String()}
	if status, _ := h.issueCall(http.MethodDelete, h.memberA, false, readOnly, del); status != http.StatusForbidden {
		t.Fatalf("unlink without triage = %d, want 403", status)
	}
	// memberA cannot unlink the member outside the scope (404, nothing changes).
	if status, _ := h.issueCall(http.MethodDelete, h.memberA, false, nil, path+"/"+h.findingB.String()); status != http.StatusNotFound {
		t.Fatalf("unlink out-of-scope member = %d, want 404", status)
	}
	if n := h.countRows(`SELECT count(*) FROM finding_issue_links WHERE tenant_id = $1 AND state = 'active'`, h.tenant.String()); n != 2 {
		t.Fatalf("active links %d after refused unlinks, want 2", n)
	}
	// memberA unlinks a2: the pair ends as unlinked, by memberA.
	if status, body := h.issueCall(http.MethodDelete, h.memberA, false, nil, del); status != http.StatusNoContent {
		t.Fatalf("unlink = %d %s", status, body)
	}
	if n := h.countRows(`SELECT count(*) FROM finding_issue_links WHERE tenant_id = $1 AND member_id = $2 AND state = 'unlinked' AND ended_by = $3`,
		h.tenant.String(), a2.String(), h.memberA.String()); n != 1 {
		t.Fatal("the link did not end as unlinked by memberA")
	}
	if n := h.countRows(`SELECT count(*) FROM finding_activities WHERE tenant_id = $1 AND activity_type = 'issue_unlinked' AND finding_id IN ($2, $3)`,
		h.tenant.String(), h.findingA.String(), a2.String()); n != 2 {
		t.Fatalf("timeline entries %d, want one on each finding", n)
	}
	if n := h.countRows(`SELECT count(*) FROM audit_logs WHERE tenant_id = $1 AND action = 'finding.issue_unlinked' AND resource_id = $2 AND actor_id = $3`,
		h.tenant.String(), a2.String(), h.memberA.String()); n != 1 {
		t.Fatalf("audit entries %d, want 1", n)
	}
	// Unlinking again: 404. Neither finding's status changed.
	if status, _ := h.issueCall(http.MethodDelete, h.memberA, false, nil, del); status != http.StatusNotFound {
		t.Fatalf("second unlink = %d, want 404", status)
	}
	if st, _ := h.dupState(a2); st != "new" {
		t.Fatalf("unlink changed the member's status to %s", st)
	}
	// memberA now sees no group: the only other visible member left it.
	_, body = h.issueCall(http.MethodGet, h.memberA, false, nil, path)
	if ids := groupIDs(t, body); len(ids) != 0 {
		t.Fatalf("memberA still sees a group %v", ids)
	}
}
