package routes

// The remaining filter / bulk finding paths, over the grouped-view harness
// (memberA's scope is asset A1; FB and FB2 are on B1; FP is a pentest finding
// on A1 in a campaign memberA is not on):
//
//   - POST /findings/bulk/status must refuse pentest findings exactly like
//     PATCH /findings/{id}/status does (they are managed by the pentest
//     module). It used to change them.
//   - VulnerabilityService.ListFindingIDs (the id set a filter-based
//     remediation campaign resolve counts against the abuse guard and sends
//     to the bulk path) must see what the caller's findings list sees.

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

func TestBulkStatus_PentestFindingRefusedLikeSinglePath(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.exec(`UPDATE findings SET status = 'in_progress' WHERE id IN ($1, $2)`, h.findingA.String(), h.findingP.String())

	// The single-finding path refuses a pentest finding, even for the owner.
	if status, body := h.do(h.owner, true, http.MethodPatch, "/api/v1/findings/"+h.findingP.String()+"/status",
		map[string]any{"status": "fix_applied", "resolution": "patched"}); status == http.StatusOK {
		t.Fatalf("single-path status on pentest finding = %d %.200s, want refused", status, body)
	}

	for _, who := range []struct {
		name  string
		user  shared.ID
		admin bool
	}{{"owner", h.owner, true}, {"in-scope member not on the campaign", h.memberA, false}} {
		status, body := h.do(who.user, who.admin, http.MethodPost, "/api/v1/findings/bulk/status",
			map[string]any{"finding_ids": []string{h.findingP.String()}, "status": "fix_applied", "resolution": "patched"})
		if status != http.StatusOK || !strings.Contains(body, `"updated":0`) || !strings.Contains(body, "pentest") {
			t.Errorf("%s bulk status on pentest finding = %d %.300s, want updated 0 and a pentest error", who.name, status, body)
		}
		if st, _, _ := h.findingState(h.findingP); st != "in_progress" {
			t.Fatalf("%s changed pentest finding FP to %s through the bulk path", who.name, st)
		}
	}

	// Non-pentest findings in the same call still move.
	status, body := h.do(h.owner, true, http.MethodPost, "/api/v1/findings/bulk/status",
		map[string]any{"finding_ids": []string{h.findingA.String(), h.findingP.String()}, "status": "fix_applied", "resolution": "patched"})
	if status != http.StatusOK || !strings.Contains(body, `"updated":1`) || !strings.Contains(body, `"failed":1`) {
		t.Errorf("owner mixed bulk = %d %.300s, want updated 1 failed 1", status, body)
	}
	if st, _, _ := h.findingState(h.findingA); st != "fix_applied" {
		t.Errorf("FA = %s, want fix_applied", st)
	}
}

// callerCtx is the context the auth middleware builds for a request.
func callerCtx(user shared.ID, admin bool) context.Context {
	ctx := context.WithValue(context.Background(), middleware.UserIDKey, user.String())
	return context.WithValue(ctx, middleware.IsAdminKey, admin)
}

func TestListFindingIDs_CallerScoped(t *testing.T) {
	h := newGroupScopeHarness(t)
	all := []string{h.cveA, h.cveB, h.cveB2, h.cveP}
	ids := func(ctx context.Context) []string {
		t.Helper()
		f := vulnerability.NewFindingFilter().WithTenantID(h.tenant)
		f.CVEIDs = all
		got, err := h.vuln.ListFindingIDs(ctx, f, 100)
		if err != nil {
			t.Fatalf("ListFindingIDs: %v", err)
		}
		out := make([]string, 0, len(got))
		for _, id := range got {
			out = append(out, id.String())
		}
		sort.Strings(out)
		return out
	}
	want := func(fs ...shared.ID) []string {
		out := make([]string, 0, len(fs))
		for _, f := range fs {
			out = append(out, f.String())
		}
		sort.Strings(out)
		return out
	}
	eq := func(a, b []string) bool { return strings.Join(a, ",") == strings.Join(b, ",") }

	everything := want(h.findingA, h.findingB, h.findingB2, h.findingP)
	if got := ids(context.Background()); !eq(got, everything) {
		t.Errorf("internal call (no user) = %v, want all %v", got, everything)
	}
	if got := ids(callerCtx(h.owner, true)); !eq(got, everything) {
		t.Errorf("owner = %v, want all %v", got, everything)
	}
	// A restricted member: only in-scope findings, and no pentest finding of
	// a campaign they are not on.
	if got := ids(callerCtx(h.memberA, false)); !eq(got, want(h.findingA)) {
		t.Errorf("memberA = %v, want only FA", got)
	}
	// On the campaign, its pentest finding on their asset is visible again.
	h.exec(`INSERT INTO pentest_campaign_members (tenant_id, campaign_id, user_id) VALUES ($1, $2, $3)`,
		h.tenant.String(), h.camp.String(), h.memberA.String())
	t.Cleanup(func() {
		_, _ = h.db.ExecContext(context.Background(), `DELETE FROM pentest_campaign_members WHERE campaign_id = $1`, h.camp.String())
	})
	if got := ids(callerCtx(h.memberA, false)); !eq(got, want(h.findingA, h.findingP)) {
		t.Errorf("memberA on the campaign = %v, want FA and FP", got)
	}
	// A member without a scope row sees nothing, although the organization
	// is still stored as 'everything'.
	for _, u := range []shared.ID{h.memberFree, h.memberStrict} {
		if got := ids(callerCtx(u, false)); len(got) != 0 {
			t.Errorf("member without scope row = %v, want none", got)
		}
	}
	// A full-data role sees every finding outside pentest campaigns.
	got := strings.Join(ids(callerCtx(h.memberFull, false)), ",")
	for _, f := range []shared.ID{h.findingA, h.findingB, h.findingB2} {
		if !strings.Contains(got, f.String()) {
			t.Errorf("full-data role = %v, missing %s", got, f)
		}
	}
}
