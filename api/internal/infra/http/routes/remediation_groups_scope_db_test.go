package routes

// Layer 2 data scope on remediation groups (GET /findings/remediation-groups,
// POST /findings/remediation-groups/{key}/resolve) and on
// POST /findings/actions/assign-to-owners, over the real routes, handlers,
// services and a migrated database. Builds on the grouped-view harness:
// memberA's scope is asset A1; FB and FB2 are on B1; FP is a pentest finding
// on A1 in a campaign memberA is not on.

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

const (
	rgKeyA        = "sol:dsa-lib"
	rgKeyB        = "sol:dsb-secret-lib"
	rgMarkerTitle = "dsB-SECRET upgrade title"
)

// seedRemediationKeys puts FA and FB2 in group A (so its counts mix scopes)
// and FB alone in group B.
func (h *gsHarness) seedRemediationKeys() {
	t := h.tenant.String()
	for _, k := range []struct {
		finding    shared.ID
		key, title string
	}{
		{h.findingA, rgKeyA, "Upgrade dsa-lib"},
		{h.findingB2, rgKeyA, "Upgrade dsa-lib"},
		{h.findingB, rgKeyB, rgMarkerTitle},
	} {
		h.exec(`INSERT INTO finding_remediation_keys (finding_id, tenant_id, remediation_key, title) VALUES ($1, $2, $3, $4)`,
			k.finding.String(), t, k.key, k.title)
	}
}

type rgGroup struct {
	Key          string `json:"key"`
	Title        string `json:"title"`
	FindingCount int    `json:"finding_count"`
	AssetCount   int    `json:"asset_count"`
}

func (h *gsHarness) remediationGroups(user shared.ID, admin bool) (map[string]rgGroup, string) {
	h.t.Helper()
	status, body := h.do(user, admin, http.MethodGet, "/api/v1/findings/remediation-groups", nil)
	if status != http.StatusOK {
		h.t.Fatalf("GET remediation-groups = %d (body %.300s)", status, body)
	}
	var out struct {
		Groups []rgGroup `json:"groups"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		h.t.Fatalf("decode: %v (%.300s)", err, body)
	}
	m := map[string]rgGroup{}
	for _, g := range out.Groups {
		m[g.Key] = g
	}
	return m, body
}

func TestRemediationGroups_ListScoped(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.seedRemediationKeys()

	got, body := h.remediationGroups(h.memberA, false)
	if len(got) != 1 || got[rgKeyA].FindingCount != 1 || got[rgKeyA].AssetCount != 1 {
		t.Errorf("memberA groups = %+v, want only %s with 1 finding on 1 asset", got, rgKeyA)
	}
	if strings.Contains(body, rgKeyB) || strings.Contains(body, rgMarkerTitle) {
		t.Errorf("memberA remediation groups leaked group B: %.300s", body)
	}

	for _, who := range []struct {
		name  string
		user  shared.ID
		admin bool
	}{{"owner", h.owner, true}, {"full-data role", h.memberFull, false}} {
		got, _ := h.remediationGroups(who.user, who.admin)
		if len(got) != 2 || got[rgKeyA].FindingCount != 2 || got[rgKeyB].FindingCount != 1 {
			t.Errorf("%s groups = %+v, want A (2 findings) and B (1)", who.name, got)
		}
	}

	if got, _ := h.remediationGroups(h.memberStrict, false); len(got) != 0 {
		t.Errorf("policy nothing: member without group sees %+v, want none", got)
	}
	if got, _ := h.remediationGroups(h.owner, true); len(got) != 2 {
		t.Errorf("policy nothing: owner sees %d groups, want 2", len(got))
	}
}

func TestRemediationGroups_ResolveOnlyInScope(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.seedRemediationKeys()
	// fix_applied is reachable from in_progress (not from new/confirmed).
	h.exec(`UPDATE findings SET status = 'in_progress' WHERE id IN ($1, $2, $3)`,
		h.findingA.String(), h.findingB.String(), h.findingB2.String())
	resolve := func(user shared.ID, admin bool, key string) (int, string) {
		return h.do(user, admin, http.MethodPost, "/api/v1/findings/remediation-groups/"+url.PathEscape(key)+"/resolve",
			map[string]any{"status": "fix_applied", "resolution": "patched"})
	}

	// Group B is entirely out of scope: nothing changes, nothing is counted.
	if status, body := resolve(h.memberA, false, rgKeyB); status != http.StatusOK || !strings.Contains(body, `"updated":0`) || !strings.Contains(body, `"failed":0`) {
		t.Errorf("memberA resolve group B = %d %.200s, want updated 0 failed 0", status, body)
	}
	if st, _, _ := h.findingState(h.findingB); st != "in_progress" {
		t.Errorf("memberA resolve changed out-of-scope FB to %s", st)
	}

	// Group A: only FA moves; FB2 (B1) is neither changed nor reported.
	if status, body := resolve(h.memberA, false, rgKeyA); status != http.StatusOK || !strings.Contains(body, `"updated":1`) || !strings.Contains(body, `"failed":0`) {
		t.Errorf("memberA resolve group A = %d %.200s, want updated 1 failed 0", status, body)
	}
	if st, _, _ := h.findingState(h.findingA); st != "fix_applied" {
		t.Errorf("FA = %s, want fix_applied", st)
	}
	if st, _, _ := h.findingState(h.findingB2); st != "in_progress" {
		t.Errorf("out-of-scope FB2 changed to %s", st)
	}

	// The owner resolves the rest.
	if status, body := resolve(h.owner, true, rgKeyB); status != http.StatusOK || !strings.Contains(body, `"updated":1`) {
		t.Errorf("owner resolve group B = %d %.200s, want updated 1", status, body)
	}
}

func TestAssignToOwners_Scoped(t *testing.T) {
	h := newGroupScopeHarness(t)
	assign := func(user shared.ID, admin bool, cves ...string) (int, string) {
		return h.do(user, admin, http.MethodPost, "/api/v1/findings/actions/assign-to-owners",
			map[string]any{"filter": map[string]any{"cve_ids": cves}})
	}
	assignee := func(id shared.ID) string {
		_, _, a := h.findingState(id)
		return a
	}

	// A restricted member assigns only in-scope findings, and never a pentest
	// finding of a campaign they are not on (FP is on their own asset A1).
	if status, body := assign(h.memberA, false, h.cveA, h.cveB, h.cveB2, h.cveP); status != http.StatusOK {
		t.Fatalf("memberA assign-to-owners = %d %.200s", status, body)
	}
	if assignee(h.findingA) != h.memberA.String() {
		t.Errorf("in-scope FA assignee = %q, want memberA (A1's owner)", assignee(h.findingA))
	}
	for _, id := range []shared.ID{h.findingB, h.findingB2, h.findingP} {
		if a := assignee(id); a != "" {
			t.Errorf("memberA assigned %s (out of scope or pentest) to %s", id, a)
		}
	}

	// Policy "nothing": a member without a group assigns nothing.
	if status, body := assign(h.memberStrict, false, h.cveB); status != http.StatusOK || !strings.Contains(body, `"assigned":0`) {
		t.Errorf("policy nothing: member without group assign = %d %.200s, want assigned 0", status, body)
	}
	if a := assignee(h.findingB); a != "" {
		t.Errorf("policy nothing: member without group assigned FB to %s", a)
	}

	// An administrator is unrestricted even when they also hold a scope row.
	h.exec(`INSERT INTO user_accessible_assets (user_id, tenant_id, asset_id, ownership_type) VALUES ($1, $2, $3, 'secondary')`,
		h.owner.String(), h.tenant.String(), h.assetA.String())
	if status, body := assign(h.owner, true, h.cveB); status != http.StatusOK || !strings.Contains(body, `"assigned":1`) {
		t.Errorf("owner assign B = %d %.200s, want assigned 1", status, body)
	}
	if a := assignee(h.findingB); a != h.ownerB.String() {
		t.Errorf("owner assign: FB assignee = %q, want B1's owner", a)
	}
}
