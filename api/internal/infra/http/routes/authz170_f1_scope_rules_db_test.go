package routes

// Research 170 (assets authz audit), fork 1: access-group changes that skip
// the D13 group-modification cap (requireWholeGroupInScope). Each test is
// written to FAIL while the hole exists.
//
// The actor is sdHarness.lead: a custom "team lead" role holding
// team:groups:* but no full data access, whose scope is assetIn only.

import (
	"net/http"
	"strings"
	"testing"
)

// TestAuthz170F1_DeleteForeignScopeRule: a scope rule on groupOut (created by
// an administrator) is deleted by the restricted lead. DeleteRule checks
// neither the rule-delegation cap nor the group cap, and the cleanup removes
// the rule-assigned assets from that team.
func TestAuthz170F1_DeleteForeignScopeRule(t *testing.T) {
	h := newSDHarness(t)
	rules := "/api/v1/groups/" + h.groupOut + "/scope-rules"
	out := h.expect(h.admin, true, http.MethodPost, rules, map[string]any{
		"name": "admin rule", "rule_type": "tag_match", "match_tags": []string{"bu-out"}, "match_logic": "any",
		"ownership_type": "secondary",
	}, http.StatusCreated)
	id := jsonField(out, "id")
	if id == "" {
		t.Fatalf("could not create the admin's rule: %s", out)
	}
	status, body := h.do(h.lead, false, http.MethodDelete, rules+"/"+id, nil)
	if status < 400 {
		t.Errorf("restricted lead deleted another team's scope rule: DELETE = %d (%.200s)", status, body)
	}
}

// TestAuthz170F1_GroupAssetCountTenantWide: GET /groups shows asset_count
// over every asset of the team, including assets outside the reader's scope
// (the asset-group counters were fixed, access-group counters were not).
func TestAuthz170F1_GroupAssetCountTenantWide(t *testing.T) {
	h := newSDHarness(t)
	_, body := h.do(h.lead, false, http.MethodGet, "/api/v1/groups/"+h.groupOut, nil)
	if strings.Contains(body, `"asset_count":1`) {
		t.Errorf("restricted lead sees asset_count 1 for a team whose only asset is outside their scope: %.300s", body)
	}
}

func jsonField(body, key string) string {
	i := strings.Index(body, `"`+key+`":"`)
	if i < 0 {
		return ""
	}
	rest := body[i+len(key)+4:]
	j := strings.IndexByte(rest, '"')
	if j < 0 {
		return ""
	}
	return rest[:j]
}
