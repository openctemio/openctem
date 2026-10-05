package routes

// The count contract of RFC-048: GET /findings, /findings/stats and
// /findings/groups compile the same filter as the same caller, so for any
// filter the list total, the stats total and the sum of the groups of a
// disjoint dimension are equal, for an administrator, a scoped member and an
// unrestricted member. Export joins this matrix when it ships.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func (h *gsHarness) statsTotal(t *testing.T, c flCaller, query string) int64 {
	t.Helper()
	status, _, body := h.listFindingsPath(t, c, "/api/v1/findings/stats?"+query)
	if status != http.StatusOK {
		t.Fatalf("%s stats?%s = %d: %.300s", c.name, query, status, body)
	}
	var out struct {
		Total int64 `json:"total"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out.Total
}

func (h *gsHarness) groupsSum(t *testing.T, c flCaller, groupBy, query string) int64 {
	t.Helper()
	status, _, body := h.listFindingsPath(t, c, "/api/v1/findings/groups?group_by="+groupBy+"&per_page=100&"+query)
	if status != http.StatusOK {
		t.Fatalf("%s groups?%s = %d: %.300s", c.name, query, status, body)
	}
	var out gsGroupsResponse
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	var sum int64
	for _, g := range out.Data {
		sum += int64(g.Stats.Total)
	}
	return sum
}

func TestFindingsCountContract_ListStatsGroupsAgree(t *testing.T) {
	h := newGroupScopeHarness(t)
	h.exec(`UPDATE assets SET tags = ARRAY['prod'] WHERE id = $1`, h.assetA.String())
	// Every finding has a family, so family is a disjoint dimension too.
	h.exec(`UPDATE findings SET family = CASE WHEN severity = 'critical' THEN 'General' ELSE 'CGI abuses' END WHERE tenant_id = $1`, h.tenant.String())
	callers := []flCaller{
		{"owner", h.owner, true},
		{"memberA", h.memberA, false},
		{"full-data role", h.memberFull, false},
	}
	// The grouped view never shows pentest findings (they have their own
	// campaign views), so the matrix excludes them for every caller; for a
	// non-member they are invisible anyway.
	filters := []string{
		"",
		"severity=high",
		"severities=critical,high",
		"source=sast",
		"asset_id=" + h.assetB.String(),
		"asset_tags=prod",
		"asset_tag_not=prod",
		"cve_id=" + h.cveB,
		"finding_type=vulnerability",
		"status_not=resolved",
		"id=" + h.findingB.String(),
		"q=dsB-SECRET",
		"family=General",
		"related_to=me",
	}
	for _, f := range filters {
		query := "source_not=pentest"
		if f != "" {
			query += "&" + f
		}
		for _, c := range callers {
			t.Run(fmt.Sprintf("%s/%s", c.name, f), func(t *testing.T) {
				_, listTotal, _ := h.listIDs(t, c, query)
				statsTotal := h.statsTotal(t, c, query)
				if listTotal != statsTotal {
					t.Errorf("list total %d != stats total %d", listTotal, statsTotal)
				}
				for _, dim := range []string{"severity", "source", "finding_type", "family"} {
					if sum := h.groupsSum(t, c, dim, query); sum != listTotal {
						t.Errorf("groups by %s sum %d != list total %d", dim, sum, listTotal)
					}
				}
			})
		}
	}
}

// Out-of-scope rows contribute nothing to any count, and the stats of the
// pentest finding stay hidden from a non-member (the old stats query counted
// it: the metric strip disagreed with the table and leaked its existence).
func TestFindingsCountContract_ScopeAndPentest(t *testing.T) {
	h := newGroupScopeHarness(t)
	memberA := flCaller{"memberA", h.memberA, false}
	for _, q := range []string{"asset_id=" + h.assetB.String(), "id=" + h.findingB.String(), "cve_id=" + h.cveB2, "source=pentest"} {
		if n := h.statsTotal(t, memberA, q); n != 0 {
			t.Errorf("memberA stats?%s total = %d, want 0", q, n)
		}
	}
	if n := h.statsTotal(t, memberA, ""); n != 1 {
		t.Errorf("memberA stats total = %d, want 1 (FA only)", n)
	}
	free := flCaller{"full-data role", h.memberFull, false}
	if n := h.statsTotal(t, free, "source=pentest"); n != 0 {
		t.Errorf("non-member stats counted the pentest finding: %d", n)
	}
	if n := h.statsTotal(t, flCaller{"owner", h.owner, true}, "source=pentest"); n != 1 {
		t.Errorf("owner stats source=pentest = %d, want 1", n)
	}

	strict := flCaller{"strict", h.memberStrict, false}
	if n := h.statsTotal(t, strict, ""); n != 0 {
		t.Errorf("strict member stats total = %d, want 0", n)
	}
	if sum := h.groupsSum(t, strict, "severity", ""); sum != 0 {
		t.Errorf("strict member groups sum = %d, want 0", sum)
	}
}
