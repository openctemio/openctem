package routes

// The state lens (research 24 §2.2, owner decision C2): state=open|fixed|
// dispositioned|all is one filter field, so for every lens the list total,
// the stats total, the sum of the groups and the export rows agree, for an
// administrator, a scoped member and an unrestricted member. A disposition
// (false positive, accepted, duplicate) is never counted as fixed.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// seedLensFindings adds one finding per interesting status on in-scope A1
// and returns their ids by status. FA (confirmed) is already on A1; FB and
// FB2 (critical / high, confirmed) are on out-of-scope B1.
func (h *gsHarness) seedLensFindings(t *testing.T) map[string]string {
	t.Helper()
	ids := map[string]string{}
	for _, st := range []string{"new", "fix_applied", "not_observed", "resolved", "verified", "false_positive", "accepted", "duplicate"} {
		id := shared.NewID()
		resolvedAt := "NULL"
		switch st {
		case "resolved", "verified", "false_positive", "accepted", "duplicate":
			resolvedAt = "now() - interval '3 days'"
		}
		h.exec(fmt.Sprintf(`INSERT INTO findings (id, tenant_id, asset_id, source, tool_name, message, severity, fingerprint, status, finding_type, resolved_at)
			VALUES ($1::uuid, $2, $3, 'sast', 'ds-tool', 'lens finding', 'medium', $1::text, $4, 'vulnerability', %s)`, resolvedAt),
			id.String(), h.tenant.String(), h.assetA.String(), st)
		ids[st] = id.String()
	}
	// An out-of-scope resolved finding: it must never count for memberA.
	h.exec(`UPDATE findings SET status = 'resolved', resolved_at = now() - interval '40 days' WHERE id = $1`, h.findingB2.String())
	return ids
}

func (h *gsHarness) statsByState(t *testing.T, c flCaller, query string) map[string]int64 {
	t.Helper()
	status, _, body := h.listFindingsPath(t, c, "/api/v1/findings/stats?"+query)
	if status != http.StatusOK {
		t.Fatalf("%s stats?%s = %d: %.300s", c.name, query, status, body)
	}
	var out struct {
		ByState map[string]int64 `json:"by_state"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	return out.ByState
}

func TestFindingsStateLens_CountContract(t *testing.T) {
	h := newGroupScopeHarness(t)
	ids := h.seedLensFindings(t)
	fa, fb, fb2 := h.findingA.String(), h.findingB.String(), h.findingB2.String()
	admin := flCaller{"owner", h.owner, true}
	memberA := flCaller{"memberA", h.memberA, false}
	full := flCaller{"full-data role", h.memberFull, false}
	exportPerms := strings.Join(append(append([]string{}, dsMemberPerms...), permission.FindingsExport.String()), ",")

	want := map[string]map[string][]string{
		"open": {
			"owner":   sorted(fa, fb, ids["new"], ids["fix_applied"], ids["not_observed"]),
			"memberA": sorted(fa, ids["new"], ids["fix_applied"], ids["not_observed"]),
		},
		"fixed": {
			"owner":   sorted(fb2, ids["resolved"], ids["verified"]),
			"memberA": sorted(ids["resolved"], ids["verified"]),
		},
		"dispositioned": {
			"owner":   sorted(ids["false_positive"], ids["accepted"], ids["duplicate"]),
			"memberA": sorted(ids["false_positive"], ids["accepted"], ids["duplicate"]),
		},
	}
	allOwner := append(append(append([]string{}, want["open"]["owner"]...), want["fixed"]["owner"]...), want["dispositioned"]["owner"]...)
	allMember := append(append(append([]string{}, want["open"]["memberA"]...), want["fixed"]["memberA"]...), want["dispositioned"]["memberA"]...)
	want["all"] = map[string][]string{"owner": sorted(allOwner...), "memberA": sorted(allMember...)}
	want["open"]["full-data role"] = want["open"]["owner"]
	want["fixed"]["full-data role"] = want["fixed"]["owner"]
	want["dispositioned"]["full-data role"] = want["dispositioned"]["owner"]
	want["all"]["full-data role"] = want["all"]["owner"]

	for _, state := range []string{"open", "fixed", "dispositioned", "all"} {
		for _, c := range []flCaller{admin, memberA, full} {
			t.Run(state+"/"+c.name, func(t *testing.T) {
				// The grouped view never shows pentest findings; the matrix
				// excludes them for every caller, like the count contract.
				query := "source_not=pentest&state=" + state
				ids, listTotal, _ := h.listIDs(t, c, query+"&per_page=100")
				if strings.Join(ids, ",") != strings.Join(want[state][c.name], ",") {
					t.Errorf("list ?%s = %v, want %v", query, ids, want[state][c.name])
				}
				if st := h.statsTotal(t, c, query); st != listTotal {
					t.Errorf("stats total %d != list total %d", st, listTotal)
				}
				for _, dim := range []string{"severity", "source", "finding_type"} {
					if sum := h.groupsSum(t, c, dim, query); sum != listTotal {
						t.Errorf("groups by %s sum %d != list total %d", dim, sum, listTotal)
					}
				}
				resp, body := h.export(t, c, http.MethodGet, query, nil, exportPerms)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("export ?%s = %d %.200s", query, resp.StatusCode, body)
				}
				if rows := csvIDs(t, body); int64(len(rows)) != listTotal {
					t.Errorf("export rows %d != list total %d", len(rows), listTotal)
				}
				if c.name == "memberA" && (strings.Contains(body, fb) || strings.Contains(body, fb2)) {
					t.Errorf("memberA export leaked an out-of-scope finding")
				}
			})
		}
	}

	// by_state on stats: the lens counts of the same filter, side by side,
	// scoped like every other number.
	for _, c := range []flCaller{admin, memberA} {
		got := h.statsByState(t, c, "source_not=pentest")
		for _, state := range []string{"open", "fixed", "dispositioned", "all"} {
			if got[state] != int64(len(want[state][c.name])) {
				t.Errorf("%s stats by_state[%s] = %d, want %d (%v)", c.name, state, got[state], len(want[state][c.name]), got)
			}
		}
	}

	// A scoped member asking for the fixed lens of an out-of-scope asset
	// gets nothing (empty, not an error).
	if ids, total, _ := h.listIDs(t, memberA, "state=fixed&asset_id="+h.assetB.String()); len(ids) != 0 || total != 0 {
		t.Errorf("memberA fixed lens on B1 = %v (total %d), want none", ids, total)
	}
	// An unknown lens is a 400 INVALID_FILTER, not "everything".
	if status, _, body := h.listFindings(t, admin, "state=closed"); status != http.StatusBadRequest || !strings.Contains(body, "INVALID_FILTER") {
		t.Errorf("state=closed = %d %.200s, want 400 INVALID_FILTER", status, body)
	}
}

// resolved_at narrows the fixed lens to a window ("fixed this month").
func TestFindingsStateLens_ResolvedAtWindow(t *testing.T) {
	h := newGroupScopeHarness(t)
	ids := h.seedLensFindings(t)
	admin := flCaller{"owner", h.owner, true}
	got, total, _ := h.listIDs(t, admin, "state=fixed&resolved_at_gte=-P30D")
	if want := sorted(ids["resolved"], ids["verified"]); strings.Join(got, ",") != strings.Join(want, ",") || total != 2 {
		t.Errorf("fixed in the last 30 days = %v (total %d), want %v (FB2 was fixed 40 days ago)", got, total, want)
	}
	if got, _, _ := h.listIDs(t, admin, "state=fixed&resolved_at_lt=-P30D"); len(got) != 1 || got[0] != h.findingB2.String() {
		t.Errorf("fixed before 30 days ago = %v, want [FB2]", got)
	}
}
