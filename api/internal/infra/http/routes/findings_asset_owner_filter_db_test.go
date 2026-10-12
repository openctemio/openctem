package routes

// asset_owner_id: the list filter behind "View" on a group-by-owner row
// (research 24 P0-1). It uses the grouping's own rule (the asset's first
// primary user owner), so a group's total equals the list it drills into,
// inside the caller's scope.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestFindingsList_AssetOwnerFilterMatchesTheOwnerGroups(t *testing.T) {
	h := newGroupScopeHarness(t)
	fa, fb, fb2 := h.findingA.String(), h.findingB.String(), h.findingB2.String()
	admin := flCaller{"owner", h.owner, true}
	memberA := flCaller{"memberA", h.memberA, false}

	cases := []struct {
		query          string
		admin, memberA []string
	}{
		// memberA owns A1 (FA, and the pentest FP the list shows only to
		// campaign members); ownerB owns B1 (FB, FB2).
		{"source_not=pentest&asset_owner_id=" + h.memberA.String(), sorted(fa), sorted(fa)},
		{"asset_owner_id=" + h.ownerB.String(), sorted(fb, fb2), nil},
		{"asset_owner_id=" + h.memberA.String() + "," + h.ownerB.String() + "&source_not=pentest", sorted(fa, fb, fb2), sorted(fa)},
		{"asset_owner_id_null=true", nil, nil},
	}
	for _, c := range cases {
		for _, who := range []struct {
			caller flCaller
			want   []string
		}{{admin, c.admin}, {memberA, c.memberA}} {
			ids, total, _ := h.listIDs(t, who.caller, c.query)
			if strings.Join(ids, ",") != strings.Join(who.want, ",") || total != int64(len(who.want)) {
				t.Errorf("%s ?%s = %v (total %d), want %v", who.caller.name, c.query, ids, total, who.want)
			}
		}
	}

	// Every owner group's total equals the list its View opens.
	h.exec(`DELETE FROM asset_owners WHERE asset_id = $1`, h.assetB.String()) // B1 becomes "unassigned"
	for _, who := range []flCaller{admin, memberA} {
		status, _, body := h.listFindingsPath(t, who, "/api/v1/findings/groups?group_by=owner_id&per_page=100")
		if status != http.StatusOK {
			t.Fatalf("groups = %d %s", status, body)
		}
		var out gsGroupsResponse
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Data) == 0 {
			t.Fatalf("%s: no owner groups", who.name)
		}
		for _, g := range out.Data {
			q := "source_not=pentest&asset_owner_id=" + g.GroupKey
			if g.GroupKey == "unassigned" {
				q = "source_not=pentest&asset_owner_id_null=true"
			}
			if _, total, _ := h.listIDs(t, who, q); total != int64(g.Stats.Total) {
				t.Errorf("%s owner group %s total %d != list ?%s total %d", who.name, g.GroupKey, g.Stats.Total, q, total)
			}
		}
	}
}
