package routes

// Research 170 (assets authz audit), fork 1: access-group changes that skip
// the D13 group-modification cap (requireWholeGroupInScope). Each test is
// written to FAIL while the hole exists.
//
// The actor is sdHarness.lead: a custom "team lead" role holding
// team:groups:* but no full data access, whose scope is assetIn only.

import (
	"net/http"
	"testing"
)

// TestAuthz170F1_ReactivateGroupWidensOwnScope: an administrator turns off a
// team (groupOut, holding assetOut) to cut its members' access. A restricted
// lead who is a member of that team turns it back on with PUT /groups/{id}
// and regains assetOut. UpdateGroup never applies the cap.
func TestAuthz170F1_ReactivateGroupWidensOwnScope(t *testing.T) {
	h := newSDHarness(t)
	// The lead is a legitimate member of groupIn (assetIn) and of groupOut.
	h.exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member'), ($3, $2, 'member')`,
		h.groupIn, h.lead, h.groupOut)
	h.exec(`SELECT refresh_access_for_user($1, $2)`, h.tenant, h.lead)
	// The administrator deactivates groupOut: the trigger drops the lead's assetOut row.
	h.exec(`UPDATE groups SET is_active = FALSE WHERE id = $1`, h.groupOut)
	if n := h.count(`SELECT COUNT(*) FROM user_accessible_assets WHERE user_id = $1 AND asset_id = $2`, h.lead, h.assetOut); n != 0 {
		t.Fatalf("precondition: lead still holds assetOut after deactivation (%d rows)", n)
	}

	status, body := h.do(h.lead, false, http.MethodPut, "/api/v1/groups/"+h.groupOut, map[string]any{"is_active": true})
	if status < 400 {
		t.Errorf("restricted lead reactivated a team holding an asset outside their scope: PUT = %d (%.200s)", status, body)
	}
	if n := h.count(`SELECT COUNT(*) FROM user_accessible_assets WHERE user_id = $1 AND asset_id = $2`, h.lead, h.assetOut); n != 0 {
		t.Errorf("restricted lead widened their own scope to assetOut by reactivating the team (%d rows)", n)
	}
}

// TestAuthz170F1_DeactivateForeignGroup: the same lead deactivates another
// business unit's team (groupOut, whose asset they cannot see), revoking
// every member's access. RemoveMember/UnassignAsset refuse this with the
// cap; UpdateGroup does not.
func TestAuthz170F1_DeactivateForeignGroup(t *testing.T) {
	h := newSDHarness(t)
	h.exec(`INSERT INTO group_members (group_id, user_id, role) VALUES ($1, $2, 'member')`, h.groupOut, h.peer)
	h.exec(`SELECT refresh_access_for_user($1, $2)`, h.tenant, h.peer)

	status, body := h.do(h.lead, false, http.MethodPut, "/api/v1/groups/"+h.groupOut, map[string]any{"is_active": false})
	if status < 400 {
		t.Errorf("restricted lead deactivated a team holding an asset outside their scope: PUT = %d (%.200s)", status, body)
	}
	if n := h.count(`SELECT COUNT(*) FROM user_accessible_assets WHERE user_id = $1 AND asset_id = $2`, h.peer, h.assetOut); n != 1 {
		t.Errorf("peer lost access to assetOut through the lead's change (%d rows)", n)
	}
}
