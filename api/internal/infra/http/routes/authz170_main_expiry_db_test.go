package routes

// Research 170 (assets authz audit): an access-team membership that has
// passed its end date must not grant data scope. Team ROLES honour the end
// date at read time (v_user_role_grants filters expires_at), but the data
// scope (user_accessible_assets) is only cleaned when the expiry controller
// deletes the row, and the scope triggers that add rows ignore expires_at.
// This test FAILS while that gap is open.

import (
	"net/http"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

func TestAuthz170Main_ExpiredTeamMembershipStillGrantsScope(t *testing.T) {
	h := newDSHarness(t)
	team := shared.NewID()
	h.exec(`INSERT INTO groups (id, tenant_id, name, slug, group_type) VALUES ($1, $2, 'a170-team', $3, 'external')`,
		team.String(), h.tenant.String(), "a170-"+team.String()[:8])
	// memberStrict's membership ended an hour ago; the controller has not run yet.
	h.exec(`INSERT INTO group_members (group_id, user_id, expires_at, expiry_reason) VALUES ($1, $2, now() - interval '1 hour', 'audit ended')`,
		team.String(), h.memberStrict.String())
	// The team is then given asset B1 (scope trigger materializes rows).
	h.exec(`INSERT INTO asset_owners (asset_id, group_id, ownership_type) VALUES ($1, $2, 'secondary')`,
		h.assetB.String(), team.String())

	status, body := h.do(h.memberStrict, false, http.MethodGet, "/api/v1/assets/"+h.assetB.String(), nil)
	if status != http.StatusNotFound {
		t.Errorf("expired team member GET asset B1 = %d, want 404 (membership ended; body %.160s)", status, body)
	}
}
