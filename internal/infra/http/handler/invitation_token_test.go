package handler

import (
	"testing"

	"github.com/openctemio/api/pkg/domain/tenant"
)

// Invitation tokens are credentials: a member or viewer who could read them
// could accept an invitation meant for someone else (with its role) by
// registering that email. Only the roles that create invitations see them.
func TestCanSeeInvitationTokens(t *testing.T) {
	for role, want := range map[tenant.Role]bool{
		tenant.RoleOwner:  true,
		tenant.RoleAdmin:  true,
		tenant.RoleMember: false,
		tenant.RoleViewer: false,
		"":                false,
	} {
		if got := canSeeInvitationTokens(role); got != want {
			t.Errorf("%q: got %v, want %v", role, got, want)
		}
	}
}
