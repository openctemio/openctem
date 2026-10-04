package tenant

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// What members without an access group see — the organization's data-scope
// policy, stored in tenants.members_without_group_see (migration 000247).
// Owners and admins always see everything; members with an access group see
// that group's assets. The policy only decides the members with none.
const (
	// MembersWithoutGroupSeeEverything is fail-open: they see every asset and
	// finding of the organization. Organizations created before migration
	// 000247 keep this value.
	MembersWithoutGroupSeeEverything = "everything"
	// MembersWithoutGroupSeeNothing is fail-closed: they see no asset or
	// finding until they are added to an access group. The default for new
	// organizations.
	MembersWithoutGroupSeeNothing = "nothing"
)

// ValidateMembersWithoutGroupSee checks a policy value.
func ValidateMembersWithoutGroupSee(v string) error {
	switch v {
	case MembersWithoutGroupSeeEverything, MembersWithoutGroupSeeNothing:
		return nil
	default:
		return fmt.Errorf("%w: members_without_group_see must be %q or %q",
			shared.ErrValidation, MembersWithoutGroupSeeEverything, MembersWithoutGroupSeeNothing)
	}
}

// RestrictsMembersWithoutGroup reports whether the policy is fail-closed.
// Anything but "everything" restricts, so an unexpected value fails closed.
func RestrictsMembersWithoutGroup(v string) bool {
	return v != MembersWithoutGroupSeeEverything
}

// ErrSeeEverythingRetired: an organization that restricts members without an
// access group cannot go back to showing them everything (owner decision D2,
// research doc 15 L-04).
var ErrSeeEverythingRetired = fmt.Errorf("%w: \"everything\" is being retired; once members without a team see nothing, it cannot be switched back. Add the members to a team instead", shared.ErrValidation)

// ScopeImpactMember is a member who would see nothing once the organization
// stops showing everything to members without an access group: not an owner
// or admin, no role with full data access, and no data-scope row.
type ScopeImpactMember struct {
	UserID string
	Name   string
	Email  string
	Role   string
}
