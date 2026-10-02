package group

import (
	"errors"
	"fmt"

	"github.com/openctemio/api/pkg/domain/shared"
)

// Domain errors for groups.
var (
	ErrGroupNotFound       = fmt.Errorf("%w: group not found", shared.ErrNotFound)
	ErrGroupSlugExists     = fmt.Errorf("%w: group slug already exists", shared.ErrAlreadyExists)
	ErrMemberNotFound      = fmt.Errorf("%w: group member not found", shared.ErrNotFound)
	ErrMemberAlreadyExists = fmt.Errorf("%w: user is already a member of this group", shared.ErrAlreadyExists)
	ErrLastOwner           = fmt.Errorf("%w: cannot remove the last owner of the group", shared.ErrValidation)
	ErrCannotRemoveSelf    = fmt.Errorf("%w: cannot remove yourself from the group", shared.ErrValidation)
	ErrMaxMembersReached   = fmt.Errorf("%w: maximum number of members reached", shared.ErrValidation)
	ErrInactiveGroup       = fmt.Errorf("%w: group is inactive", shared.ErrValidation)
	ErrExternalGroupSync   = fmt.Errorf("%w: cannot modify externally synced group", shared.ErrValidation)
)

// IsGroupNotFound checks if the error is a group not found error.
func IsGroupNotFound(err error) bool {
	return errors.Is(err, ErrGroupNotFound)
}

// IsGroupSlugExists checks if the error is a slug exists error.
func IsGroupSlugExists(err error) bool {
	return errors.Is(err, ErrGroupSlugExists)
}

// IsMemberNotFound checks if the error is a member not found error.
func IsMemberNotFound(err error) bool {
	return errors.Is(err, ErrMemberNotFound)
}

// IsMemberAlreadyExists checks if the error is a member already exists error.
func IsMemberAlreadyExists(err error) bool {
	return errors.Is(err, ErrMemberAlreadyExists)
}
