package accesscontrol

import (
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Domain errors for access control.
var (
	// Asset ownership errors
	ErrAssetOwnerNotFound   = fmt.Errorf("%w: asset owner not found", shared.ErrNotFound)
	ErrAssetOwnerExists     = fmt.Errorf("%w: asset ownership already exists", shared.ErrAlreadyExists)
	ErrAccessGrantNotFound  = fmt.Errorf("%w: access grant not found", shared.ErrNotFound)
	ErrAccessGrantExists    = fmt.Errorf("%w: the user already has an access grant for this asset", shared.ErrAlreadyExists)
	ErrLastPrimaryOwner     = fmt.Errorf("%w: cannot remove the last primary owner", shared.ErrValidation)
	ErrInvalidOwnershipType = fmt.Errorf("%w: invalid ownership type", shared.ErrValidation)

	// Assignment rule errors
	ErrAssignmentRuleNotFound = fmt.Errorf("%w: assignment rule not found", shared.ErrNotFound)
	ErrAssignmentRuleInactive = fmt.Errorf("%w: assignment rule is inactive", shared.ErrValidation)
	ErrNoMatchingRule         = fmt.Errorf("%w: no matching assignment rule found", shared.ErrNotFound)
	ErrTargetGroupNotFound    = fmt.Errorf("%w: target group not found", shared.ErrNotFound)
	ErrTargetGroupInactive    = fmt.Errorf("%w: target group is inactive", shared.ErrValidation)

	// Access errors
	ErrAccessDenied           = fmt.Errorf("%w: access denied", shared.ErrForbidden)
	ErrInsufficientPermission = fmt.Errorf("%w: insufficient permissions", shared.ErrForbidden)
	ErrAssetAccessDenied      = fmt.Errorf("%w: access to asset denied", shared.ErrForbidden)
)

// IsAssetOwnerNotFound checks if the error is an asset owner not found error.
func IsAssetOwnerNotFound(err error) bool {
	return errors.Is(err, ErrAssetOwnerNotFound)
}

// IsAssetOwnerExists checks if the error is an asset owner exists error.
func IsAssetOwnerExists(err error) bool {
	return errors.Is(err, ErrAssetOwnerExists)
}

// IsAssignmentRuleNotFound checks if the error is an assignment rule not found error.
func IsAssignmentRuleNotFound(err error) bool {
	return errors.Is(err, ErrAssignmentRuleNotFound)
}

// IsAccessDenied checks if the error is an access denied error.
func IsAccessDenied(err error) bool {
	return errors.Is(err, ErrAccessDenied)
}

// IsInsufficientPermission checks if the error is an insufficient permission error.
func IsInsufficientPermission(err error) bool {
	return errors.Is(err, ErrInsufficientPermission)
}
