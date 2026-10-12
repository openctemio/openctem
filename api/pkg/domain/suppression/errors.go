package suppression

import (
	"errors"
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Domain errors for suppression rules.
var (
	ErrRuleNotFound      = errors.New("suppression rule not found")
	ErrRuleAlreadyExists = errors.New("suppression rule already exists")
	ErrRuleNotPending    = errors.New("suppression rule is not pending")
	ErrRuleExpired       = errors.New("suppression rule has expired")
	ErrInvalidCriteria   = errors.New("invalid suppression criteria")
	ErrSuppressionExists = errors.New("finding already suppressed by this rule")

	// ErrSelfApproval: the requester tried to approve their own rule while
	// another person could approve it (owner decision B16).
	ErrSelfApproval = fmt.Errorf("%w: a suppression rule must be approved by someone other than its requester", shared.ErrForbidden)
	// ErrRuleChangedSinceReview: the rule was edited after the approver
	// loaded it; the approver must review the current version.
	ErrRuleChangedSinceReview = fmt.Errorf("%w: the rule changed since you reviewed it; review it again", shared.ErrConflict)
	// ErrReviewedVersionRequired: an approval must name the version reviewed.
	ErrReviewedVersionRequired = fmt.Errorf("%w: reviewed_updated_at is required to approve a rule", shared.ErrValidation)
)
