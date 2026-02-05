package suppression

import "errors"

// Domain errors for suppression rules.
var (
	ErrRuleNotFound      = errors.New("suppression rule not found")
	ErrRuleAlreadyExists = errors.New("suppression rule already exists")
	ErrRuleNotPending    = errors.New("suppression rule is not pending")
	ErrRuleExpired       = errors.New("suppression rule has expired")
	ErrInvalidCriteria   = errors.New("invalid suppression criteria")
	ErrSuppressionExists = errors.New("finding already suppressed by this rule")
)
