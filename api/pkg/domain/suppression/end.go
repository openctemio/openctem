package suppression

import (
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Every suppression rule ends: a rule hides findings (as false positives or
// accepted risk) from the backlog and the CI gate, so an end that is never
// reached would hide them for good. A rule made without an end gets
// DefaultRuleDuration; no rule may end more than MaxRuleDuration ahead.
// Renewal is a new rule, reviewed and approved again.
const (
	DefaultRuleDuration = 90 * 24 * time.Hour
	MaxRuleDuration     = 365 * 24 * time.Hour
)

// ReviewReasonNoEndDate flags a rule the platform gave an end because it had
// none (rules made before an end was required).
const ReviewReasonNoEndDate = "no_end_date"

// ErrRuleEndRequired: a rule's end cannot be removed.
var ErrRuleEndRequired = fmt.Errorf("%w: a suppression rule always has an end date (at most 365 days ahead)", shared.ErrValidation)

// RuleEnd returns the end a rule takes: the default from now when none is
// asked, otherwise a future time at most MaxRuleDuration from now.
func RuleEnd(requested *time.Time, now time.Time) (time.Time, error) {
	if requested == nil {
		return now.Add(DefaultRuleDuration), nil
	}
	if !requested.After(now) {
		return time.Time{}, fmt.Errorf("%w: the end date of a suppression rule must be in the future", shared.ErrValidation)
	}
	if requested.After(now.Add(MaxRuleDuration)) {
		return time.Time{}, fmt.Errorf("%w: a suppression rule ends within 365 days", shared.ErrValidation)
	}
	return *requested, nil
}
