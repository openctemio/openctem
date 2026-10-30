package automation

import (
	"fmt"
	"slices"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Guardrails every automation obeys (RFC-125 D9, D14).
//
//   - update_status moves a finding only to confirmed or in progress. No
//     action writes false positive, accepted, resolved or duplicate: closing
//     risk is a person's decision, which an automation may only request
//     (request_false_positive, request_risk_acceptance).
//   - A live run makes at most MaxChangesPerRun changes (default 250, at most
//     1,000); the next one pauses the run until a publisher lets it continue.
//     A cap above the default makes the automation high risk.

// AutomationStatusTargets are the statuses update_status may set.
var AutomationStatusTargets = []string{"confirmed", "in_progress"}

// ErrCodeStatusNotAllowed is the error code for an update_status target
// outside AutomationStatusTargets.
const ErrCodeStatusNotAllowed = "AUTOMATION_STATUS_NOT_ALLOWED"

// StatusTargetAllowed reports whether update_status may set status.
func StatusTargetAllowed(status string) bool { return slices.Contains(AutomationStatusTargets, status) }

// ValidateStatusTargets refuses an update_status config whose target is not
// allowed.
func ValidateStatusTargets(configs ...NodeConfig) error {
	for _, c := range configs {
		if c.ActionType != ActionTypeUpdateStatus {
			continue
		}
		status, _ := c.ActionConfig["status"].(string)
		if status != "" && !StatusTargetAllowed(status) {
			return shared.NewDomainError(ErrCodeStatusNotAllowed,
				fmt.Sprintf("an automation may set a finding's status only to %v; %q is a person's decision (use a request action for a false positive or an accepted risk)", AutomationStatusTargets, status),
				shared.ErrValidation)
		}
	}
	return nil
}

// Change cap of a live run.
const (
	DefaultMaxChangesPerRun = 250
	MaxMaxChangesPerRun     = 1000
)

// ValidateMaxChanges refuses a cap outside 1..MaxMaxChangesPerRun (0 means the default).
func ValidateMaxChanges(n int) error {
	if n < 0 || n > MaxMaxChangesPerRun {
		return shared.NewDomainError("VALIDATION", fmt.Sprintf("max_changes_per_run must be between 1 and %d", MaxMaxChangesPerRun), shared.ErrValidation)
	}
	return nil
}

// EffectiveMaxChanges is the cap in force for a stored value (0: default).
func EffectiveMaxChanges(n int) int {
	if n <= 0 {
		return DefaultMaxChangesPerRun
	}
	return n
}

// Request action settings.
const (
	MaxAcceptanceDays = 365
)

// ValidateRequestConfigs refuses a request action without the reason and
// note every request carries, or a risk acceptance without an end within
// MaxAcceptanceDays.
func ValidateRequestConfigs(configs ...NodeConfig) error {
	for _, c := range configs {
		if c.ActionType != ActionTypeRequestFalsePositive && c.ActionType != ActionTypeRequestRiskAcceptance {
			continue
		}
		reason, _ := c.ActionConfig["closure_reason"].(string)
		note, _ := c.ActionConfig["justification"].(string)
		if reason == "" || note == "" {
			return shared.NewDomainError("VALIDATION", string(c.ActionType)+" needs closure_reason and justification", shared.ErrValidation)
		}
		if c.ActionType == ActionTypeRequestRiskAcceptance {
			days, ok := c.ActionConfig["expires_in_days"].(float64)
			if !ok || days < 1 || days > MaxAcceptanceDays || days != float64(int(days)) {
				return shared.NewDomainError("VALIDATION", fmt.Sprintf("request_risk_acceptance needs expires_in_days between 1 and %d", MaxAcceptanceDays), shared.ErrValidation)
			}
		}
	}
	return nil
}
