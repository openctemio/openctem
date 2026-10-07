package workflow

import (
	"fmt"
	"slices"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// ErrCodeInvalidTriggerConfig is the domain error code for a trigger option
// the platform would never match.
const ErrCodeInvalidTriggerConfig = "INVALID_TRIGGER_CONFIG"

// ScanOutcomes are the scan run outcomes the scan_completed trigger can
// filter on (trigger_config.status_filter). Without a filter it fires on
// completed runs only.
var ScanOutcomes = []string{"completed", "partial", "failed"}

// ValidateTriggerConfig refuses trigger options that would make the trigger
// silently never fire: a scan_completed status_filter that is not a list of
// known outcomes.
func ValidateTriggerConfig(configs ...NodeConfig) error {
	for _, c := range configs {
		if c.TriggerType != TriggerTypeScanCompleted || c.TriggerConfig == nil {
			continue
		}
		raw, present := c.TriggerConfig["status_filter"]
		if !present || raw == nil {
			continue
		}
		list, ok := raw.([]any)
		if !ok {
			return invalidTriggerConfig("status_filter must be a list of scan outcomes")
		}
		for _, v := range list {
			s, ok := v.(string)
			if !ok || !slices.Contains(ScanOutcomes, s) {
				return invalidTriggerConfig(fmt.Sprintf("status_filter: %v is not a scan outcome (one of %v)", v, ScanOutcomes))
			}
		}
	}
	return nil
}

func invalidTriggerConfig(msg string) error {
	return shared.NewDomainError(ErrCodeInvalidTriggerConfig, msg, shared.ErrValidation)
}
