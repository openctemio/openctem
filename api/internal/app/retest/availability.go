package retest

import "errors"

// Reason codes for a retest that would be refused. They are stable API
// values (the finding verification plan returns them); the console words them.
const (
	ReasonStatusNotEligible          = "status_not_eligible"
	ReasonSecretNeedsRotation        = "secret_needs_rotation"
	ReasonCheckCannotRun             = "check_cannot_run"
	ReasonNoToolRule                 = "no_tool_rule"
	ReasonTemplateNotRerun           = "template_not_rerun"
	ReasonNoAsset                    = "no_asset"
	ReasonAssetInactive              = "asset_inactive"
	ReasonAssetNotNetworkAddressable = "asset_not_network_addressable"
	ReasonAssetNoAddress             = "asset_no_address"
	ReasonTargetRefused              = "target_refused"
	ReasonNoSensor                   = "no_sensor"
	ReasonNoCheckSensor              = "no_check_sensor"
	// ReasonNotEligible is the fallback for an ineligibility without a code.
	ReasonNotEligible = "not_eligible"
)

// ineligibleError carries the reason code of an ineligibility; it unwraps to
// the wrapped error, so errors.Is(err, retestdom.ErrNotEligible) still holds.
type ineligibleError struct {
	code string
	err  error
}

func (e *ineligibleError) Error() string { return e.err.Error() }
func (e *ineligibleError) Unwrap() error { return e.err }

func ineligible(code string, err error) error { return &ineligibleError{code: code, err: err} }

// IneligibleReason is the reason code an ineligibility error carries, or
// ReasonNotEligible when it carries none.
func IneligibleReason(err error) string {
	var ie *ineligibleError
	if errors.As(err, &ie) {
		return ie.code
	}
	return ReasonNotEligible
}
