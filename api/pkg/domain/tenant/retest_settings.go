package tenant

import (
	"fmt"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Auto-retest bounds (RFC-039 §8.1). The defaults apply when a field is zero.
const (
	DefaultRetestIntervalHours = 24
	MinRetestIntervalHours     = 6
	MaxRetestIntervalHours     = 168
	DefaultRetestDailyCap      = 200
	MaxRetestDailyCap          = 2000
)

// RetestSettings controls auto-retest for a tenant (RFC-039): re-running the
// exact check that produced each eligible finding about once per interval, so a
// fixed issue is closed and a regression reopened without a person.
//
// AutoEnabled defaults to false (zero value) for every tenant until the scans
// redesign P1 (HA scheduler claims, leases) lands. Manual "Retest now" does not
// depend on it.
type RetestSettings struct {
	AutoEnabled bool `json:"auto_enabled"`
	// IntervalHours is how often each eligible finding is retested.
	// 0 = DefaultRetestIntervalHours.
	IntervalHours int `json:"interval_hours,omitempty"`
	// DailyCap bounds the auto retests queued for the tenant per 24 h.
	// 0 = DefaultRetestDailyCap.
	DailyCap int `json:"daily_cap,omitempty"`
	// AutoResolve: a confirmed fix (the endpoint answered and the check did
	// not match, RFC-057 R2) resolves the finding. Off (default): it moves the
	// finding to validated_fixed for a person with findings:verify to close.
	AutoResolve bool `json:"auto_resolve"`
}

// Validate checks the bounds. Zero means "use the default".
func (s RetestSettings) Validate() error {
	if s.IntervalHours != 0 && (s.IntervalHours < MinRetestIntervalHours || s.IntervalHours > MaxRetestIntervalHours) {
		return fmt.Errorf("%w: interval_hours must be between %d and %d", shared.ErrValidation, MinRetestIntervalHours, MaxRetestIntervalHours)
	}
	if s.DailyCap < 0 || s.DailyCap > MaxRetestDailyCap {
		return fmt.Errorf("%w: daily_cap must be between 1 and %d", shared.ErrValidation, MaxRetestDailyCap)
	}
	return nil
}

// EffectiveIntervalHours returns the interval, falling back to the default.
func (s RetestSettings) EffectiveIntervalHours() int {
	if s.IntervalHours <= 0 {
		return DefaultRetestIntervalHours
	}
	return s.IntervalHours
}

// EffectiveDailyCap returns the daily cap, falling back to the default.
func (s RetestSettings) EffectiveDailyCap() int {
	if s.DailyCap <= 0 {
		return DefaultRetestDailyCap
	}
	return s.DailyCap
}
