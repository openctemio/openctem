package tenant

import (
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/liveness"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AssetLivenessSettings are the organization's liveness thresholds and
// whether findings of a gone asset close (docs/architecture/
// asset-liveness.md). Zero values mean the defaults. Each value has a floor
// (pkg/domain/liveness) so a blocked sensor, an edge protection or a short
// outage can never close a finding.
type AssetLivenessSettings struct {
	// CloseFindingsWhenGone closes the open findings of a gone asset as
	// resolved / obsolete_asset (never counted as fixed) and reopens them
	// when the asset is seen again. Off by default: until it is on, gone
	// is a label only.
	CloseFindingsWhenGone bool `json:"close_findings_when_gone"`
	// UnreachableAttempts and UnreachableWindowHours: consecutive checks
	// with no answer, over at least this many hours, make an asset
	// unreachable (a label; findings stay open). Defaults 3 and 72.
	UnreachableAttempts    int `json:"unreachable_attempts,omitempty"`
	UnreachableWindowHours int `json:"unreachable_window_hours,omitempty"`
	// GoneAttempts, GoneWindowHours and GoneSingleObserverWindowHours: a
	// name is gone after this many "no address" answers over at least
	// GoneWindowHours seen by two or more scan zones or sensors, or over
	// GoneSingleObserverWindowHours seen by one. Defaults 3, 72 and 168.
	GoneAttempts                  int `json:"gone_attempts,omitempty"`
	GoneWindowHours               int `json:"gone_window_hours,omitempty"`
	GoneSingleObserverWindowHours int `json:"gone_single_observer_window_hours,omitempty"`
	// MaxGonePerDay bounds how many assets with open findings may become
	// gone in 24 hours; more wait for the next day (a broken resolver cannot
	// close a whole inventory's findings at once). Default 50.
	MaxGonePerDay int `json:"max_gone_per_day,omitempty"`
}

// Liveness bounds. The minimums are the safe floors.
const (
	MinLivenessUnreachableAttempts      = 2
	MinLivenessUnreachableWindowHours   = 24
	MinLivenessGoneAttempts             = 3
	MinLivenessGoneWindowHours          = 24
	MinLivenessGoneSingleObserverWindow = 72
	MaxLivenessAttempts                 = 20
	MaxLivenessWindowHours              = 90 * 24
	DefaultLivenessMaxGonePerDay        = 50
	MaxLivenessMaxGonePerDay            = 5000
)

// EffectiveMaxGonePerDay returns the daily bound, the default when unset.
func (s AssetLivenessSettings) EffectiveMaxGonePerDay() int {
	if s.MaxGonePerDay <= 0 {
		return DefaultLivenessMaxGonePerDay
	}
	return s.MaxGonePerDay
}

// Validate checks every set value against its floor and ceiling.
func (s AssetLivenessSettings) Validate() error {
	checks := []struct {
		name     string
		v, lo, h int
	}{
		{"unreachable_attempts", s.UnreachableAttempts, MinLivenessUnreachableAttempts, MaxLivenessAttempts},
		{"unreachable_window_hours", s.UnreachableWindowHours, MinLivenessUnreachableWindowHours, MaxLivenessWindowHours},
		{"gone_attempts", s.GoneAttempts, MinLivenessGoneAttempts, MaxLivenessAttempts},
		{"gone_window_hours", s.GoneWindowHours, MinLivenessGoneWindowHours, MaxLivenessWindowHours},
		{"gone_single_observer_window_hours", s.GoneSingleObserverWindowHours, MinLivenessGoneSingleObserverWindow, MaxLivenessWindowHours},
		{"max_gone_per_day", s.MaxGonePerDay, 1, MaxLivenessMaxGonePerDay},
	}
	for _, c := range checks {
		if c.v != 0 && (c.v < c.lo || c.v > c.h) {
			return fmt.Errorf("%w: liveness.%s must be between %d and %d", shared.ErrValidation, c.name, c.lo, c.h)
		}
	}
	if s.GoneWindowHours != 0 && s.GoneSingleObserverWindowHours != 0 && s.GoneSingleObserverWindowHours < s.GoneWindowHours {
		return fmt.Errorf("%w: liveness.gone_single_observer_window_hours must not be shorter than gone_window_hours", shared.ErrValidation)
	}
	return nil
}

// Thresholds returns the liveness thresholds: the defaults for unset
// values, floored.
func (s AssetLivenessSettings) Thresholds() liveness.Thresholds {
	th := liveness.DefaultThresholds()
	h := func(v int) time.Duration { return time.Duration(v) * time.Hour }
	if s.UnreachableAttempts > 0 {
		th.UnreachableAttempts = s.UnreachableAttempts
	}
	if s.UnreachableWindowHours > 0 {
		th.UnreachableWindow = h(s.UnreachableWindowHours)
	}
	if s.GoneAttempts > 0 {
		th.GoneAttempts = s.GoneAttempts
	}
	if s.GoneWindowHours > 0 {
		th.GoneWindow = h(s.GoneWindowHours)
	}
	if s.GoneSingleObserverWindowHours > 0 {
		th.GoneSingleObserverWindow = h(s.GoneSingleObserverWindowHours)
	}
	return th.Floored()
}

// LivenessLoosened reports a change that lets the platform close more
// findings sooner: closing turned on, fewer attempts, shorter windows or a
// higher daily bound. Unset values compare as their defaults.
func LivenessLoosened(before, after AssetLivenessSettings) bool {
	if !after.CloseFindingsWhenGone {
		return false
	}
	if !before.CloseFindingsWhenGone {
		return true
	}
	b, a := before.Thresholds(), after.Thresholds()
	return a.GoneAttempts < b.GoneAttempts || a.GoneWindow < b.GoneWindow ||
		a.GoneSingleObserverWindow < b.GoneSingleObserverWindow ||
		after.EffectiveMaxGonePerDay() > before.EffectiveMaxGonePerDay()
}
