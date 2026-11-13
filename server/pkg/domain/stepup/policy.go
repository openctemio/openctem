// Package stepup is the organization's re-verification (step-up) policy:
// how often a signed-in person must confirm their identity again before an
// action, per risk tier (docs/architecture/step-up-reauth.md).
//
// Every action behind step-up belongs to one tier. Critical actions (roles,
// sign-in, credentials, secrets, deleting or erasing, approving active
// scanning, exporting) always ask: the organization may choose every time or
// once per 10 minutes, never less. Sensitive actions (governance changes,
// approvals of findings and risk, bulk closes) and routine actions (one
// finding's status) follow the organization's choice, down to off.
//
// Threat model: the policy decides how long one proof of identity unlocks
// actions in one session. Its floor keeps a stolen session from taking over
// the organization (credentials, roles, sign-in) without the password or the
// authenticator; above the floor the organization trades prompts for exposure
// of its own findings and governance, and every change of the policy is an
// owner's decision, made with step-up and audited.
package stepup

import (
	"fmt"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Tier is the risk class of an action behind step-up.
type Tier string

const (
	// TierCritical: control of the organization (roles, sign-in, credentials,
	// secrets, deletion, active-scan approval, exports). Never off.
	TierCritical Tier = "critical"
	// TierSensitive: governance and decisions that hide or lower risk.
	TierSensitive Tier = "sensitive"
	// TierRoutine: day-to-day work on one finding.
	TierRoutine Tier = "routine"
)

// Tiers lists the tiers from the most to the least demanding.
var Tiers = []Tier{TierCritical, TierSensitive, TierRoutine}

// Mode is how often a tier asks.
type Mode string

const (
	// ModeEveryTime: each action needs its own proof, given within
	// EveryTimeFreshness; a proof is spent by the action it unlocks.
	ModeEveryTime Mode = "every_time"
	// ModeWindow: one proof unlocks the tier's actions for Window.
	ModeWindow Mode = "once_per_window"
	// ModeOff: the tier never asks.
	ModeOff Mode = "off"
)

// Window lengths a ModeWindow rule may use.
const (
	Window10m     = "10m"
	Window1h      = "1h"
	Window4h      = "4h"
	Window8h      = "8h"
	WindowSession = "session"
)

// windows maps a window name to its length; WindowSession has none (the
// session's own lifetime bounds it).
var windows = map[string]time.Duration{
	Window10m:     10 * time.Minute,
	Window1h:      time.Hour,
	Window4h:      4 * time.Hour,
	Window8h:      8 * time.Hour,
	WindowSession: 0,
}

// WindowNames lists the windows from the shortest to the longest.
var WindowNames = []string{Window10m, Window1h, Window4h, Window8h, WindowSession}

// EveryTimeFreshness is how old a proof may be when an every_time action
// spends it: long enough for the dialog and the retried request.
const EveryTimeFreshness = 5 * time.Minute

// CriticalMaxWindow is the platform floor for critical actions: they never
// ride a proof older than this.
const CriticalMaxWindow = 15 * time.Minute

// Rule is a tier's setting.
type Rule struct {
	Mode   Mode   `json:"mode"`
	Window string `json:"window,omitempty"`
}

// Policy is the organization's re-verification policy.
type Policy struct {
	Critical  Rule `json:"critical"`
	Sensitive Rule `json:"sensitive"`
	Routine   Rule `json:"routine"`
}

// DefaultPolicy is the policy of an organization created from now on:
// critical once per 10 minutes, sensitive once per hour, routine off.
func DefaultPolicy() Policy {
	return Policy{
		Critical:  Rule{Mode: ModeWindow, Window: Window10m},
		Sensitive: Rule{Mode: ModeWindow, Window: Window1h},
		Routine:   Rule{Mode: ModeOff},
	}
}

// LegacyPolicy is the policy of an organization that never saved one: the
// fixed 10-minute window that applied to every step-up action before the
// policy existed, with routine off (one finding's close no longer asks).
func LegacyPolicy() Policy {
	return Policy{
		Critical:  Rule{Mode: ModeWindow, Window: Window10m},
		Sensitive: Rule{Mode: ModeWindow, Window: Window10m},
		Routine:   Rule{Mode: ModeOff},
	}
}

// Effective is the policy in force for a stored one: LegacyPolicy when none
// is stored, otherwise the stored policy with every tier clamped to the
// platform floor (a value stored before a floor was raised never loosens it).
func Effective(p *Policy) Policy {
	if p == nil {
		return LegacyPolicy()
	}
	out := *p
	if !out.Critical.withinCriticalFloor() {
		out.Critical = Rule{Mode: ModeWindow, Window: Window10m}
	}
	if !out.Sensitive.valid() {
		out.Sensitive = LegacyPolicy().Sensitive
	}
	if !out.Routine.valid() {
		out.Routine = LegacyPolicy().Routine
	}
	return out
}

// ErrBelowFloor: a policy asks for less than the platform allows.
var ErrBelowFloor = shared.NewDomainError("STEP_UP_POLICY_BELOW_FLOOR",
	"critical actions ask every time or once per 10 minutes; they cannot be turned off", shared.ErrValidation)

// Validate refuses an unknown mode or window and a critical rule below the
// platform floor.
func (p Policy) Validate() error {
	for _, t := range Tiers {
		r := p.Rule(t)
		if !r.valid() {
			return fmt.Errorf("%w: %s: mode must be every_time, once_per_window or off, with a window of 10m, 1h, 4h, 8h or session", shared.ErrValidation, t)
		}
	}
	if !p.Critical.withinCriticalFloor() {
		return ErrBelowFloor
	}
	return nil
}

// Rule returns the rule of tier t; an unknown tier is critical.
func (p Policy) Rule(t Tier) Rule {
	switch t {
	case TierSensitive:
		return p.Sensitive
	case TierRoutine:
		return p.Routine
	default:
		return p.Critical
	}
}

func (r Rule) valid() bool {
	switch r.Mode {
	case ModeEveryTime, ModeOff:
		return r.Window == ""
	case ModeWindow:
		_, ok := windows[r.Window]
		return ok
	default:
		return false
	}
}

func (r Rule) withinCriticalFloor() bool {
	if !r.valid() || r.Mode == ModeOff {
		return false
	}
	if r.Mode == ModeEveryTime {
		return true
	}
	d := windows[r.Window]
	return d > 0 && d <= CriticalMaxWindow
}

// Duration is the window length of a ModeWindow rule; session reports true
// for WindowSession (no length of its own).
func (r Rule) Duration() (d time.Duration, session bool) {
	if r.Mode != ModeWindow {
		return 0, false
	}
	d = windows[r.Window]
	return d, r.Window == WindowSession
}

// strictness orders rules from the least (0) to the most demanding.
func (r Rule) strictness() int {
	switch r.Mode {
	case ModeOff:
		return 0
	case ModeEveryTime:
		return 100
	case ModeWindow:
		for i, w := range WindowNames {
			if w == r.Window {
				return 90 - i*10 // 10m 90 ... session 50
			}
		}
	}
	return 0
}

// Looser reports whether after asks less often than before for any tier.
func Looser(before, after Policy) bool {
	for _, t := range Tiers {
		if after.Rule(t).strictness() < before.Rule(t).strictness() {
			return true
		}
	}
	return false
}
