package licensekey

import "time"

// State is a license's state at an effective time.
type State string

// License states.
const (
	// StateNotYetValid: before not_before (a renewal uploaded early waits).
	StateNotYetValid State = "not_yet_valid"
	// StateActive: valid, more than ExpiringWindow before expires_at.
	StateActive State = "active"
	// StateExpiring: valid, in the last ExpiringWindow before expires_at.
	StateExpiring State = "expiring"
	// StateGrace: past expires_at, inside the grace window; still granted.
	StateGrace State = "grace"
	// StateExpired: past the grace window; grants stop producing new data.
	StateExpired State = "expired"
)

// Granting reports whether entitlements are on in state s.
func (s State) Granting() bool {
	return s == StateActive || s == StateExpiring || s == StateGrace
}

// StateAt returns the state at effective time t (see EffectiveTime; never
// pass the raw wall clock, or a clock wound back revives an expired license).
func (c *Claims) StateAt(t time.Time) State {
	switch {
	case t.Before(c.NotBefore):
		return StateNotYetValid
	case t.Before(c.ExpiresAt.Add(-ExpiringWindow)):
		return StateActive
	case t.Before(c.ExpiresAt):
		return StateExpiring
	case t.Before(c.GraceEndsAt()):
		return StateGrace
	default:
		return StateExpired
	}
}

// EffectiveTime is the time license states are computed at: the latest of
// the wall clock, the stored high-water mark (the highest effective time
// seen before) and the issued_at of every stored license. Winding the clock
// back therefore cannot revive an expired license, and a wrong clock never
// locks anyone out of anything a license does not grant.
func EffectiveTime(now, highWater time.Time, issuedAt ...time.Time) time.Time {
	t := now
	if highWater.After(t) {
		t = highWater
	}
	for _, i := range issuedAt {
		if i.After(t) {
			t = i
		}
	}
	return t.UTC()
}
