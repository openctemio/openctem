// Package liveness is what the platform knows about whether an asset is
// still there (docs/architecture/asset-liveness.md).
//
// Liveness is read from the evidence the coverage loop already collects,
// target by target: a check answered (alive), it got no answer (a timeout,
// a refused or filtered connection), or the name did not resolve (NXDOMAIN
// or a failed lookup). One observation never decides anything. A state
// needs a number of consecutive observations over a minimum time, and the
// strongest state, gone, needs the name to have no address for days, seen
// by two observers (or one observer for a longer window), with the dangling
// DNS check run since and finding nothing.
//
// States, weakest to strongest claim:
//
//   - unknown: no active check has looked at the asset yet;
//   - alive: an active check got an answer (an edge protection that blocked
//     or challenged the check counts: something answered for the name);
//   - unreachable: the last checks got no answer, over a minimum time, and
//     nothing answered since the first of them. Findings stay open;
//   - unresolvable: the name has no address (NXDOMAIN) or the lookup failed
//     (SERVFAIL), over a minimum time. Findings stay open;
//   - gone: the name has had no address long enough, from enough observers,
//     and it is not a dangling name. Findings may close as obsolete_asset.
//
// "Not seen" (assets.status stale) is a separate, older signal: an asset no
// source re-observed. It never feeds liveness.
package liveness

import (
	"slices"
	"time"
)

// State is an asset's liveness.
type State string

// States.
const (
	StateUnknown      State = "unknown"
	StateAlive        State = "alive"
	StateUnreachable  State = "unreachable"
	StateUnresolvable State = "unresolvable"
	StateGone         State = "gone"
)

// AllStates lists the states in display order.
func AllStates() []State {
	return []State{StateAlive, StateUnreachable, StateUnresolvable, StateGone, StateUnknown}
}

// Valid reports whether s is a known state.
func (s State) Valid() bool { return slices.Contains(AllStates(), s) }

// Reasons recorded with a state.
const (
	// ReasonNoAnswer: unreachable; the checks timed out or were refused.
	ReasonNoAnswer = "no_answer"
	// ReasonNXDomain: unresolvable; the name has no address.
	ReasonNXDomain = "nxdomain"
	// ReasonResolverFailed: unresolvable; the lookup failed (SERVFAIL, a
	// resolver timeout). Ambiguous: it may be the sensor's own DNS, so it
	// never leads to gone.
	ReasonResolverFailed = "resolver_failed"
	// ReasonDangling: unresolvable, and the name is dangling (a CNAME to a
	// target with no address, or an open takeover exposure): an
	// organization asset with a takeover risk, never gone.
	ReasonDangling = "dangling"
	// ReasonNXConfirmed: gone; the name has had no address long enough.
	ReasonNXConfirmed = "nxdomain_confirmed"
	// ReasonHostGone: gone; the service's host name is gone.
	ReasonHostGone = "host_gone"
)

// Kind is what one observation saw.
type Kind string

// Observation kinds.
const (
	// KindAnswered: an active check got an answer from the target (also an
	// edge protection answering for it). Implies the name resolved.
	KindAnswered Kind = "answered"
	// KindResolved: the name resolved to an address (DNS only).
	KindResolved Kind = "resolved"
	// KindNoAnswer: an active check got no answer (timeout, refused,
	// filtered) although the name resolved.
	KindNoAnswer Kind = "no_answer"
	// KindNXDomain: the name has no address.
	KindNXDomain Kind = "nxdomain"
	// KindResolverFailed: the lookup itself failed.
	KindResolverFailed Kind = "resolver_failed"
)

// Observation is one check's result for one asset.
type Observation struct {
	Kind Kind
	// Observer is the scan zone or sensor that made it ("zone:<id>",
	// "sensor:<id>"), "" when unknown. Distinct observers count towards
	// gone; an unknown observer never counts as a second one.
	Observer string
	// Capability and Outcome are what the coverage ledger recorded.
	Capability string
	Outcome    string
}

// MaxObservers bounds the distinct observers kept per streak.
const MaxObservers = 8

// Evidence is the per-asset evidence and the state decided from it.
type Evidence struct {
	State  State
	Reason string
	// Since is when the asset entered State (for unreachable and
	// unresolvable: the first observation of the streak).
	Since *time.Time

	LastCheckedAt  *time.Time
	LastCheckedBy  string
	LastKind       Kind
	LastCapability string
	LastOutcome    string
	LastAliveAt    *time.Time
	LastResolvedAt *time.Time

	// Reach streak: consecutive no-answer observations since the last
	// answer (any observer).
	ReachFails     int
	ReachFailSince *time.Time
	ReachFailLast  *time.Time
	ReachObservers []string

	// DNS streak: consecutive observations of a name that did not resolve
	// (no address or a failed lookup) since it last resolved.
	DNSFails     int
	DNSFailSince *time.Time
	DNSFailLast  *time.Time

	// NXDOMAIN streak: observations of "no address" since the name last
	// resolved. A failed lookup in between neither grows nor breaks it.
	NXCount     int
	NXSince     *time.Time
	NXLast      *time.Time
	NXObservers []string
}

// Thresholds are how much evidence each state needs.
type Thresholds struct {
	UnreachableAttempts      int
	UnreachableWindow        time.Duration
	UnresolvableAttempts     int
	UnresolvableWindow       time.Duration
	GoneAttempts             int
	GoneWindow               time.Duration // with two or more observers
	GoneSingleObserverWindow time.Duration // with one observer
}

// Defaults and floors. The floors are what a tenant setting may not go
// under: one blocked sensor, an edge protection or a short outage must never
// close anything.
const (
	DefaultUnreachableAttempts      = 3
	DefaultUnreachableWindow        = 72 * time.Hour
	DefaultUnresolvableAttempts     = 2
	DefaultUnresolvableWindow       = 12 * time.Hour
	DefaultGoneAttempts             = 3
	DefaultGoneWindow               = 72 * time.Hour
	DefaultGoneSingleObserverWindow = 7 * 24 * time.Hour

	MinUnreachableAttempts      = 2
	MinUnreachableWindow        = 24 * time.Hour
	MinGoneAttempts             = 3
	MinGoneWindow               = 24 * time.Hour
	MinGoneSingleObserverWindow = 72 * time.Hour
)

// DefaultThresholds returns the defaults.
func DefaultThresholds() Thresholds {
	return Thresholds{
		UnreachableAttempts:      DefaultUnreachableAttempts,
		UnreachableWindow:        DefaultUnreachableWindow,
		UnresolvableAttempts:     DefaultUnresolvableAttempts,
		UnresolvableWindow:       DefaultUnresolvableWindow,
		GoneAttempts:             DefaultGoneAttempts,
		GoneWindow:               DefaultGoneWindow,
		GoneSingleObserverWindow: DefaultGoneSingleObserverWindow,
	}
}

// Floored returns th with every value raised to its floor (and the
// unresolvable values, which have no setting, at their defaults).
func (th Thresholds) Floored() Thresholds {
	th.UnreachableAttempts = max(th.UnreachableAttempts, MinUnreachableAttempts)
	th.UnreachableWindow = max(th.UnreachableWindow, MinUnreachableWindow)
	th.UnresolvableAttempts = max(th.UnresolvableAttempts, DefaultUnresolvableAttempts)
	th.UnresolvableWindow = max(th.UnresolvableWindow, DefaultUnresolvableWindow)
	th.GoneAttempts = max(th.GoneAttempts, MinGoneAttempts)
	th.GoneWindow = max(th.GoneWindow, MinGoneWindow)
	th.GoneSingleObserverWindow = max(th.GoneSingleObserverWindow, MinGoneSingleObserverWindow, th.GoneWindow)
	return th
}

// Observe returns e updated with one observation made at at.
func (e Evidence) Observe(o Observation, at time.Time) Evidence {
	t := at
	e.LastCheckedAt, e.LastCheckedBy, e.LastKind = &t, o.Observer, o.Kind
	e.LastCapability, e.LastOutcome = o.Capability, o.Outcome
	switch o.Kind {
	case KindAnswered:
		e.LastAliveAt, e.LastResolvedAt = &t, &t
		e = e.resetReach().resetDNS()
	case KindResolved:
		e.LastResolvedAt = &t
		e = e.resetDNS()
	case KindNoAnswer:
		if e.ReachFails == 0 {
			e.ReachFailSince = &t
		}
		e.ReachFails = capCount(e.ReachFails + 1)
		e.ReachFailLast = &t
		e.ReachObservers = addObserver(e.ReachObservers, o.Observer)
	case KindNXDomain:
		e = e.dnsFail(t)
		if e.NXCount == 0 {
			e.NXSince = &t
		}
		e.NXCount = capCount(e.NXCount + 1)
		e.NXLast = &t
		e.NXObservers = addObserver(e.NXObservers, o.Observer)
	case KindResolverFailed:
		e = e.dnsFail(t)
	}
	return e
}

func (e Evidence) resetReach() Evidence {
	e.ReachFails, e.ReachFailSince, e.ReachFailLast, e.ReachObservers = 0, nil, nil, nil
	return e
}

func (e Evidence) resetDNS() Evidence {
	e.DNSFails, e.DNSFailSince, e.DNSFailLast = 0, nil, nil
	e.NXCount, e.NXSince, e.NXLast, e.NXObservers = 0, nil, nil, nil
	return e
}

func (e Evidence) dnsFail(t time.Time) Evidence {
	if e.DNSFails == 0 {
		e.DNSFailSince = &t
	}
	e.DNSFails = capCount(e.DNSFails + 1)
	e.DNSFailLast = &t
	return e
}

func capCount(n int) int { return min(n, 32767) }

// addObserver adds a known observer to the bounded set.
func addObserver(set []string, o string) []string {
	if o == "" || slices.Contains(set, o) {
		return set
	}
	if len(set) >= MaxObservers {
		return set
	}
	return append(slices.Clone(set), o)
}

func span(from, to *time.Time) time.Duration {
	if from == nil || to == nil {
		return 0
	}
	return to.Sub(*from)
}

// Unreachable reports whether the reach streak meets the thresholds.
func (e Evidence) Unreachable(th Thresholds) bool {
	th = th.Floored()
	return e.ReachFails >= th.UnreachableAttempts && span(e.ReachFailSince, e.ReachFailLast) >= th.UnreachableWindow
}

// Unresolvable reports whether the DNS streak meets the thresholds.
func (e Evidence) Unresolvable(th Thresholds) bool {
	th = th.Floored()
	return e.DNSFails >= th.UnresolvableAttempts && span(e.DNSFailSince, e.DNSFailLast) >= th.UnresolvableWindow
}

// NXConfirmed reports whether the NXDOMAIN streak is strong enough for
// gone: enough observations over the window, from two or more observers,
// or over the longer single-observer window. A failed lookup never counts.
func (e Evidence) NXConfirmed(th Thresholds) bool {
	th = th.Floored()
	if e.NXCount < th.GoneAttempts {
		return false
	}
	d := span(e.NXSince, e.NXLast)
	if len(e.NXObservers) >= 2 && d >= th.GoneWindow {
		return true
	}
	return d >= th.GoneSingleObserverWindow
}

// Guards are the facts outside the evidence that gone depends on. Known is
// false when the caller did not read them (the settle path): gone is then
// never entered, only kept while its evidence still holds.
type Guards struct {
	Known bool
	// Dangling: an open dangling_cname, dangling_ns or subdomain_takeover
	// exposure, or the dangling_cname tag, on the asset or its host name.
	Dangling bool
	// DanglingChecked: the dangling DNS check of the name (or the host
	// name) ran since the NXDOMAIN streak began and found nothing.
	DanglingChecked bool
	// Pinned: a person set the asset's status by hand or snoozed its
	// lifecycle: the platform does not decide it is gone.
	Pinned bool
	// HostGone: the service's host name asset is gone.
	HostGone bool
}

// Decide returns the state and reason for e. prev is e's stored state and
// reason (the evidence's own State and Reason).
func Decide(e Evidence, g Guards, th Thresholds) (State, string) {
	th = th.Floored()
	if g.Known {
		if !g.Pinned && !g.Dangling {
			if g.HostGone {
				return StateGone, ReasonHostGone
			}
			if e.NXConfirmed(th) && g.DanglingChecked {
				return StateGone, ReasonNXConfirmed
			}
		}
	} else if e.State == StateGone && !e.seenSince() {
		// Without the guards gone is only kept, never entered; any answer
		// or resolution since it was entered ends it.
		return StateGone, e.Reason
	}
	if e.Unresolvable(th) {
		switch {
		case g.Known && g.Dangling:
			return StateUnresolvable, ReasonDangling
		case !g.Known && e.State == StateUnresolvable && e.Reason == ReasonDangling:
			return StateUnresolvable, ReasonDangling
		case e.NXCount > 0:
			return StateUnresolvable, ReasonNXDomain
		default:
			return StateUnresolvable, ReasonResolverFailed
		}
	}
	if e.Unreachable(th) {
		return StateUnreachable, ReasonNoAnswer
	}
	if e.LastAliveAt != nil || e.LastResolvedAt != nil {
		return StateAlive, ""
	}
	return StateUnknown, ""
}

// seenSince reports whether something answered or resolved the name after
// the asset entered its state.
func (e Evidence) seenSince() bool {
	if e.Since == nil {
		return false
	}
	after := func(t *time.Time) bool { return t != nil && t.After(*e.Since) }
	return after(e.LastAliveAt) || after(e.LastResolvedAt)
}

// Settle sets e's state from Decide, with Since moved when the state
// changes (unreachable and unresolvable date from the streak's first
// observation; the others from now). It reports whether the state changed.
func (e Evidence) Settle(g Guards, th Thresholds, now time.Time) (Evidence, bool) {
	state, reason := Decide(e, g, th)
	if state == e.State && reason == e.Reason && e.Since != nil {
		return e, false
	}
	changed := state != e.State
	if changed || e.Since == nil {
		t := now
		switch state {
		case StateUnreachable:
			if e.ReachFailSince != nil {
				t = *e.ReachFailSince
			}
		case StateUnresolvable:
			if e.DNSFailSince != nil {
				t = *e.DNSFailSince
			}
		}
		e.Since = &t
	}
	e.State, e.Reason = state, reason
	return e, changed
}

// Transition is one asset's state change.
type Transition struct {
	From, To State
	Reason   string
}
