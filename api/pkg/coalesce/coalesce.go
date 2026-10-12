// Package coalesce runs a per-key action at most once per interval without
// ever losing the last call: a call inside the interval is folded into one
// run at the end of it (a trailing-edge throttle). It bounds work a caller
// can trigger in a loop, such as the sensor control-stream wakes
// (research/84 RE-12), while a delayed run stays a run.
package coalesce

import (
	"sync"
	"time"
)

// pruneFloor is the key count below which idle keys are never swept.
const pruneFloor = 1024

// Throttle runs fn for a key at most once per interval. The zero value is
// not usable; use New.
type Throttle struct {
	interval time.Duration

	mu      sync.Mutex
	keys    map[string]*entry
	pruneAt int
}

type entry struct {
	last    time.Time
	pending bool
}

// New builds a throttle with the given interval (<= 0: every call runs).
func New(interval time.Duration) *Throttle {
	return &Throttle{interval: interval, keys: map[string]*entry{}, pruneAt: pruneFloor}
}

// Do runs fn now when key last ran at least interval ago. Otherwise one run
// is scheduled for when the interval ends, and every further call until
// then is folded into it. It never blocks on fn's work; fn runs on the
// caller's goroutine (immediate) or a timer's (deferred), never under the
// throttle's lock. It reports whether this call was folded into a pending
// or scheduled run instead of running at once.
func (t *Throttle) Do(key string, fn func()) (coalesced bool) {
	if t.interval <= 0 {
		fn()
		return false
	}
	now := time.Now()
	t.mu.Lock()
	e := t.keys[key]
	if e == nil {
		t.prune(now)
		e = &entry{}
		t.keys[key] = e
	}
	if e.pending {
		t.mu.Unlock()
		return true
	}
	if wait := t.interval - now.Sub(e.last); wait > 0 && !e.last.IsZero() {
		e.pending = true
		t.mu.Unlock()
		time.AfterFunc(wait, func() {
			t.mu.Lock()
			e.pending, e.last = false, time.Now()
			t.mu.Unlock()
			fn()
		})
		return true
	}
	e.last = now
	t.mu.Unlock()
	fn()
	return false
}

// prune drops keys that ran more than an interval ago and wait for nothing
// (forgetting them changes no outcome: their next call runs at once). It
// runs when the map has doubled since the last sweep. Caller holds mu.
func (t *Throttle) prune(now time.Time) {
	if len(t.keys) < t.pruneAt {
		return
	}
	for k, e := range t.keys {
		if !e.pending && now.Sub(e.last) >= t.interval {
			delete(t.keys, k)
		}
	}
	t.pruneAt = max(pruneFloor, 2*len(t.keys))
}

// Len is the number of keys held (tests and diagnostics).
func (t *Throttle) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.keys)
}
