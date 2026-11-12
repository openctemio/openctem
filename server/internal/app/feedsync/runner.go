// Package feedsync runs a platform-wide intelligence feed's sync in the
// background when an operator asks for it, so the HTTP request does no
// download or import work. One run per feed at a time: a second request while
// one runs is acknowledged, not started, and the feed's own claim (a
// conditional update of its status row) keeps a scheduled run on any replica
// from overlapping.
package feedsync

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

// Job runs one pass of a feed: fetch, store, reconcile (the same pass its
// controller runs on schedule).
type Job func(ctx context.Context) error

// Defaults.
const (
	// DefaultMinGap is the shortest time between two accepted starts of one
	// feed: every start is a full external download.
	DefaultMinGap = 15 * time.Second
	// DefaultRunTimeout bounds one run (the longest controller run is 45 min).
	DefaultRunTimeout = 50 * time.Minute
)

// Outcome says what a request did.
type Outcome string

// Outcomes.
const (
	// Queued: a background run was started.
	Queued Outcome = "queued"
	// AlreadyRunning: a run of this feed in this process holds it.
	AlreadyRunning Outcome = "already_running"
)

// ErrUnknownSource: no job is registered for the source.
var ErrUnknownSource = errors.New("unknown feed")

// TooSoonError: the feed was started less than the minimum gap ago.
type TooSoonError struct{ RetryAfter time.Duration }

func (e *TooSoonError) Error() string {
	return fmt.Sprintf("feed sync requested too soon; retry in %s", e.RetryAfter.Round(time.Second))
}

// Runner starts feed jobs in the background.
type Runner struct {
	jobs    map[string]Job
	log     *logger.Logger
	minGap  time.Duration
	timeout time.Duration
	now     func() time.Time

	mu      sync.Mutex
	running map[string]bool
	started map[string]time.Time
	wg      sync.WaitGroup
	base    context.Context
	stop    context.CancelFunc
}

// New creates a runner for the given jobs, by source.
func New(jobs map[string]Job, log *logger.Logger) *Runner {
	base, stop := context.WithCancel(context.Background())
	return &Runner{jobs: jobs, log: log, minGap: DefaultMinGap, timeout: DefaultRunTimeout, now: time.Now,
		running: map[string]bool{}, started: map[string]time.Time{}, base: base, stop: stop}
}

// Has reports whether a job is registered for the source.
func (r *Runner) Has(source string) bool { _, ok := r.jobs[source]; return ok }

// Trigger starts the source's job in the background and returns at once.
func (r *Runner) Trigger(source string) (Outcome, error) {
	job, ok := r.jobs[source]
	if !ok {
		return "", ErrUnknownSource
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running[source] {
		return AlreadyRunning, nil
	}
	if last, ok := r.started[source]; ok {
		if wait := r.minGap - r.now().Sub(last); wait > 0 {
			return "", &TooSoonError{RetryAfter: wait}
		}
	}
	r.running[source] = true
	r.started[source] = r.now()
	r.wg.Add(1)
	go r.run(source, job)
	return Queued, nil
}

func (r *Runner) run(source string, job Job) {
	defer r.wg.Done()
	ctx, cancel := context.WithTimeout(r.base, r.timeout)
	defer cancel()
	defer func() {
		if v := recover(); v != nil {
			r.log.Error("feed sync panicked", "source", source, "panic", fmt.Sprint(v))
		}
		r.mu.Lock()
		delete(r.running, source)
		r.mu.Unlock()
	}()
	if err := job(ctx); err != nil {
		r.log.Warn("feed sync failed", "source", source, "error", err)
	}
}

// Shutdown stops accepting work, cancels the runs and waits for them (or ctx).
func (r *Runner) Shutdown(ctx context.Context) {
	r.stop()
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}
