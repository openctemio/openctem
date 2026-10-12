package easm

// The scope join runs again after every scope change that can confirm a
// waiting name (RFC-054 §4.3): an entry coming into effect (create, approve,
// activate), an entry in effect changing, and an exclusion going away or
// narrowing. scope.Service asks for a run after the change commits; this
// scheduler debounces those requests per tenant, never runs two joins of one
// tenant at once, and repeats a run when a change arrives while one is in
// progress. The join is idempotent, and the periodic controller is the safety
// net for a run that failed.

import (
	"context"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/internal/app/scope"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// joinRunner is the join the scheduler drives (*ScopeJoin).
type joinRunner interface {
	Run(ctx context.Context, tenantID shared.ID) ([]scope.JoinedAsset, error)
	Preview(ctx context.Context, tenantID shared.ID, candidate *scopedom.Target) ([]scope.JoinedAsset, error)
}

// Defaults of the scheduler.
const (
	// DefaultJoinDebounce collects the changes of one burst (a bulk import,
	// several approvals) into one run.
	DefaultJoinDebounce = 2 * time.Second
	// joinRunTimeout bounds one background run.
	joinRunTimeout = 2 * time.Minute
)

// tenantJoin is one tenant's state: a run is pending (timer armed) and the
// run lock serializes runs.
type tenantJoin struct {
	pending bool
	timer   *time.Timer
	run     sync.Mutex
}

// JoinScheduler debounces and serializes scope-join runs per tenant. It
// implements scope.ScopeJoiner.
type JoinScheduler struct {
	join   joinRunner
	delay  time.Duration
	log    *logger.Logger
	mu     sync.Mutex
	state  map[shared.ID]*tenantJoin
	flight sync.WaitGroup
}

var _ scope.ScopeJoiner = (*JoinScheduler)(nil)

// NewJoinScheduler creates the scheduler. delay <= 0 uses DefaultJoinDebounce.
func NewJoinScheduler(join *ScopeJoin, delay time.Duration, log *logger.Logger) *JoinScheduler {
	return newJoinScheduler(join, delay, log)
}

func newJoinScheduler(join joinRunner, delay time.Duration, log *logger.Logger) *JoinScheduler {
	if delay <= 0 {
		delay = DefaultJoinDebounce
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &JoinScheduler{join: join, delay: delay, log: log.With("component", "scope-join-scheduler"),
		state: map[shared.ID]*tenantJoin{}}
}

func (s *JoinScheduler) tenant(id shared.ID) *tenantJoin {
	st, ok := s.state[id]
	if !ok {
		st = &tenantJoin{}
		s.state[id] = st
	}
	return st
}

// Schedule asks for a run of the tenant's join after the debounce delay. A
// request while one is pending is folded into it; a request during a run
// starts one more run after it.
func (s *JoinScheduler) Schedule(tenantID shared.ID) {
	if s == nil || s.join == nil || tenantID.IsZero() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.tenant(tenantID)
	if st.pending {
		return
	}
	st.pending = true
	s.flight.Add(1)
	st.timer = time.AfterFunc(s.delay, func() {
		defer s.flight.Done()
		s.fire(tenantID)
	})
}

// fire runs a pending request (RunNow may have taken it already).
func (s *JoinScheduler) fire(tenantID shared.ID) {
	s.mu.Lock()
	st := s.tenant(tenantID)
	if !st.pending {
		s.mu.Unlock()
		return
	}
	st.pending = false
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), joinRunTimeout)
	defer cancel()
	if _, err := s.runLocked(ctx, tenantID, st); err != nil {
		s.log.Warn("scope join after a scope change failed; the periodic run repeats it",
			"tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
	}
}

// RunNow runs the tenant's join at once and returns what it confirmed (the
// apply response reports it). It takes over a pending request; on failure
// it schedules a retry.
func (s *JoinScheduler) RunNow(ctx context.Context, tenantID shared.ID) ([]scope.JoinedAsset, error) {
	if s == nil || s.join == nil || tenantID.IsZero() {
		return nil, nil
	}
	s.mu.Lock()
	st := s.tenant(tenantID)
	if st.pending && st.timer != nil && st.timer.Stop() {
		st.pending = false
		s.flight.Done()
	}
	s.mu.Unlock()
	done, err := s.runLocked(ctx, tenantID, st)
	if err != nil {
		s.Schedule(tenantID)
	}
	return done, err
}

func (s *JoinScheduler) runLocked(ctx context.Context, tenantID shared.ID, st *tenantJoin) ([]scope.JoinedAsset, error) {
	st.run.Lock()
	defer st.run.Unlock()
	return s.join.Run(ctx, tenantID)
}

// Preview lists what a candidate entry would confirm (nothing is written).
func (s *JoinScheduler) Preview(ctx context.Context, tenantID shared.ID, candidate *scopedom.Target) ([]scope.JoinedAsset, error) {
	if s == nil || s.join == nil {
		return nil, nil
	}
	return s.join.Preview(ctx, tenantID, candidate)
}

// Wait blocks until every scheduled run has finished (tests, shutdown).
func (s *JoinScheduler) Wait() { s.flight.Wait() }
