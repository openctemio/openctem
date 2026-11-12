package asset

import (
	"context"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// GroupRuleNotifier is told when assets of a tenant were created or changed,
// so the rule groups of the tenant are evaluated again
// (*GroupRuleScheduler).
type GroupRuleNotifier interface {
	NotifyAssetsChanged(tenantID shared.ID)
}

// Defaults of the scheduler.
const (
	// DefaultGroupRuleDebounce collects the changes of one burst (an
	// import, a scan result) into one evaluation.
	DefaultGroupRuleDebounce = 5 * time.Second
	groupRuleRunTimeout      = 5 * time.Minute
)

type tenantRuleRun struct {
	pending bool // a timer is armed
	running bool // an evaluation is in progress
	again   bool // a change arrived during the run
}

// GroupRuleScheduler debounces the evaluation of a tenant's rule groups
// after asset changes, never runs two evaluations of one tenant at once, and
// repeats a run when a change arrived during it. The periodic full recompute
// is the safety net for a run that failed.
type GroupRuleScheduler struct {
	eval  func(ctx context.Context, tenantID shared.ID) (int, error)
	delay time.Duration
	log   *logger.Logger

	mu     sync.Mutex
	state  map[shared.ID]*tenantRuleRun
	flight sync.WaitGroup
}

var _ GroupRuleNotifier = (*GroupRuleScheduler)(nil)

// NewGroupRuleScheduler creates the scheduler over the group service. delay
// <= 0 uses DefaultGroupRuleDebounce.
func NewGroupRuleScheduler(svc *AssetGroupService, delay time.Duration, log *logger.Logger) *GroupRuleScheduler {
	return newGroupRuleScheduler(svc.EvaluateTenant, delay, log)
}

func newGroupRuleScheduler(eval func(context.Context, shared.ID) (int, error), delay time.Duration, log *logger.Logger) *GroupRuleScheduler {
	if delay <= 0 {
		delay = DefaultGroupRuleDebounce
	}
	if log == nil {
		log = logger.NewNop()
	}
	return &GroupRuleScheduler{eval: eval, delay: delay, log: log.With("component", "group-rule-scheduler"),
		state: map[shared.ID]*tenantRuleRun{}}
}

// NotifyAssetsChanged implements GroupRuleNotifier.
func (s *GroupRuleScheduler) NotifyAssetsChanged(tenantID shared.ID) {
	if s == nil || tenantID.IsZero() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.state[tenantID]
	if !ok {
		st = &tenantRuleRun{}
		s.state[tenantID] = st
	}
	switch {
	case st.running:
		st.again = true
	case !st.pending:
		s.arm(tenantID, st)
	}
}

// arm starts the timer; the caller holds s.mu.
func (s *GroupRuleScheduler) arm(tenantID shared.ID, st *tenantRuleRun) {
	st.pending = true
	s.flight.Add(1)
	time.AfterFunc(s.delay, func() {
		defer s.flight.Done()
		s.fire(tenantID)
	})
}

func (s *GroupRuleScheduler) fire(tenantID shared.ID) {
	s.mu.Lock()
	st := s.state[tenantID]
	st.pending, st.running = false, true
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), groupRuleRunTimeout)
	defer cancel()
	func() {
		defer func() {
			if r := recover(); r != nil {
				s.log.Error("panic in group rule evaluation", "tenant_id", tenantID.String(), "recover", r)
			}
		}()
		if _, err := s.eval(ctx, tenantID); err != nil {
			s.log.Warn("group rule evaluation after an asset change failed; the periodic run repeats it",
				"tenant_id", tenantID.String(), "error", logger.SanitizeError(err))
		}
	}()

	s.mu.Lock()
	defer s.mu.Unlock()
	st.running = false
	if st.again {
		st.again = false
		s.arm(tenantID, st)
	}
}

// Wait blocks until every armed or running evaluation finished (tests).
func (s *GroupRuleScheduler) Wait() { s.flight.Wait() }
