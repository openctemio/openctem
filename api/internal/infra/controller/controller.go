// Package controller implements K8s-style reconciliation loop controllers
// for self-healing background operations.
//
// Controllers periodically reconcile the desired state of the system with its actual state.
// Each controller runs in its own goroutine and handles a specific aspect of the system:
// - SensorHealthController: Marks stale sensors as offline, cleans up expired leases
// - JobRecoveryController: Recovers stuck jobs and re-queues them
// - QueuePriorityController: Recalculates queue priorities for fair scheduling
// - TokenCleanupController: Cleans up expired bootstrap tokens
// - AuditRetentionController: Manages audit log retention
//
// Design principles:
// - Each controller is independent and can fail without affecting others
// - Controllers are idempotent - running multiple times has the same effect
// - Controllers use optimistic locking to handle concurrent modifications
// - All state changes are logged for debugging and monitoring
package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/controllerlease"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Controller defines the interface for a reconciliation loop controller.
// Controllers are responsible for maintaining a specific aspect of system state.
type Controller interface {
	// Name returns the unique name of this controller.
	Name() string

	// Interval returns how often this controller should run.
	Interval() time.Duration

	// Reconcile performs the reconciliation logic.
	// It should be idempotent - running multiple times should have the same effect.
	// Returns the number of items processed and any error encountered.
	Reconcile(ctx context.Context) (int, error)
}

// ReconcileTimeouter is an optional Controller extension. By default a
// reconcile is bounded by the controller's tick Interval, which suits pollers
// whose per-run work is trivial. A controller whose single run can legitimately
// take much longer than the interval — e.g. the ingest worker polls every few
// seconds but must run a claimed batch through the full ingest pipeline —
// implements this to request a larger per-run timeout. A non-positive value
// falls back to the interval. Controllers that don't implement it are unaffected.
type ReconcileTimeouter interface {
	ReconcileTimeout() time.Duration
}

// Metrics defines the interface for controller metrics collection.
type Metrics interface {
	// RecordReconcile records a reconciliation run.
	RecordReconcile(controller string, itemsProcessed int, duration time.Duration, err error)

	// SetControllerRunning sets whether a controller is running.
	SetControllerRunning(controller string, running bool)

	// IncrementReconcileErrors increments the error counter.
	IncrementReconcileErrors(controller string)

	// SetLastReconcileTime sets the last reconcile timestamp.
	SetLastReconcileTime(controller string, t time.Time)
}

// Exclusive is an optional Controller extension for work that is not
// idempotent (retention sweeps, refreshes that call external services): with
// a lease store set on the manager, each reconcile first takes the controller
// lease "controller:<name>" (RFC-046 §11, P1.8), so with several API
// replicas exactly one runs it at a time. A replica that does not get the
// lease skips the tick.
type Exclusive interface {
	Exclusive() bool
}

// Manager manages multiple controllers, running them in parallel goroutines.
type Manager struct {
	controllers []Controller
	metrics     Metrics
	leases      controllerlease.Store
	holder      string
	// leaseRenew overrides the renewal period (a third of the lease TTL);
	// tests only.
	leaseRenew time.Duration
	logger     *logger.Logger
	running    bool
	stopCh     chan struct{}
	wg         sync.WaitGroup
	mu         sync.Mutex
}

// ManagerConfig configures the controller manager.
type ManagerConfig struct {
	// Metrics collector (optional)
	Metrics Metrics

	// Leases and LeaseHolder run Exclusive controllers on one replica at a
	// time (optional; without them they run on every replica, as before).
	Leases      controllerlease.Store
	LeaseHolder string

	// Logger (required)
	Logger *logger.Logger
}

// NewManager creates a new controller manager.
func NewManager(cfg *ManagerConfig) *Manager {
	return &Manager{
		controllers: make([]Controller, 0),
		metrics:     cfg.Metrics,
		leases:      cfg.Leases,
		holder:      cfg.LeaseHolder,
		logger:      cfg.Logger,
		stopCh:      make(chan struct{}),
	}
}

// Register adds a controller to the manager.
func (m *Manager) Register(c Controller) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		panic("cannot register controllers while manager is running")
	}

	m.controllers = append(m.controllers, c)

	// Publish the running gauge at 0 on registration so the series exists
	// before Start. Prometheus cannot alert on `controller_running == 0` for a
	// series that was never emitted, so without this a controller that is
	// registered but never started is indistinguishable from one that does not
	// exist. runController flips it to 1.
	if m.metrics != nil {
		m.metrics.SetControllerRunning(c.Name(), false)
	}

	m.logger.Info("controller registered",
		"name", c.Name(),
		"interval", c.Interval().String(),
	)
}

// Start starts all registered controllers.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("controller manager already running")
	}
	m.running = true
	m.stopCh = make(chan struct{})
	m.mu.Unlock()

	m.logger.Info("starting controller manager",
		"controller_count", len(m.controllers),
	)

	// Start each controller in its own goroutine
	for _, c := range m.controllers {
		m.wg.Add(1)
		go m.runController(ctx, c)
	}

	return nil
}

// Stop stops all controllers gracefully.
func (m *Manager) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = false
	close(m.stopCh)
	m.mu.Unlock()

	m.logger.Info("stopping controller manager")

	// Wait for all controllers to stop
	m.wg.Wait()

	m.logger.Info("controller manager stopped")
	return nil
}

// runController runs a single controller's reconciliation loop.
func (m *Manager) runController(ctx context.Context, c Controller) {
	defer m.wg.Done()

	name := c.Name()
	interval := c.Interval()

	m.logger.Info("starting controller", "name", name, "interval", interval)

	if m.metrics != nil {
		m.metrics.SetControllerRunning(name, true)
	}

	// Run immediately on start
	m.reconcileOnce(ctx, c)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			m.logger.Info("controller stopping (context canceled)", "name", name)
			if m.metrics != nil {
				m.metrics.SetControllerRunning(name, false)
			}
			return

		case <-m.stopCh:
			m.logger.Info("controller stopping (manager stopped)", "name", name)
			if m.metrics != nil {
				m.metrics.SetControllerRunning(name, false)
			}
			return

		case <-ticker.C:
			m.reconcileOnce(ctx, c)
		}
	}
}

// reconcileOnce runs a single reconciliation for a controller.
func (m *Manager) reconcileOnce(ctx context.Context, c Controller) {
	name := c.Name()
	start := time.Now()

	// Create a timeout context for this reconciliation. Default is the tick
	// interval; a controller may opt into a longer per-run budget (e.g. a queue
	// drainer that processes a batch inline) via ReconcileTimeouter.
	timeout := c.Interval()
	if t, ok := c.(ReconcileTimeouter); ok {
		if d := t.ReconcileTimeout(); d > 0 {
			timeout = d
		}
	}
	reconcileCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// An exclusive controller runs only while it holds its lease.
	if release, ok := m.holdLease(reconcileCtx, cancel, c, timeout); !ok {
		return
	} else if release != nil {
		defer release()
	}

	count, err := c.Reconcile(reconcileCtx)
	duration := time.Since(start)

	if err != nil {
		m.logger.Error("controller reconcile failed",
			"name", name,
			"duration", duration,
			"error", err,
		)
		if m.metrics != nil {
			m.metrics.IncrementReconcileErrors(name)
			m.metrics.RecordReconcile(name, count, duration, err)
		}
	} else {
		if count > 0 {
			m.logger.Info("controller reconcile completed",
				"name", name,
				"items_processed", count,
				"duration", duration,
			)
		}
		// No log when zero items — reduces noise in dev/prod logs
		if m.metrics != nil {
			m.metrics.RecordReconcile(name, count, duration, nil)
		}
	}

	if m.metrics != nil {
		m.metrics.SetLastReconcileTime(name, time.Now())
	}
}

// holdLease takes c's lease when c is Exclusive and the manager has a lease
// store, and renews it every third of its TTL while c reconciles; losing it
// cancels the reconcile. ok is false when another replica holds it (the tick
// is skipped). release is nil when no lease is involved.
func (m *Manager) holdLease(ctx context.Context, cancel context.CancelFunc, c Controller, timeout time.Duration) (release func(), ok bool) {
	ex, isEx := c.(Exclusive)
	if !isEx || !ex.Exclusive() || m.leases == nil || m.holder == "" {
		return nil, true
	}
	name := "controller:" + c.Name()
	ttl := controllerlease.ClampTTL(timeout + 30*time.Second)
	lease, got, err := m.leases.TryAcquire(ctx, name, m.holder, ttl)
	if err != nil {
		m.logger.Warn("controller lease unavailable; skipping this run", "name", c.Name(), "error", err)
		return nil, false
	}
	if !got {
		m.logger.Debug("controller lease held by another replica; skipping this run", "name", c.Name())
		return nil, false
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		every := ttl / 3
		if m.leaseRenew > 0 {
			every = m.leaseRenew
		}
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
				held, rerr := m.leases.Renew(rctx, lease, ttl)
				rcancel()
				if rerr == nil && !held {
					m.logger.Warn("controller lease lost; stopping this run", "name", c.Name(), "epoch", lease.Epoch)
					cancel()
					return
				}
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		rctx, rcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer rcancel()
		if err := m.leases.Release(rctx, lease); err != nil {
			m.logger.Warn("failed to release controller lease", "name", c.Name(), "error", err)
		}
	}, true
}

// IsRunning checks if the manager is running.
func (m *Manager) IsRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// ControllerCount returns the number of registered controllers.
func (m *Manager) ControllerCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.controllers)
}

// ControllerNames returns the names of all registered controllers.
func (m *Manager) ControllerNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	names := make([]string, len(m.controllers))
	for i, c := range m.controllers {
		names[i] = c.Name()
	}
	return names
}
