// Package controller implements K8s-style reconciliation loop controllers
// for self-healing background operations.
//
// Controllers periodically reconcile the desired state of the system with its actual state.
// Each controller runs in its own goroutine and handles a specific aspect of the system:
// - AgentHealthController: Marks stale agents as offline, cleans up expired leases
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

	"github.com/openctemio/api/pkg/logger"
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

// Manager manages multiple controllers, running them in parallel goroutines.
type Manager struct {
	controllers []Controller
	metrics     Metrics
	logger      *logger.Logger
	running     bool
	stopCh      chan struct{}
	wg          sync.WaitGroup
	mu          sync.Mutex
}

// ManagerConfig configures the controller manager.
type ManagerConfig struct {
	// Metrics collector (optional)
	Metrics Metrics

	// Logger (required)
	Logger *logger.Logger
}

// NewManager creates a new controller manager.
func NewManager(cfg *ManagerConfig) *Manager {
	return &Manager{
		controllers: make([]Controller, 0),
		metrics:     cfg.Metrics,
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

	// Create a timeout context for this reconciliation
	reconcileCtx, cancel := context.WithTimeout(ctx, c.Interval())
	defer cancel()

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
		} else {
			m.logger.Debug("controller reconcile completed (no items)",
				"name", name,
				"duration", duration,
			)
		}
		if m.metrics != nil {
			m.metrics.RecordReconcile(name, count, duration, nil)
		}
	}

	if m.metrics != nil {
		m.metrics.SetLastReconcileTime(name, time.Now())
	}
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
