package app

import (
	"context"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/logger"
	"github.com/google/uuid"
)

// NotificationSchedulerConfig holds configuration for the notification scheduler.
type NotificationSchedulerConfig struct {
	// ProcessInterval is how often to process outbox entries (default: 5 seconds).
	ProcessInterval time.Duration
	// CleanupInterval is how often to cleanup old entries (default: 24 hours).
	CleanupInterval time.Duration
	// UnlockInterval is how often to unlock stale entries (default: 1 minute).
	UnlockInterval time.Duration
	// BatchSize is the number of entries to process per batch (default: 50).
	BatchSize int
	// CompletedRetentionDays is how long to keep completed outbox entries (default: 7).
	// Note: With the new architecture, completed entries are deleted immediately after archiving.
	// This is kept for backward compatibility and for entries that failed to archive.
	CompletedRetentionDays int
	// FailedRetentionDays is how long to keep failed outbox entries (default: 30).
	FailedRetentionDays int
	// EventRetentionDays is how long to keep archived notification events (default: 90).
	// Set to 0 for unlimited retention.
	EventRetentionDays int
	// StaleMinutes is how long before a locked entry is considered stale (default: 10).
	StaleMinutes int
}

// DefaultNotificationSchedulerConfig returns the default configuration.
func DefaultNotificationSchedulerConfig() NotificationSchedulerConfig {
	return NotificationSchedulerConfig{
		ProcessInterval:        5 * time.Second,
		CleanupInterval:        24 * time.Hour,
		UnlockInterval:         1 * time.Minute,
		BatchSize:              50,
		CompletedRetentionDays: 7,
		FailedRetentionDays:    30,
		EventRetentionDays:     90,
		StaleMinutes:           10,
	}
}

// NotificationScheduler runs periodic notification processing tasks.
type NotificationScheduler struct {
	service  *NotificationService
	config   NotificationSchedulerConfig
	log      *logger.Logger
	workerID string

	stopCh  chan struct{}
	wg      sync.WaitGroup
	mu      sync.Mutex
	running bool
}

// NewNotificationScheduler creates a new notification scheduler.
func NewNotificationScheduler(service *NotificationService, config NotificationSchedulerConfig, log *logger.Logger) *NotificationScheduler {
	return &NotificationScheduler{
		service:  service,
		config:   config,
		log:      log,
		workerID: uuid.New().String()[:8], // Short unique ID for this worker
		stopCh:   make(chan struct{}),
	}
}

// Start starts the notification scheduler.
func (s *NotificationScheduler) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	s.log.Info("starting notification scheduler",
		"worker_id", s.workerID,
		"process_interval", s.config.ProcessInterval,
		"batch_size", s.config.BatchSize,
	)

	// Start processing goroutine
	s.wg.Add(1)
	go s.processLoop()

	// Start cleanup goroutine
	s.wg.Add(1)
	go s.cleanupLoop()

	// Start unlock goroutine
	s.wg.Add(1)
	go s.unlockLoop()
}

// Stop stops the notification scheduler gracefully.
func (s *NotificationScheduler) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	s.mu.Unlock()

	s.log.Info("stopping notification scheduler")
	close(s.stopCh)
	s.wg.Wait()
	s.log.Info("notification scheduler stopped")
}

// processLoop continuously processes outbox entries.
func (s *NotificationScheduler) processLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.ProcessInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.processBatch()
		}
	}
}

// processBatch processes a batch of pending outbox entries.
func (s *NotificationScheduler) processBatch() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	processed, failed, err := s.service.ProcessOutboxBatch(ctx, s.workerID, s.config.BatchSize)
	if err != nil {
		s.log.Error("failed to process notification batch",
			"error", err,
			"worker_id", s.workerID,
		)
		return
	}

	if processed > 0 || failed > 0 {
		s.log.Info("processed notification batch",
			"worker_id", s.workerID,
			"processed", processed,
			"failed", failed,
		)
	}
}

// cleanupLoop periodically cleans up old entries.
func (s *NotificationScheduler) cleanupLoop() {
	defer s.wg.Done()

	// Run cleanup immediately on start
	s.cleanup()

	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.cleanup()
		}
	}
}

// cleanup removes old completed and failed outbox entries, and old archived events.
func (s *NotificationScheduler) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Cleanup old outbox entries
	deletedCompleted, deletedFailed, err := s.service.CleanupOldEntries(
		ctx,
		s.config.CompletedRetentionDays,
		s.config.FailedRetentionDays,
	)
	if err != nil {
		s.log.Error("failed to cleanup notification outbox", "error", err)
	} else if deletedCompleted > 0 || deletedFailed > 0 {
		s.log.Info("cleaned up notification outbox",
			"deleted_completed", deletedCompleted,
			"deleted_failed", deletedFailed,
		)
	}

	// Cleanup old archived events
	deletedEvents, err := s.service.CleanupOldEvents(ctx, s.config.EventRetentionDays)
	if err != nil {
		s.log.Error("failed to cleanup notification events", "error", err)
	} else if deletedEvents > 0 {
		s.log.Info("cleaned up notification events",
			"deleted_events", deletedEvents,
			"retention_days", s.config.EventRetentionDays,
		)
	}
}

// unlockLoop periodically unlocks stale entries.
func (s *NotificationScheduler) unlockLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.config.UnlockInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.unlockStale()
		}
	}
}

// unlockStale releases locks on entries that have been processing too long.
func (s *NotificationScheduler) unlockStale() {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	unlocked, err := s.service.UnlockStaleEntries(ctx, s.config.StaleMinutes)
	if err != nil {
		s.log.Error("failed to unlock stale notification entries", "error", err)
		return
	}

	if unlocked > 0 {
		s.log.Warn("unlocked stale notification entries",
			"unlocked", unlocked,
			"older_than_minutes", s.config.StaleMinutes,
		)
	}
}
