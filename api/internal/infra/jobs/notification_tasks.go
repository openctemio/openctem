package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"
)

// =============================================================================
// Task Types
// =============================================================================

const (
	// TypeNotificationProcess is the task type for processing outbox entries.
	TypeNotificationProcess = "notification:process"

	// TypeNotificationCleanup is the task type for cleaning up old outbox entries.
	TypeNotificationCleanup = "notification:cleanup"

	// TypeNotificationUnlockStale is the task type for unlocking stale entries.
	TypeNotificationUnlockStale = "notification:unlock_stale"
)

// =============================================================================
// Task Payloads
// =============================================================================

// NotificationProcessPayload contains data for processing outbox entries.
type NotificationProcessPayload struct {
	WorkerID  string `json:"worker_id"`
	BatchSize int    `json:"batch_size"`
}

// NotificationCleanupPayload contains data for cleanup tasks.
type NotificationCleanupPayload struct {
	CompletedOlderThanDays int `json:"completed_older_than_days"`
	FailedOlderThanDays    int `json:"failed_older_than_days"`
}

// NotificationUnlockStalePayload contains data for unlocking stale entries.
type NotificationUnlockStalePayload struct {
	OlderThanMinutes int `json:"older_than_minutes"`
}

// =============================================================================
// Task Creators
// =============================================================================

// NewNotificationProcessTask creates a task for processing outbox entries.
func NewNotificationProcessTask(workerID string, batchSize int) (*asynq.Task, error) {
	payload, err := json.Marshal(NotificationProcessPayload{
		WorkerID:  workerID,
		BatchSize: batchSize,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal notification process payload: %w", err)
	}

	return asynq.NewTask(
		TypeNotificationProcess,
		payload,
		asynq.MaxRetry(0),            // Don't retry the task itself, retries are handled in outbox
		asynq.Timeout(2*time.Minute), // 2 minute timeout for batch processing
		asynq.Queue("notifications"), // Dedicated queue
	), nil
}

// NewNotificationCleanupTask creates a task for cleaning up old outbox entries.
func NewNotificationCleanupTask(completedDays, failedDays int) (*asynq.Task, error) {
	payload, err := json.Marshal(NotificationCleanupPayload{
		CompletedOlderThanDays: completedDays,
		FailedOlderThanDays:    failedDays,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal notification cleanup payload: %w", err)
	}

	return asynq.NewTask(
		TypeNotificationCleanup,
		payload,
		asynq.MaxRetry(3),
		asynq.Timeout(5*time.Minute),
		asynq.Queue("maintenance"),
	), nil
}

// NewNotificationUnlockStaleTask creates a task for unlocking stale entries.
func NewNotificationUnlockStaleTask(olderThanMinutes int) (*asynq.Task, error) {
	payload, err := json.Marshal(NotificationUnlockStalePayload{
		OlderThanMinutes: olderThanMinutes,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal notification unlock stale payload: %w", err)
	}

	return asynq.NewTask(
		TypeNotificationUnlockStale,
		payload,
		asynq.MaxRetry(3),
		asynq.Timeout(1*time.Minute),
		asynq.Queue("maintenance"),
	), nil
}

// =============================================================================
// Task Handlers
// =============================================================================

// NotificationTaskHandler handles notification-related tasks.
type NotificationTaskHandler struct {
	processor NotificationProcessor
	log       *slog.Logger
}

// NotificationProcessor defines the interface for processing notifications.
// This will be implemented by the notification service.
type NotificationProcessor interface {
	// ProcessOutboxBatch processes a batch of outbox entries.
	ProcessOutboxBatch(ctx context.Context, workerID string, batchSize int) (processed, failed int, err error)

	// CleanupOldEntries removes old completed and failed entries.
	CleanupOldEntries(ctx context.Context, completedDays, failedDays int) (deletedCompleted, deletedFailed int64, err error)

	// UnlockStaleEntries releases locks on stale processing entries.
	UnlockStaleEntries(ctx context.Context, olderThanMinutes int) (unlocked int64, err error)
}

// NewNotificationTaskHandler creates a new notification task handler.
func NewNotificationTaskHandler(processor NotificationProcessor, log *slog.Logger) *NotificationTaskHandler {
	return &NotificationTaskHandler{
		processor: processor,
		log:       log,
	}
}

// HandleProcess handles the notification process task.
func (h *NotificationTaskHandler) HandleProcess(ctx context.Context, t *asynq.Task) error {
	var payload NotificationProcessPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	processed, failed, err := h.processor.ProcessOutboxBatch(ctx, payload.WorkerID, payload.BatchSize)
	if err != nil {
		h.log.Error("failed to process notification batch",
			"error", err,
			"worker_id", payload.WorkerID,
		)
		return err
	}

	h.log.Info("processed notification batch",
		"worker_id", payload.WorkerID,
		"processed", processed,
		"failed", failed,
	)

	return nil
}

// HandleCleanup handles the notification cleanup task.
func (h *NotificationTaskHandler) HandleCleanup(ctx context.Context, t *asynq.Task) error {
	var payload NotificationCleanupPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	deletedCompleted, deletedFailed, err := h.processor.CleanupOldEntries(
		ctx,
		payload.CompletedOlderThanDays,
		payload.FailedOlderThanDays,
	)
	if err != nil {
		h.log.Error("failed to cleanup notification outbox",
			"error", err,
		)
		return err
	}

	h.log.Info("cleaned up notification outbox",
		"deleted_completed", deletedCompleted,
		"deleted_failed", deletedFailed,
	)

	return nil
}

// HandleUnlockStale handles the unlock stale entries task.
func (h *NotificationTaskHandler) HandleUnlockStale(ctx context.Context, t *asynq.Task) error {
	var payload NotificationUnlockStalePayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	unlocked, err := h.processor.UnlockStaleEntries(ctx, payload.OlderThanMinutes)
	if err != nil {
		h.log.Error("failed to unlock stale notification entries",
			"error", err,
		)
		return err
	}

	if unlocked > 0 {
		h.log.Warn("unlocked stale notification entries",
			"unlocked", unlocked,
			"older_than_minutes", payload.OlderThanMinutes,
		)
	}

	return nil
}

// RegisterHandlers registers notification task handlers with the asynq server mux.
func (h *NotificationTaskHandler) RegisterHandlers(mux *asynq.ServeMux) {
	mux.HandleFunc(TypeNotificationProcess, h.HandleProcess)
	mux.HandleFunc(TypeNotificationCleanup, h.HandleCleanup)
	mux.HandleFunc(TypeNotificationUnlockStale, h.HandleUnlockStale)
}
