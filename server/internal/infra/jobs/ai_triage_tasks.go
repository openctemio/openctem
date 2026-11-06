package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"

	aitriagedom "github.com/openctemio/openctem/api/pkg/domain/aitriage"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// =============================================================================
// Task Types
// =============================================================================

const (
	// TypeAITriage is the task type for AI triage processing.
	TypeAITriage = "ai:triage"

	// aiTriageMaxRetry is how often the queue retries a transient failure.
	aiTriageMaxRetry = 3
	// aiTriageTaskTimeout bounds one attempt.
	aiTriageTaskTimeout = 4 * time.Minute
)

// =============================================================================
// Task Payloads
// =============================================================================

// AITriagePayload contains data for processing an AI triage job.
type AITriagePayload struct {
	ResultID  string `json:"result_id"`
	TenantID  string `json:"tenant_id"`
	FindingID string `json:"finding_id"`
}

// =============================================================================
// Task Creators
// =============================================================================

// NewAITriageTask creates a task for processing an AI triage job.
func NewAITriageTask(payload AITriagePayload, delay time.Duration) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal ai triage payload: %w", err)
	}

	opts := []asynq.Option{
		asynq.MaxRetry(aiTriageMaxRetry),
		// Longer than one provider call with its own retries (three tries of
		// AI_TIMEOUT_SECONDS plus backoff), so the queue does not cancel an
		// attempt the provider client is still retrying.
		asynq.Timeout(aiTriageTaskTimeout),
		asynq.Queue("ai_triage"),
	}

	if delay > 0 {
		opts = append(opts, asynq.ProcessIn(delay))
	}

	return asynq.NewTask(TypeAITriage, data, opts...), nil
}

// =============================================================================
// Task Handler Interface
// =============================================================================

// AITriageProcessor defines the interface for processing AI triage jobs.
// This is implemented by AITriageService.
type AITriageProcessor interface {
	// ProcessTriage processes a triage job.
	ProcessTriage(ctx context.Context, resultID, tenantID, findingID shared.ID) error
}

// =============================================================================
// Task Handler
// =============================================================================

// AITriageTaskHandler handles AI triage tasks.
type AITriageTaskHandler struct {
	processor AITriageProcessor
	log       *slog.Logger
}

// NewAITriageTaskHandler creates a new AI triage task handler.
func NewAITriageTaskHandler(processor AITriageProcessor, log *slog.Logger) *AITriageTaskHandler {
	return &AITriageTaskHandler{
		processor: processor,
		log:       log,
	}
}

// HandleTriage handles the AI triage task.
func (h *AITriageTaskHandler) HandleTriage(ctx context.Context, t *asynq.Task) error {
	var payload AITriagePayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		h.log.Error("failed to unmarshal AI triage payload", "error", err)
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	h.log.Info("processing AI triage task",
		"result_id", payload.ResultID,
		"finding_id", payload.FindingID,
	)

	// Parse IDs
	resultID, err := shared.IDFromString(payload.ResultID)
	if err != nil {
		h.log.Error("invalid result_id", "error", err, "result_id", payload.ResultID)
		return fmt.Errorf("invalid result_id: %w", err)
	}

	tenantID, err := shared.IDFromString(payload.TenantID)
	if err != nil {
		h.log.Error("invalid tenant_id", "error", err, "tenant_id", payload.TenantID)
		return fmt.Errorf("invalid tenant_id: %w", err)
	}

	findingID, err := shared.IDFromString(payload.FindingID)
	if err != nil {
		h.log.Error("invalid finding_id", "error", err, "finding_id", payload.FindingID)
		return fmt.Errorf("invalid finding_id: %w", err)
	}

	// Process triage. The service retries transient failures through the
	// queue while attempts are left, and fails the row on the last one.
	retried, _ := asynq.GetRetryCount(ctx)
	maxRetry, ok := asynq.GetMaxRetry(ctx)
	ctx = aitriagedom.WithRetriesLeft(ctx, ok && retried < maxRetry)
	if err := h.processor.ProcessTriage(ctx, resultID, tenantID, findingID); err != nil {
		h.log.Error("failed to process AI triage",
			"error", err,
			"result_id", payload.ResultID,
			"finding_id", payload.FindingID,
		)
		if errors.Is(err, aitriagedom.ErrTriageFailed) {
			// Final: the row is failed; another attempt would find it so.
			return fmt.Errorf("%w: %w", err, asynq.SkipRetry)
		}
		return err
	}

	h.log.Info("AI triage task completed",
		"result_id", payload.ResultID,
		"finding_id", payload.FindingID,
	)

	return nil
}

// RegisterHandlers registers AI triage task handlers with the asynq server mux.
func (h *AITriageTaskHandler) RegisterHandlers(mux *asynq.ServeMux) {
	mux.HandleFunc(TypeAITriage, h.HandleTriage)
}
