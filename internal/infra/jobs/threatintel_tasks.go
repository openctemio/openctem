package jobs

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hibiken/asynq"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/logger"
)

// Threat Intel task types
const (
	TypeThreatIntelSyncAll  = "threatintel:sync_all"
	TypeThreatIntelSyncEPSS = "threatintel:sync_epss"
	TypeThreatIntelSyncKEV  = "threatintel:sync_kev"
)

// ThreatIntelSyncPayload is the payload for threat intel sync tasks.
type ThreatIntelSyncPayload struct {
	// Source is the specific source to sync (empty for all)
	Source string `json:"source,omitempty"`
}

// ThreatIntelTaskHandler handles threat intel background tasks.
type ThreatIntelTaskHandler struct {
	service *app.ThreatIntelService
	logger  *logger.Logger
}

// NewThreatIntelTaskHandler creates a new ThreatIntelTaskHandler.
func NewThreatIntelTaskHandler(service *app.ThreatIntelService, log *logger.Logger) *ThreatIntelTaskHandler {
	return &ThreatIntelTaskHandler{
		service: service,
		logger:  log.With("component", "threatintel_task_handler"),
	}
}

// HandleSyncAll handles the sync all task.
func (h *ThreatIntelTaskHandler) HandleSyncAll(ctx context.Context, task *asynq.Task) error {
	h.logger.Info("starting threat intel sync all task")

	results := h.service.SyncAll(ctx)

	for _, result := range results {
		if result.Error != nil {
			h.logger.Error("sync failed",
				"source", result.Source,
				"error", result.Error,
			)
		} else {
			h.logger.Info("sync completed",
				"source", result.Source,
				"records", result.RecordsSynced,
				"duration_ms", result.DurationMs,
			)
		}
	}

	// Return error if any sync failed
	for _, result := range results {
		if result.Error != nil {
			return fmt.Errorf("threat intel sync failed: %w", result.Error)
		}
	}

	return nil
}

// HandleSyncEPSS handles the EPSS sync task.
func (h *ThreatIntelTaskHandler) HandleSyncEPSS(ctx context.Context, task *asynq.Task) error {
	h.logger.Info("starting EPSS sync task")

	result := h.service.SyncEPSS(ctx)
	if result.Error != nil {
		h.logger.Error("EPSS sync failed", "error", result.Error)
		return fmt.Errorf("EPSS sync failed: %w", result.Error)
	}

	h.logger.Info("EPSS sync completed",
		"records", result.RecordsSynced,
		"duration_ms", result.DurationMs,
	)

	return nil
}

// HandleSyncKEV handles the KEV sync task.
func (h *ThreatIntelTaskHandler) HandleSyncKEV(ctx context.Context, task *asynq.Task) error {
	h.logger.Info("starting KEV sync task")

	result := h.service.SyncKEV(ctx)
	if result.Error != nil {
		h.logger.Error("KEV sync failed", "error", result.Error)
		return fmt.Errorf("KEV sync failed: %w", result.Error)
	}

	h.logger.Info("KEV sync completed",
		"records", result.RecordsSynced,
		"duration_ms", result.DurationMs,
	)

	return nil
}

// NewThreatIntelSyncAllTask creates a new sync all task.
func NewThreatIntelSyncAllTask() (*asynq.Task, error) {
	payload, err := json.Marshal(ThreatIntelSyncPayload{})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	return asynq.NewTask(TypeThreatIntelSyncAll, payload), nil
}

// NewThreatIntelSyncEPSSTask creates a new EPSS sync task.
func NewThreatIntelSyncEPSSTask() (*asynq.Task, error) {
	payload, err := json.Marshal(ThreatIntelSyncPayload{Source: "epss"})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	return asynq.NewTask(TypeThreatIntelSyncEPSS, payload), nil
}

// NewThreatIntelSyncKEVTask creates a new KEV sync task.
func NewThreatIntelSyncKEVTask() (*asynq.Task, error) {
	payload, err := json.Marshal(ThreatIntelSyncPayload{Source: "kev"})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	return asynq.NewTask(TypeThreatIntelSyncKEV, payload), nil
}
