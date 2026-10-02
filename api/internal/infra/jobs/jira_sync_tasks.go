package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"

	"github.com/openctemio/api/pkg/domain/shared"
)

// TypeJiraSyncFindingStatus pushes a finding's status to its linked Jira issue
// (RFC-006 Phase 3c, outbound). Enqueued after an OpenCTEM-initiated finding
// status change; the handler is a no-op unless the tenant opted in.
const TypeJiraSyncFindingStatus = "jira:sync_finding_status"

// JiraSyncFindingStatusPayload identifies the finding whose status to push.
type JiraSyncFindingStatusPayload struct {
	TenantID  string `json:"tenant_id"`
	FindingID string `json:"finding_id"`
}

// NewJiraSyncFindingStatusTask builds the outbound Jira status-sync task. A
// small delay lets the triggering DB transaction commit before the worker reads
// the finding.
func NewJiraSyncFindingStatusTask(payload JiraSyncFindingStatusPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal jira sync payload: %w", err)
	}
	return asynq.NewTask(TypeJiraSyncFindingStatus, data,
		asynq.MaxRetry(3),
		asynq.Timeout(1*time.Minute),
		asynq.Queue("default"),
		asynq.ProcessIn(5*time.Second),
	), nil
}

// JiraStatusSyncer performs the outbound push. Implemented by
// jira.SyncService.SyncFindingStatus (resolves the tenant's mapping + client,
// honors the opt-in gate, echo-guards, falls back to a comment).
type JiraStatusSyncer interface {
	SyncFindingStatus(ctx context.Context, tenantID, findingID shared.ID) error
}

// JiraSyncTaskHandler handles outbound Jira status-sync tasks.
type JiraSyncTaskHandler struct {
	syncer JiraStatusSyncer
	log    *slog.Logger
}

// NewJiraSyncTaskHandler creates the handler.
func NewJiraSyncTaskHandler(syncer JiraStatusSyncer, log *slog.Logger) *JiraSyncTaskHandler {
	return &JiraSyncTaskHandler{syncer: syncer, log: log}
}

// HandleSyncFindingStatus processes one outbound status-sync task.
func (h *JiraSyncTaskHandler) HandleSyncFindingStatus(ctx context.Context, t *asynq.Task) error {
	var payload JiraSyncFindingStatusPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		// Unparseable payload will never succeed — drop it (SkipRetry).
		h.log.Error("jira sync: bad payload", "error", err)
		return fmt.Errorf("unmarshal payload: %w: %w", err, asynq.SkipRetry)
	}

	tenantID, err := shared.IDFromString(payload.TenantID)
	if err != nil {
		return fmt.Errorf("invalid tenant_id: %w: %w", err, asynq.SkipRetry)
	}
	findingID, err := shared.IDFromString(payload.FindingID)
	if err != nil {
		return fmt.Errorf("invalid finding_id: %w: %w", err, asynq.SkipRetry)
	}

	if err := h.syncer.SyncFindingStatus(ctx, tenantID, findingID); err != nil {
		h.log.Error("jira sync: push failed",
			"tenant_id", payload.TenantID, "finding_id", payload.FindingID, "error", err)
		return err // retry transient Jira/API errors
	}
	return nil
}

// RegisterHandlers registers the jira-sync handler with the asynq server mux.
func (h *JiraSyncTaskHandler) RegisterHandlers(mux *asynq.ServeMux) {
	mux.HandleFunc(TypeJiraSyncFindingStatus, h.HandleSyncFindingStatus)
}
