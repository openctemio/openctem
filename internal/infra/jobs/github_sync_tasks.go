//nolint:dupl // parallel provider task handler; intentionally mirrors jira_sync_tasks.go with provider-specific types
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

// TypeGitHubSyncFindingStatus pushes a finding's status to its linked GitHub
// issue (outbound). Enqueued after an OpenCTEM-initiated finding status change;
// the handler is a no-op unless the finding is linked to a GitHub issue.
const TypeGitHubSyncFindingStatus = "github:sync_finding_status"

// GitHubSyncFindingStatusPayload identifies the finding whose status to push.
type GitHubSyncFindingStatusPayload struct {
	TenantID  string `json:"tenant_id"`
	FindingID string `json:"finding_id"`
}

// NewGitHubSyncFindingStatusTask builds the outbound GitHub status-sync task. A
// small delay lets the triggering DB transaction commit before the worker reads
// the finding.
func NewGitHubSyncFindingStatusTask(payload GitHubSyncFindingStatusPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal github sync payload: %w", err)
	}
	return asynq.NewTask(TypeGitHubSyncFindingStatus, data,
		asynq.MaxRetry(3),
		asynq.Timeout(1*time.Minute),
		asynq.Queue("default"),
		asynq.ProcessIn(5*time.Second),
	), nil
}

// GitHubStatusSyncer performs the outbound push. Implemented by
// ticketing.GitHubTicketService.SyncFindingStatus (resolves the tenant's GitHub
// integration, no-ops when the finding has no linked issue, closes/reopens it).
type GitHubStatusSyncer interface {
	SyncFindingStatus(ctx context.Context, tenantID, findingID shared.ID) error
}

// GitHubSyncTaskHandler handles outbound GitHub status-sync tasks.
type GitHubSyncTaskHandler struct {
	syncer GitHubStatusSyncer
	log    *slog.Logger
}

// NewGitHubSyncTaskHandler creates the handler.
func NewGitHubSyncTaskHandler(syncer GitHubStatusSyncer, log *slog.Logger) *GitHubSyncTaskHandler {
	return &GitHubSyncTaskHandler{syncer: syncer, log: log}
}

// HandleSyncFindingStatus processes one outbound status-sync task.
func (h *GitHubSyncTaskHandler) HandleSyncFindingStatus(ctx context.Context, t *asynq.Task) error {
	var payload GitHubSyncFindingStatusPayload
	if err := json.Unmarshal(t.Payload(), &payload); err != nil {
		h.log.Error("github sync: bad payload", "error", err)
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
		h.log.Error("github sync: push failed",
			"tenant_id", payload.TenantID, "finding_id", payload.FindingID, "error", err)
		return err // retry transient GitHub/API errors
	}
	return nil
}

// RegisterHandlers registers the github-sync handler with the asynq server mux.
func (h *GitHubSyncTaskHandler) RegisterHandlers(mux *asynq.ServeMux) {
	mux.HandleFunc(TypeGitHubSyncFindingStatus, h.HandleSyncFindingStatus)
}
