package jobs

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
)

const (
	// TypeAssetLifecycleCleanup archives stale assets (unseen > threshold days).
	TypeAssetLifecycleCleanup = "asset:lifecycle_cleanup"
)

// AssetLifecyclePayload contains config for the cleanup job.
type AssetLifecyclePayload struct {
	TenantID      string `json:"tenant_id"`
	StaleDays     int    `json:"stale_days"`      // Assets unseen > N days get archived
	DryRun        bool   `json:"dry_run"`         // If true, only log — don't archive
}

// NewAssetLifecycleTask creates a scheduled asset lifecycle cleanup task.
func NewAssetLifecycleTask(payload AssetLifecyclePayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	return asynq.NewTask(
		TypeAssetLifecycleCleanup,
		data,
		asynq.MaxRetry(1),
		asynq.Timeout(10*time.Minute),
		asynq.Queue("maintenance"),
	), nil
}
