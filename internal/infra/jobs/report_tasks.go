package jobs

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/hibiken/asynq"
)

const (
	// TypeScheduledReportGenerate is the task type for generating a scheduled report.
	TypeScheduledReportGenerate = "report:generate_scheduled"
)

// ScheduledReportPayload contains data for a scheduled report generation job.
type ScheduledReportPayload struct {
	TenantID   string `json:"tenant_id"`
	ScheduleID string `json:"schedule_id"`
	ReportType string `json:"report_type"`
	Format     string `json:"format"`
}

// NewScheduledReportTask creates a new scheduled report generation task.
func NewScheduledReportTask(payload ScheduledReportPayload) (*asynq.Task, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}
	return asynq.NewTask(
		TypeScheduledReportGenerate,
		data,
		asynq.MaxRetry(2),
		asynq.Timeout(5*time.Minute),
		asynq.Queue("reports"),
	), nil
}
