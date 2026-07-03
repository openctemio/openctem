package validation

import (
	"context"
	"encoding/json"
	"fmt"

	commanddom "github.com/openctemio/api/pkg/domain/command"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// CommandCreator is the narrow seam over the command repository used to enqueue
// a validation job. Implemented by *postgres.CommandRepository.
type CommandCreator interface {
	Create(ctx context.Context, cmd *commanddom.Command) error
}

// JobDispatcher enqueues a validation job for an agent to execute and returns
// the command ID it was queued under. It is fire-and-forget: the agent reports
// the result later and the command-completion hook maps that result back into
// Evidence via EvidenceIngestService. (This is the async counterpart to the
// synchronous ValidationDispatcher.Submit contract, which does not fit the
// platform's poll/complete queue.)
type JobDispatcher interface {
	Dispatch(ctx context.Context, job ValidationJob) (shared.ID, error)
}

// ValidateTargetPayload is the target section of a validate command payload.
type ValidateTargetPayload struct {
	AssetID string `json:"asset_id"`
	Type    string `json:"type"`
	Address string `json:"address"`
}

// ValidateCommandPayload is the JSON payload embedded in a CommandTypeValidate
// command. It is the wire contract between the API (producer) and the agent
// executor (consumer); the agent replies with a ValidateResultPayload.
type ValidateCommandPayload struct {
	JobID          string                `json:"job_id"`
	FindingID      string                `json:"finding_id"`
	ExecutorKind   string                `json:"executor_kind"`
	Technique      string                `json:"technique"`
	Target         ValidateTargetPayload `json:"target"`
	TimeoutSeconds int                   `json:"timeout_seconds"`
	// RequiredCapabilities lets the platform route the job only to agents that
	// advertise the validation capability (mirrors the scan command payload).
	RequiredCapabilities []string `json:"required_capabilities"`
}

// ValidateResultPayload is what an agent reports back in the command result for
// a validate command. Kept small and stable; RawMeta carries probe detail.
type ValidateResultPayload struct {
	Outcome  string         `json:"outcome"`
	Summary  string         `json:"summary"`
	Evidence map[string]any `json:"evidence,omitempty"`
}

// CommandDispatcher implements JobDispatcher by creating a CommandTypeValidate
// command that a validate-capable agent polls and executes.
type CommandDispatcher struct {
	commands CommandCreator
	logger   *logger.Logger
}

// NewCommandDispatcher wires the dispatcher over the command repository.
func NewCommandDispatcher(commands CommandCreator, log *logger.Logger) *CommandDispatcher {
	return &CommandDispatcher{
		commands: commands,
		logger:   log.With("service", "validation-dispatcher"),
	}
}

// Dispatch enqueues the job as a tenant command and returns the command ID.
func (d *CommandDispatcher) Dispatch(ctx context.Context, job ValidationJob) (shared.ID, error) {
	if job.TenantID.IsZero() || job.FindingID.IsZero() {
		return shared.ID{}, fmt.Errorf("%w: tenant and finding ids are required", shared.ErrValidation)
	}

	payload := ValidateCommandPayload{
		JobID:        job.JobID.String(),
		FindingID:    job.FindingID.String(),
		ExecutorKind: string(job.ExecutorKind),
		Technique:    string(job.Technique),
		Target: ValidateTargetPayload{
			AssetID: job.Target.AssetID.String(),
			Type:    job.Target.Type,
			Address: job.Target.Address,
		},
		TimeoutSeconds:       job.TimeoutSeconds,
		RequiredCapabilities: []string{"validate"},
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return shared.ID{}, fmt.Errorf("marshal validate payload: %w", err)
	}

	cmd, err := commanddom.NewCommand(job.TenantID, commanddom.CommandTypeValidate, commanddom.CommandPriorityNormal, raw)
	if err != nil {
		return shared.ID{}, fmt.Errorf("build validate command: %w", err)
	}

	if err := d.commands.Create(ctx, cmd); err != nil {
		return shared.ID{}, fmt.Errorf("enqueue validate command: %w", err)
	}

	d.logger.Info("validation job dispatched",
		"command_id", cmd.ID.String(),
		"tenant_id", job.TenantID.String(),
		"finding_id", job.FindingID.String(),
		"executor_kind", string(job.ExecutorKind),
		"technique", string(job.Technique),
	)
	return cmd.ID, nil
}
