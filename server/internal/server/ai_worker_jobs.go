package server

import (
	"context"
	"time"

	"github.com/openctemio/openctem/server/internal/app/aianalysis"
	"github.com/openctemio/openctem/server/internal/app/command"
	commanddom "github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// analysisJobQueue queues the analysis jobs of runs on AI workers as
// `analyze` commands of the organization (docs/architecture/ai-analysis.md).
// It is the only path that creates one: the commands API does not accept
// the type.
type analysisJobQueue struct{ cmds *command.Service }

// QueueAnalysisJob implements aianalysis.AnalysisJobQueue.
func (q analysisJobQueue) QueueAnalysisJob(ctx context.Context, j aianalysis.AnalysisJob) error {
	secs := int(time.Until(j.ExpiresAt) / time.Second)
	if secs < 1 {
		secs = 1
	}
	_, err := q.cmds.Create(ctx, command.CreateInput{TenantID: j.TenantID.String(), ID: j.CommandID,
		Type: string(commanddom.CommandTypeAnalyze), Priority: j.Priority, Payload: j.Payload, ExpiresIn: secs})
	return err
}

// CancelAnalysisJob implements aianalysis.AnalysisJobQueue.
func (q analysisJobQueue) CancelAnalysisJob(ctx context.Context, tenantID, commandID shared.ID) error {
	_, err := q.cmds.CancelCommand(ctx, tenantID.String(), commandID.String())
	return err
}
