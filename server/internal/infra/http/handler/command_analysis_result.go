package handler

import (
	"context"

	"github.com/openctemio/openctem/server/internal/app/aianalysis"
	commanddom "github.com/openctemio/openctem/server/pkg/domain/command"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// analysisResultApplier takes an AI worker's result once its analysis job
// completed (aianalysis.WorkerExecutor).
type analysisResultApplier interface {
	ApplyResult(ctx context.Context, tenantID, commandID shared.ID) (*aianalysis.RunDetail, error)
}

// SetAnalysisResults wires the taking of AI worker results.
func (h *CommandHandler) SetAnalysisResults(a analysisResultApplier) { h.analysisResults = a }

// applyAnalysisResult takes the result of a completed analysis job for its
// run (docs/architecture/ai-analysis.md, "Applying a worker's result"). It
// runs after the real completion only (never a replay); the tenant is the
// command's own. A failure here never fails the worker's completion: the
// run records why, and the sweep takes a result left untaken.
func (h *CommandHandler) applyAnalysisResult(ctx context.Context, cmd *commanddom.Command) {
	if h.analysisResults == nil || cmd == nil || cmd.Type != commanddom.CommandTypeAnalyze ||
		cmd.Status != commanddom.CommandStatusCompleted {
		return
	}
	if _, err := h.analysisResults.ApplyResult(context.WithoutCancel(ctx), cmd.TenantID, cmd.ID); err != nil {
		h.logger.Warn("AI worker result not taken; the sweep retries", "command_id", cmd.ID.String(), "error", logger.SanitizeError(err))
	}
}
