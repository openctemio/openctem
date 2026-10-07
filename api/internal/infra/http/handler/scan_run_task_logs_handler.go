package handler

// GET /api/v1/scan-runs/{id}/tasks/{task_id}/logs: the log lines a
// sensor sent for one task of a run (RFC-029 §4.4.1). The lines were capped,
// cleaned and redacted when they were stored; the web shows them as plain
// text.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/commandlog"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// taskLogReader reads a run task's logs (*commandlog.Service).
type taskLogReader interface {
	ListForRunTask(ctx context.Context, tenantID, runID, commandID shared.ID) (commandlog.Page, error)
}

// SetTaskLogs serves the run page's task logs from r.
func (h *ScanWorkflowHandler) SetTaskLogs(r taskLogReader) { h.taskLogs = r }

// RunTaskLogLine is one log line of a task.
type RunTaskLogLine struct {
	TS     time.Time      `json:"ts"`
	Level  string         `json:"level" enums:"debug,info,warn,error"`
	Msg    string         `json:"msg"`
	Source string         `json:"source,omitempty"`
	Fields map[string]any `json:"fields,omitempty"`
}

// RunTaskLogsResponse is a task's log. Truncated: lines were dropped (the
// sensor reached the per-task caps, or the read limit of 5000 lines).
type RunTaskLogsResponse struct {
	Lines     []RunTaskLogLine `json:"lines"`
	Truncated bool             `json:"truncated"`
}

// GetRunTaskLogs handles GET /api/v1/scan-runs/{id}/tasks/{task_id}/logs
// @Summary      A run task's logs
// @Description  The log lines the sensor sent for one task of the run, oldest first, at most 5000. Kept 14 days. A task that is not in the run (or the run is another organization's) is not found.
// @Tags         Scan workflows
// @Produce      json
// @Param        id       path      string  true  "Run ID"
// @Param        task_id  path      string  true  "Task ID"
// @Success      200  {object}  RunTaskLogsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-runs/{id}/tasks/{task_id}/logs [get]
func (h *ScanWorkflowHandler) GetRunTaskLogs(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.NotFound("Task").WriteJSON(w)
		return
	}
	runID, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("invalid run id").WriteJSON(w)
		return
	}
	taskID, err := shared.IDFromString(chi.URLParam(r, "task_id"))
	if err != nil {
		apierror.BadRequest("invalid task id").WriteJSON(w)
		return
	}
	resp := RunTaskLogsResponse{Lines: []RunTaskLogLine{}}
	if h.taskLogs != nil {
		page, err := h.taskLogs.ListForRunTask(r.Context(), tenantID, runID, taskID)
		switch {
		case errors.Is(err, shared.ErrNotFound):
			apierror.NotFound("Task").WriteJSON(w)
			return
		case err != nil:
			h.logger.Error("failed to read task logs", "error", err)
			apierror.InternalServerError("failed to read the task's logs").WriteJSON(w)
			return
		}
		resp.Truncated = page.Truncated
		for _, l := range page.Lines {
			resp.Lines = append(resp.Lines, RunTaskLogLine{TS: l.TS, Level: l.Level, Msg: l.Msg, Source: l.Source, Fields: l.Fields})
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
