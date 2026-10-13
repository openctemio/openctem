package handler

// GET /api/v1/scan-runs/{id}/tasks/{task_id}/placement: why a queued task
// waits (docs/architecture/placement.md). The counts and reason codes are
// for anyone who can read the run; the per-sensor list (names and reasons
// of the organization's own sensors) only for a caller who can read
// sensors. Platform scanning is never broken down into sensors.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	commandapp "github.com/openctemio/openctem/api/internal/app/command"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// taskPlacementExplainer explains a run task's placement
// (*command.Service).
type taskPlacementExplainer interface {
	ExplainRunTaskPlacement(ctx context.Context, tenantID, runID, commandID shared.ID) (*commandapp.Placement, error)
}

// SetPlacement serves the run page's "why waiting" from p.
func (h *ScanWorkflowHandler) SetPlacement(p taskPlacementExplainer) { h.placement = p }

// RunTaskPlacementReason is one reason and how many sensors it keeps the
// task from.
type RunTaskPlacementReason struct {
	Code  string `json:"code"`
	Count int    `json:"count"`
}

// RunTaskPlacementSensor is one of the organization's sensors and why it
// can or cannot take the task.
type RunTaskPlacementSensor struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Eligible bool     `json:"eligible"`
	Busy     bool     `json:"busy"`
	Reasons  []string `json:"reasons"`
}

// RunTaskPlacementResponse explains where a task can go. Queued is false
// for a task that is no longer waiting (nothing else is filled). Sensors is
// present only for a caller with sensors:read.
type RunTaskPlacementResponse struct {
	Queued     bool                     `json:"queued"`
	Platform   bool                     `json:"platform"`
	JobReasons []string                 `json:"job_reasons"`
	Evaluated  int                      `json:"evaluated"`
	Truncated  bool                     `json:"truncated"`
	Eligible   int                      `json:"eligible"`
	Busy       int                      `json:"busy"`
	Blocking   []RunTaskPlacementReason `json:"blocking"`
	Sensors    []RunTaskPlacementSensor `json:"sensors,omitempty"`
}

// GetRunTaskPlacement handles GET /api/v1/scan-runs/{id}/tasks/{task_id}/placement
// @Summary      Why a run task waits
// @Description  For a queued task: the reasons that hold it whatever the sensor (scan window, busy host, expired), how many of the organization's sensors may take it and how many of those are busy, and each reason that keeps it from the others with a count. Callers with sensors:read also get each sensor's verdict. A task waiting for platform scanning names no sensor. A task that is not in the run (or the run is another organization's) is not found.
// @Tags         Scan workflows
// @Produce      json
// @Param        id       path      string  true  "Run ID"
// @Param        task_id  path      string  true  "Task ID"
// @Success      200  {object}  RunTaskPlacementResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-runs/{id}/tasks/{task_id}/placement [get]
func (h *ScanWorkflowHandler) GetRunTaskPlacement(w http.ResponseWriter, r *http.Request) {
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
	if !h.guardRun(w, r) {
		return
	}
	if h.placement == nil {
		apierror.NotFound("Task").WriteJSON(w)
		return
	}
	p, err := h.placement.ExplainRunTaskPlacement(r.Context(), tenantID, runID, taskID)
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Task").WriteJSON(w)
		return
	case err != nil:
		h.logger.Error("failed to explain task placement", "error", err)
		apierror.InternalServerError("failed to explain the task's placement").WriteJSON(w)
		return
	}
	resp := placementResponse(p, middleware.HasPermission(r.Context(), permission.SensorsRead.String()))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// placementResponse maps p; withSensors adds the per-sensor verdicts.
func placementResponse(p *commandapp.Placement, withSensors bool) RunTaskPlacementResponse {
	resp := RunTaskPlacementResponse{JobReasons: []string{}, Blocking: []RunTaskPlacementReason{}}
	resp.Queued = p.Status == "pending"
	if !resp.Queued {
		return resp
	}
	resp.Platform = p.Platform
	if p.Platform {
		return resp
	}
	resp.JobReasons = append(resp.JobReasons, p.JobReasons...)
	resp.Evaluated, resp.Truncated = len(p.Sensors), p.Truncated
	resp.Eligible, resp.Busy = p.Eligible, p.Busy
	for _, b := range p.Blocking {
		resp.Blocking = append(resp.Blocking, RunTaskPlacementReason{Code: b.Code, Count: b.Count})
	}
	if withSensors {
		resp.Sensors = make([]RunTaskPlacementSensor, 0, len(p.Sensors))
		for _, s := range p.Sensors {
			reasons := s.Reasons
			if reasons == nil {
				reasons = []string{}
			}
			resp.Sensors = append(resp.Sensors, RunTaskPlacementSensor{ID: s.SensorID.String(), Name: s.Name,
				Eligible: s.Eligible, Busy: s.Busy, Reasons: reasons})
		}
	}
	return resp
}
