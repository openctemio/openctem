package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SetRunEvents serves the run timeline (GET /scan-runs/{id}/events) from r.
func (h *ScanWorkflowHandler) SetRunEvents(r command.EventReader) { h.runEvents = r }

// RunEvent is one change in the life of one of the run's tasks.
type RunEvent struct {
	ID     string `json:"id"`
	TaskID string `json:"task_id"`
	// Event: queued, claimed, started, refused, requeued, completed,
	// failed, canceled, expired.
	Event   string `json:"event"`
	Status  string `json:"status,omitempty"`
	Attempt int    `json:"attempt"`
	// Platform: platform scanning ran the task. Its sensor is never named.
	Platform bool   `json:"platform"`
	SensorID string `json:"sensor_id,omitempty"`
	Code     string `json:"code,omitempty"`
	Message  string `json:"message,omitempty"`
	At       string `json:"at"`
}

// RunEventsResponse is a run's timeline, oldest first. Truncated: the run
// has more events than one read returns (2000).
type RunEventsResponse struct {
	Events    []RunEvent `json:"events"`
	Truncated bool       `json:"truncated"`
}

// ListRunEvents handles GET /api/v1/scan-runs/{id}/events
// @Summary      A run's timeline
// @Description  What happened to each task of the run, oldest first: queued, claimed, started, refused, requeued and how it ended, at most 2000 events. Kept 30 days. Platform scanning tasks never name their sensor. A run of another organization, or about a finding the caller may not see, is not found.
// @Tags         Scan workflows
// @Produce      json
// @Param        id   path      string  true  "Run ID"
// @Success      200  {object}  RunEventsResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-runs/{id}/events [get]
func (h *ScanWorkflowHandler) ListRunEvents(w http.ResponseWriter, r *http.Request) {
	if !h.guardRun(w, r) {
		return
	}
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.NotFound("Run").WriteJSON(w)
		return
	}
	runID, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Run").WriteJSON(w)
		return
	}
	resp := RunEventsResponse{Events: []RunEvent{}}
	if h.runEvents != nil {
		events, truncated, err := h.runEvents.ListForRun(r.Context(), tenantID, runID, command.MaxRunEvents)
		if err != nil {
			h.logger.Error("failed to read run events", "error", err)
			apierror.InternalServerError("failed to read the run's events").WriteJSON(w)
			return
		}
		resp.Truncated = truncated
		for _, e := range events {
			resp.Events = append(resp.Events, toRunEvent(e))
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// toRunEvent shapes an event for the tenant: a platform job's sensor is left
// out and its message masked, like every other platform-sensor field (#1362).
func toRunEvent(e command.Event) RunEvent {
	out := RunEvent{
		ID: e.ID.String(), TaskID: e.CommandID.String(), Event: e.Event, Status: e.Status,
		Attempt: e.Attempt, Platform: e.Platform, Code: e.Code,
		Message: platformText(e.Platform, e.Message),
		At:      e.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if e.SensorID != nil && !e.Platform {
		out.SensorID = e.SensorID.String()
	}
	return out
}
