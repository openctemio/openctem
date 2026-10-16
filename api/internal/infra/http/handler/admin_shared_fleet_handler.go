package handler

// Console > System > Shared sensors (docs/rfcs/RFC-100-shared-sensors.md §12):
// the instance sensors, queue aggregates, per-organization usage and job
// metadata for any administrator; a job's targets and logs only through an
// audited view with a reason (super or operations administrator); pause,
// resume and retire for a super admin with a reason and a fresh
// authenticator code (route-level step-up). Results and findings are never
// served here.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// AdminSharedFleetHandler serves the console's shared sensor fleet.
type AdminSharedFleetHandler struct {
	svc    *sensorapp.SharedFleetService
	logger *logger.Logger
}

// NewAdminSharedFleetHandler creates the handler.
func NewAdminSharedFleetHandler(svc *sensorapp.SharedFleetService, log *logger.Logger) *AdminSharedFleetHandler {
	return &AdminSharedFleetHandler{svc: svc, logger: log.With("handler", "admin_shared_fleet")}
}

// SharedFleetSensorResponse is one shared sensor in the console.
type SharedFleetSensorResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Region      string     `json:"region"`
	Status      string     `json:"status"`
	Health      string     `json:"health"`
	Version     string     `json:"version"`
	Tools       []string   `json:"tools"`
	CurrentJobs int        `json:"current_jobs"`
	MaxJobs     int        `json:"max_jobs"`
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// SharedFleetListResponse is the fleet.
type SharedFleetListResponse struct {
	Sensors []SharedFleetSensorResponse `json:"sensors"`
}

// SharedQueueLaneResponse is the queue of one tool lane.
type SharedQueueLaneResponse struct {
	Tool    string `json:"tool"`
	Queued  int    `json:"queued"`
	Running int    `json:"running"`
}

// SharedOrgUsageResponse counts one organization's shared jobs.
type SharedOrgUsageResponse struct {
	TenantID string `json:"tenant_id"`
	// TenantName: for super and operations administrators only.
	TenantName   string `json:"tenant_name,omitempty"`
	Queued       int    `json:"queued"`
	Running      int    `json:"running"`
	Completed24h int    `json:"completed_24h"`
	Failed24h    int    `json:"failed_24h"`
}

// SharedQueueResponse is the queue aggregates.
type SharedQueueResponse struct {
	Lanes         []SharedQueueLaneResponse `json:"lanes"`
	Organizations []SharedOrgUsageResponse  `json:"organizations"`
}

// SharedJobResponse is one shared job's metadata.
type SharedJobResponse struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	// TenantName: for super and operations administrators only.
	TenantName  string     `json:"tenant_name,omitempty"`
	Type        string     `json:"type"`
	Tool        string     `json:"tool"`
	Status      string     `json:"status"`
	SensorID    string     `json:"sensor_id,omitempty"`
	SensorName  string     `json:"sensor_name,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// SharedJobListResponse is a page of job metadata.
type SharedJobListResponse struct {
	Data       []SharedJobResponse `json:"data"`
	Total      int64               `json:"total"`
	Page       int                 `json:"page"`
	PerPage    int                 `json:"per_page"`
	TotalPages int                 `json:"total_pages"`
}

// SharedJobLogLine is one log line of a shared job.
type SharedJobLogLine struct {
	TS     time.Time      `json:"ts"`
	Level  string         `json:"level"`
	Msg    string         `json:"msg"`
	Source string         `json:"source,omitempty"`
	Fields map[string]any `json:"fields,omitempty"`
}

// SharedJobDetailResponse is the audited view of one job.
type SharedJobDetailResponse struct {
	Job           SharedJobResponse  `json:"job"`
	Targets       []string           `json:"targets"`
	Logs          []SharedJobLogLine `json:"logs"`
	LogsTruncated bool               `json:"logs_truncated"`
}

// SharedFleetReasonRequest carries the reason of a view or an action (and
// the authenticator code, which the console also sends in the step-up
// header).
type SharedFleetReasonRequest struct {
	Reason   string `json:"reason"`
	TOTPCode string `json:"totp_code,omitempty"`
}

// seesOrganizationNames: organization names in the queue and job lists are
// for super and operations administrators; a read-only administrator gets
// the counts and opaque ids only.
func seesOrganizationNames(r *http.Request) bool {
	a := middleware.GetAdminUser(r.Context())
	return a != nil && (a.Role() == admin.AdminRoleSuperAdmin || a.Role() == admin.AdminRoleOpsAdmin)
}

func toSharedJobResponse(j sensorapp.SharedJob) SharedJobResponse {
	out := SharedJobResponse{ID: j.ID.String(), TenantID: j.TenantID.String(), TenantName: j.TenantName, Type: j.Type,
		Tool: j.Tool, Status: j.Status, SensorName: j.SensorName, CreatedAt: j.CreatedAt, StartedAt: j.StartedAt, CompletedAt: j.CompletedAt}
	if j.SensorID != nil {
		out.SensorID = j.SensorID.String()
	}
	return out
}

// List returns the shared sensors.
// @Summary      Shared sensors of this instance
// @Description  Every instance sensor: name, region, status, health, version, tools, current jobs and last seen. Any administrator.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  SharedFleetListResponse
// @Router       /admin/shared-sensors [get]
func (h *AdminSharedFleetHandler) List(w http.ResponseWriter, r *http.Request) {
	list, err := h.svc.List(r.Context())
	if err != nil {
		h.logger.Error("list shared sensors", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not read the shared sensors").WriteJSON(w)
		return
	}
	out := SharedFleetListResponse{Sensors: make([]SharedFleetSensorResponse, 0, len(list))}
	for _, s := range list {
		out.Sensors = append(out.Sensors, SharedFleetSensorResponse{ID: s.ID.String(), Name: s.Name, Region: s.Region,
			Status: s.Status, Health: s.Health, Version: s.Version, Tools: s.Tools, CurrentJobs: s.CurrentJobs,
			MaxJobs: s.MaxJobs, LastSeenAt: s.LastSeenAt, CreatedAt: s.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

// Queue returns the queue aggregates.
// @Summary      Shared sensor queue
// @Description  Queued and running shared jobs per tool lane, and per organization (with the last day's completed and failed counts). Counts only. Any administrator; organization names only for super and operations administrators.
// @Tags         Admin System
// @Produce      json
// @Success      200  {object}  SharedQueueResponse
// @Router       /admin/shared-sensors/queue [get]
func (h *AdminSharedFleetHandler) Queue(w http.ResponseWriter, r *http.Request) {
	q, err := h.svc.Queue(r.Context())
	if err != nil {
		h.logger.Error("shared sensor queue", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not read the queue").WriteJSON(w)
		return
	}
	out := SharedQueueResponse{Lanes: make([]SharedQueueLaneResponse, 0, len(q.Lanes)),
		Organizations: make([]SharedOrgUsageResponse, 0, len(q.Organizations))}
	for _, l := range q.Lanes {
		out.Lanes = append(out.Lanes, SharedQueueLaneResponse(l))
	}
	names := seesOrganizationNames(r)
	for _, o := range q.Organizations {
		if !names {
			o.TenantName = ""
		}
		out.Organizations = append(out.Organizations, SharedOrgUsageResponse{TenantID: o.TenantID.String(), TenantName: o.TenantName,
			Queued: o.Queued, Running: o.Running, Completed24h: o.Completed, Failed24h: o.Failed})
	}
	writeJSON(w, http.StatusOK, out)
}

// Jobs returns shared job metadata.
// @Summary      Shared jobs (metadata)
// @Description  Shared jobs, newest first: organization, type, tool, state, shared sensor and times. Never targets, payload, result or error text. Any administrator; organization names only for super and operations administrators.
// @Tags         Admin System
// @Produce      json
// @Param        sensor_id  query     string  false  "Shared sensor ID"
// @Param        tenant_id  query     string  false  "Organization ID"
// @Param        status     query     string  false  "Status"
// @Param        page       query     int     false  "Page"
// @Param        per_page   query     int     false  "Per page (max 100)"
// @Success      200  {object}  SharedJobListResponse
// @Router       /admin/shared-sensors/jobs [get]
func (h *AdminSharedFleetHandler) Jobs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var f sensorapp.SharedJobFilter
	for key, dst := range map[string]**shared.ID{"sensor_id": &f.SensorID, "tenant_id": &f.TenantID} {
		if v := q.Get(key); v != "" {
			id, err := shared.IDFromString(v)
			if err != nil {
				apierror.BadRequest(key + " is not a valid id").WriteJSON(w)
				return
			}
			*dst = &id
		}
	}
	f.Status = q.Get("status")
	page, _ := strconv.Atoi(q.Get("page"))
	perPage, _ := strconv.Atoi(q.Get("per_page"))
	res, err := h.svc.Jobs(r.Context(), f, pagination.New(page, perPage))
	if err != nil {
		h.writeErr(w, err)
		return
	}
	out := SharedJobListResponse{Data: make([]SharedJobResponse, 0, len(res.Data)), Total: res.Total, Page: res.Page,
		PerPage: res.PerPage, TotalPages: res.TotalPages}
	names := seesOrganizationNames(r)
	for _, j := range res.Data {
		if !names {
			j.TenantName = ""
		}
		out.Data = append(out.Data, toSharedJobResponse(j))
	}
	writeJSON(w, http.StatusOK, out)
}

// ViewJob returns a job's targets and logs, audited with the reason.
// @Summary      View a shared job's targets and logs
// @Description  Super or operations administrator, with a reason. Writes a high admin audit row naming the organization and the reason before anything is returned. Never the result or findings.
// @Tags         Admin System
// @Accept       json
// @Produce      json
// @Param        job_id   path      string                    true  "Job ID"
// @Param        request  body      SharedFleetReasonRequest  true  "Reason"
// @Success      200  {object}  SharedJobDetailResponse
// @Failure      404  {object}  apierror.Error
// @Router       /admin/shared-sensors/jobs/{job_id}/view [post]
func (h *AdminSharedFleetHandler) ViewJob(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(chi.URLParam(r, "job_id"))
	if err != nil {
		apierror.NotFound("Job").WriteJSON(w)
		return
	}
	c, ok := h.change(w, r)
	if !ok {
		return
	}
	d, err := h.svc.JobDetails(r.Context(), id, c)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	out := SharedJobDetailResponse{Job: toSharedJobResponse(d.Job), Targets: d.Targets,
		Logs: make([]SharedJobLogLine, 0, len(d.Logs)), LogsTruncated: d.LogsTruncate}
	for _, l := range d.Logs {
		out.Logs = append(out.Logs, SharedJobLogLine{TS: l.TS, Level: l.Level, Msg: l.Msg, Source: l.Source, Fields: l.Fields})
	}
	writeJSON(w, http.StatusOK, out)
}

// Pause pauses a shared sensor.
// @Summary      Pause a shared sensor
// @Description  Super admin with a reason and a fresh authenticator code (route-level step-up). The sensor takes no new jobs; jobs it holds run to the end. Audited (critical).
// @Tags         Admin System
// @Accept       json
// @Param        sensor_id  path  string                    true  "Shared sensor ID"
// @Param        request    body  SharedFleetReasonRequest  true  "Reason"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /admin/shared-sensors/{sensor_id}/disable [post]
func (h *AdminSharedFleetHandler) Pause(w http.ResponseWriter, r *http.Request) {
	h.act(w, r, h.svc.Pause)
}

// Resume resumes a paused shared sensor.
// @Summary      Resume a shared sensor
// @Description  Super admin with a reason and a fresh authenticator code (route-level step-up). A retired sensor cannot be resumed (409). Audited (critical).
// @Tags         Admin System
// @Accept       json
// @Param        sensor_id  path  string                    true  "Shared sensor ID"
// @Param        request    body  SharedFleetReasonRequest  true  "Reason"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /admin/shared-sensors/{sensor_id}/enable [post]
func (h *AdminSharedFleetHandler) Resume(w http.ResponseWriter, r *http.Request) {
	h.act(w, r, h.svc.Resume)
}

// Retire revokes a shared sensor for good.
// @Summary      Retire a shared sensor
// @Description  Super admin with a reason and a fresh authenticator code (route-level step-up). Revokes the sensor: its key no longer authenticates and it cannot be resumed. Audited (critical).
// @Tags         Admin System
// @Accept       json
// @Param        sensor_id  path  string                    true  "Shared sensor ID"
// @Param        request    body  SharedFleetReasonRequest  true  "Reason"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Router       /admin/shared-sensors/{sensor_id}/revoke [post]
func (h *AdminSharedFleetHandler) Retire(w http.ResponseWriter, r *http.Request) {
	h.act(w, r, h.svc.Retire)
}

func (h *AdminSharedFleetHandler) act(w http.ResponseWriter, r *http.Request, run func(ctx context.Context, id shared.ID, c sensorapp.AdminChange) error) {
	id, err := shared.IDFromString(chi.URLParam(r, "sensor_id"))
	if err != nil {
		apierror.NotFound("Shared sensor").WriteJSON(w)
		return
	}
	c, ok := h.change(w, r)
	if !ok {
		return
	}
	if err := run(r.Context(), id, c); err != nil {
		h.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *AdminSharedFleetHandler) change(w http.ResponseWriter, r *http.Request) (sensorapp.AdminChange, bool) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return sensorapp.AdminChange{}, false
	}
	var req SharedFleetReasonRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return sensorapp.AdminChange{}, false
	}
	return sensorapp.AdminChange{Actor: actor, Reason: req.Reason, IP: middleware.ClientIP(r), UserAgent: r.UserAgent()}, true
}

func (h *AdminSharedFleetHandler) writeErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Shared sensor or job").WriteJSON(w)
	case errors.Is(err, sensorapp.ErrSharedSensorRetired):
		apierror.Conflict("The shared sensor is retired").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden("not allowed").WriteJSON(w)
	default:
		h.logger.Error("shared sensor fleet", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not complete the request").WriteJSON(w)
	}
}
