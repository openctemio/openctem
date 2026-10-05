package handler

// Scanner content (docs/rfcs/RFC-031-managed-sensor-updates.md): the tenant's
// content policy and refresh requests. What sensors report is on the sensor
// itself (SensorResponse.content).

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SensorContentHandler serves the content policy and refresh endpoints.
type SensorContentHandler struct {
	service *sensorapp.ContentService
	audit   func(r *http.Request) *auditsvc.AuditContext
	logger  *logger.Logger
}

// NewSensorContentHandler creates the handler. sensors provides the audit
// context of a request (the same as every sensor write).
func NewSensorContentHandler(svc *sensorapp.ContentService, sensors *SensorHandler, log *logger.Logger) *SensorContentHandler {
	return &SensorContentHandler{service: svc, audit: sensors.buildAuditContext, logger: log.With("handler", "sensor_content")}
}

// ContentPolicyBody is a scanner content policy: the refresh interval, and
// per content (trivy-db, trivy-java-db, nuclei-templates, semgrep-rules) the
// maximum age, a pinned version (an OCI digest "sha256:..." for a database, a
// release tag for templates) and, for semgrep-rules, the registry rulesets.
// It never names a content source.
type ContentPolicyBody struct {
	RefreshIntervalHours int                       `json:"refresh_interval_hours"`
	Content              map[string]ContentPinBody `json:"content"`
}

// ContentPinBody is the policy for one kind of content. max_age_hours 0 =
// the platform default.
type ContentPinBody struct {
	MaxAgeHours int      `json:"max_age_hours"`
	Version     string   `json:"version"`
	Rulesets    []string `json:"rulesets"`
}

// ContentPolicyResponse is GET/PUT /sensors/content-policy.
type ContentPolicyResponse struct {
	// Policy is the effective policy (defaults filled in).
	Policy ContentPolicyBody `json:"policy"`
	// Defaults is the platform default.
	Defaults ContentPolicyBody `json:"defaults"`
	// UpdatedAt / UpdatedBy are null while the tenant uses the defaults.
	UpdatedAt *string `json:"updated_at"`
	UpdatedBy *string `json:"updated_by"`
	// CommandsCreated / Skipped: only on PUT with apply_now.
	CommandsCreated *int `json:"commands_created,omitempty"`
	Skipped         *int `json:"skipped,omitempty"`
}

// UpdateContentPolicyRequest is the PUT body.
type UpdateContentPolicyRequest struct {
	Policy ContentPolicyBody `json:"policy"`
	// ApplyNow sends the policy to every sensor that manages content now (a
	// refresh_content command each, not forced). Otherwise sensors get it
	// with their next refresh request.
	ApplyNow bool `json:"apply_now"`
}

// RefreshContentRequest is the body of the refresh endpoints. content empty =
// all managed content; force defaults to true (refresh even fresh content).
type RefreshContentRequest struct {
	Content []string `json:"content"`
	Force   *bool    `json:"force"`
}

// RefreshContentResponse is POST /sensors/{id}/content/refresh.
type RefreshContentResponse struct {
	CommandID string `json:"command_id"`
	// AlreadyPending: a refresh was already queued for the sensor; that
	// command is returned and no new one was created.
	AlreadyPending bool `json:"already_pending"`
}

// FleetRefreshContentResponse is POST /sensors/content/refresh.
type FleetRefreshContentResponse struct {
	CommandsCreated int `json:"commands_created"`
	// Skipped: sensors that do not manage content, are disabled or revoked,
	// or already have a refresh queued.
	Skipped int `json:"skipped"`
}

// GetPolicy handles GET /api/v1/sensors/content-policy
// @Summary      Get the scanner content policy
// @Description  The tenant's scanner content policy (RFC-031): refresh interval, and per content the maximum age, a pinned version and semgrep rulesets. Defaults are filled in.
// @Tags         Sensors
// @Produce      json
// @Success      200  {object}  ContentPolicyResponse
// @Failure      401  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/content-policy [get]
func (h *SensorContentHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	view, err := h.service.GetPolicy(r.Context(), tenantID)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policyResponse(view))
}

// UpdatePolicy handles PUT /api/v1/sensors/content-policy
// @Summary      Update the scanner content policy
// @Description  Replace the tenant's scanner content policy. With apply_now every sensor that manages content gets a refresh_content command carrying it.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        body  body      UpdateContentPolicyRequest  true  "Policy"
// @Success      200   {object}  ContentPolicyResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/content-policy [put]
func (h *SensorContentHandler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	var req UpdateContentPolicyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	view, res, err := h.service.UpdatePolicy(r.Context(), tenantID, req.Policy.toDomain(), req.ApplyNow, h.audit(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	resp := policyResponse(view)
	if req.ApplyNow {
		resp.CommandsCreated, resp.Skipped = &res.CommandsCreated, &res.Skipped
	}
	writeJSON(w, http.StatusOK, resp)
}

// RefreshSensor handles POST /api/v1/sensors/{id}/content/refresh
// @Summary      Refresh a sensor's scanner content
// @Description  Queue a refresh_content command for the sensor (trivy DB, nuclei templates, semgrep rules). 409 when the sensor manages no content (an older sensor) or is disabled. A refresh already queued is returned instead of a new one.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id    path      string                 true   "Sensor ID"
// @Param        body  body      RefreshContentRequest  false  "Content to refresh"
// @Success      202   {object}  RefreshContentResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/content/refresh [post]
func (h *SensorContentHandler) RefreshSensor(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	sensorID, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Sensor").WriteJSON(w)
		return
	}
	req, ok := decodeRefresh(w, r)
	if !ok {
		return
	}
	id, pending, err := h.service.RefreshSensor(r.Context(), tenantID, sensorID, req.Content, forceOf(req), h.audit(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, RefreshContentResponse{CommandID: id.String(), AlreadyPending: pending})
}

// RefreshFleet handles POST /api/v1/sensors/content/refresh
// @Summary      Refresh scanner content on every sensor
// @Description  Queue a refresh_content command for every sensor of the tenant that manages content and has none queued.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        body  body      RefreshContentRequest  false  "Content to refresh"
// @Success      200   {object}  FleetRefreshContentResponse
// @Failure      400   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/content/refresh [post]
func (h *SensorContentHandler) RefreshFleet(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := h.tenant(w, r)
	if !ok {
		return
	}
	req, ok := decodeRefresh(w, r)
	if !ok {
		return
	}
	res, err := h.service.RefreshFleet(r.Context(), tenantID, req.Content, forceOf(req), h.audit(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, FleetRefreshContentResponse{CommandsCreated: res.CommandsCreated, Skipped: res.Skipped})
}

func decodeRefresh(w http.ResponseWriter, r *http.Request) (RefreshContentRequest, bool) {
	var req RefreshContentRequest
	if r.Body == nil || r.ContentLength == 0 {
		return req, true
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return req, false
	}
	return req, true
}

func forceOf(req RefreshContentRequest) bool {
	return req.Force == nil || *req.Force
}

func (h *SensorContentHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

func (h *SensorContentHandler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sensorapp.ErrContentRefreshUnsupported):
		apierror.Conflict("The sensor does not support content refresh: it reports no content it manages, or it is disabled.").WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Sensor").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("sensor content request failed", "error", logger.SanitizeError(err))
		apierror.InternalError(err).WriteJSON(w)
	}
}

func (b ContentPolicyBody) toDomain() sensor.ContentPolicy {
	p := sensor.ContentPolicy{RefreshIntervalHours: b.RefreshIntervalHours}
	if len(b.Content) > 0 {
		p.Content = make(map[string]sensor.ContentPin, len(b.Content))
		for name, pin := range b.Content {
			p.Content[name] = sensor.ContentPin{MaxAgeHours: pin.MaxAgeHours, Version: pin.Version, Rulesets: pin.Rulesets}
		}
	}
	return p
}

func policyBody(p sensor.ContentPolicy) ContentPolicyBody {
	b := ContentPolicyBody{RefreshIntervalHours: p.RefreshIntervalHours, Content: map[string]ContentPinBody{}}
	for name, pin := range p.Content {
		rs := pin.Rulesets
		if rs == nil {
			rs = []string{}
		}
		b.Content[name] = ContentPinBody{MaxAgeHours: pin.MaxAgeHours, Version: pin.Version, Rulesets: rs}
	}
	return b
}

func policyResponse(v *sensorapp.ContentPolicyView) ContentPolicyResponse {
	resp := ContentPolicyResponse{Policy: policyBody(v.Policy), Defaults: policyBody(v.Defaults)}
	if v.UpdatedAt != nil {
		s := v.UpdatedAt.UTC().Format(time.RFC3339)
		resp.UpdatedAt = &s
	}
	if v.UpdatedBy != nil {
		s := v.UpdatedBy.String()
		resp.UpdatedBy = &s
	}
	return resp
}
