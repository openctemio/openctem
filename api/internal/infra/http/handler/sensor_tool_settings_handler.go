package handler

// Per-sensor tool settings (docs/architecture/sensors.md, "Tool settings").
// Reads need sensors:read; saving and resetting need sensors:write (owners
// and administrators). Every route ends with OwnSensor: another
// organization's sensor and a platform sensor answer 404.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/ctis/settings"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// ToolSettingsProblem is one invalid value, by JSON pointer into the values.
type ToolSettingsProblem struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// SensorToolSettingsResponse is one tool's settings on a sensor: the
// settings schema its descriptor declares in the sensor's current manifest
// (the CTIS settings contract), the stored values (keys left out take their
// defaults) and, when the stored values no longer validate against that
// schema (a sensor upgrade changed it), the problems.
type SensorToolSettingsResponse struct {
	Tool         string                `json:"tool"`
	SchemaDigest string                `json:"schema_digest"`
	Schema       json.RawMessage       `json:"schema" swaggertype:"object"`
	Values       map[string]any        `json:"values"`
	Stored       bool                  `json:"stored"`
	StoredDigest string                `json:"stored_digest,omitempty"`
	Problems     []ToolSettingsProblem `json:"problems"`
	UpdatedAt    *string               `json:"updated_at,omitempty"`
	UpdatedBy    *string               `json:"updated_by,omitempty"`
}

// SensorToolSettingsListResponse is every tool of the sensor's current
// manifest that declares settings.
type SensorToolSettingsListResponse struct {
	Items []SensorToolSettingsResponse `json:"items"`
}

// UpdateSensorToolSettingsRequest replaces one tool's settings.
type UpdateSensorToolSettingsRequest struct {
	Values map[string]any `json:"values" swaggertype:"object"`
}

// EffectiveToolSettingResponse is one key of a tool's effective settings.
type EffectiveToolSettingResponse struct {
	Key string `json:"key"`
	// Value is null when the key has neither a default nor a stored value.
	Value  any    `json:"value"`
	Source string `json:"source" enums:"default,sensor,scan,"`
	Flag   string `json:"flag,omitempty"`
	Common string `json:"common,omitempty"`
	Scope  string `json:"scope" enums:"sensor,scan"`
	Tier   string `json:"tier,omitempty"`
}

// PreviewSensorToolSettingsRequest is a scan's (or a workflow step's) tool
// options: its config, as the scan stores it.
type PreviewSensorToolSettingsRequest struct {
	Config map[string]any `json:"config" swaggertype:"object"`
}

// SensorToolSettingsPreviewResponse is every key of a tool's schema with the
// value a job of a scan with the given config runs with on this sensor
// (source default, sensor or scan), before the job's own limits and the
// sensor's local policy, which only lower values. Ignored lists the config
// keys the sensor ignores (not options of this tool, or read by the
// sensor's executor itself: rate_limit, concurrency, bulk_size,
// allow_interactsh, exclude).
type SensorToolSettingsPreviewResponse struct {
	Tool         string                         `json:"tool"`
	SchemaDigest string                         `json:"schema_digest"`
	Items        []EffectiveToolSettingResponse `json:"items"`
	Ignored      []string                       `json:"ignored"`
}

// SensorEffectiveToolSettingsResponse is every key of a tool's schema with
// the value a job of this sensor runs with before the scan's own options.
type SensorEffectiveToolSettingsResponse struct {
	Tool         string                         `json:"tool"`
	SchemaDigest string                         `json:"schema_digest"`
	Items        []EffectiveToolSettingResponse `json:"items"`
}

func toSensorToolSettingsResponse(v sensorapp.ToolSettingsView) SensorToolSettingsResponse {
	out := SensorToolSettingsResponse{
		Tool: v.Tool, SchemaDigest: v.SchemaDigest, Schema: v.Schema, Values: v.Values,
		Stored: v.Stored, StoredDigest: v.StoredDigest, Problems: sensorToolSettingsProblems(v.Problems),
	}
	if out.Values == nil {
		out.Values = map[string]any{}
	}
	if v.UpdatedAt != nil {
		at := v.UpdatedAt.UTC().Format(time.RFC3339)
		out.UpdatedAt = &at
	}
	if v.UpdatedBy != nil {
		by := v.UpdatedBy.String()
		out.UpdatedBy = &by
	}
	return out
}

func sensorToolSettingsProblems(errs settings.Errors) []ToolSettingsProblem {
	out := make([]ToolSettingsProblem, 0, len(errs))
	for _, e := range errs {
		out = append(out, ToolSettingsProblem{Path: e.Path, Message: e.Message})
	}
	return out
}

// handleToolSettingsError writes the answer to a tool settings error:
// invalid values as 422 with every problem by path.
func (h *SensorHandler) handleToolSettingsError(w http.ResponseWriter, err error) {
	var errs settings.Errors
	switch {
	case errors.As(err, &errs):
		apierror.ValidationFailed("The settings are not valid for this tool", sensorToolSettingsProblems(errs)).WriteJSON(w)
	case errors.Is(err, sensor.ErrToolHasNoSettings):
		apierror.NotFound("Tool settings").WriteJSON(w)
	default:
		h.handleServiceError(w, err)
	}
}

// ListToolSettings handles GET /api/v1/sensors/{id}/tool-settings
// @Summary      Sensor tool settings
// @Description  Every tool of the sensor's current manifest that declares a settings schema: the schema, its digest and the stored values. Values that no longer validate after a sensor upgrade are listed with their problems.
// @Tags         Sensors
// @Produce      json
// @Param        id   path      string  true  "Sensor ID"
// @Success      200  {object}  SensorToolSettingsListResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/tool-settings [get]
func (h *SensorHandler) ListToolSettings(w http.ResponseWriter, r *http.Request) {
	views, err := h.service.ListToolSettings(r.Context(), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		h.handleToolSettingsError(w, err)
		return
	}
	out := SensorToolSettingsListResponse{Items: make([]SensorToolSettingsResponse, 0, len(views))}
	for _, v := range views {
		out.Items = append(out.Items, toSensorToolSettingsResponse(v))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// UpdateToolSettings handles PUT /api/v1/sensors/{id}/tool-settings/{tool}
// @Summary      Save a tool's settings on a sensor
// @Description  Replaces the tool's settings on the sensor. The values are validated with the tool's settings schema from the sensor's current manifest; a non-default value of a dangerous (T2) option is refused (the organization's enablement of dangerous options is not available yet). The change is audited; values of sensitive keys never appear in the audit log. The settings reach the sensor inside each signed scan job of the tool.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id    path      string                           true  "Sensor ID"
// @Param        tool  path      string                           true  "Tool name"
// @Param        body  body      UpdateSensorToolSettingsRequest  true  "Values"
// @Success      200   {object}  SensorToolSettingsResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      422   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/tool-settings/{tool} [put]
func (h *SensorHandler) UpdateToolSettings(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, sensor.MaxToolSettingsBytes+1024))
	if err != nil {
		apierror.BadRequest("Request body too large").WriteJSON(w)
		return
	}
	var req struct {
		Values json.RawMessage `json:"values"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	values, err := sensor.DecodeToolSettingsValues(req.Values)
	if err != nil {
		h.handleToolSettingsError(w, err)
		return
	}
	v, err := h.service.UpdateToolSettings(r.Context(), sensorapp.UpdateToolSettingsInput{
		TenantID: middleware.GetTenantID(r.Context()), SensorID: chi.URLParam(r, "id"),
		Tool: chi.URLParam(r, "tool"), Values: values, AuditContext: h.buildAuditContext(r),
	})
	if err != nil {
		h.handleToolSettingsError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toSensorToolSettingsResponse(*v))
}

// ResetToolSettings handles DELETE /api/v1/sensors/{id}/tool-settings/{tool}
// @Summary      Reset a tool's settings on a sensor
// @Description  Removes the tool's stored settings: every key takes its default again. Audited. Works for a tool the current manifest no longer lists.
// @Tags         Sensors
// @Param        id    path  string  true  "Sensor ID"
// @Param        tool  path  string  true  "Tool name"
// @Success      204   "No Content"
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/tool-settings/{tool} [delete]
func (h *SensorHandler) ResetToolSettings(w http.ResponseWriter, r *http.Request) {
	if err := h.service.ResetToolSettings(r.Context(), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"),
		chi.URLParam(r, "tool"), h.buildAuditContext(r)); err != nil {
		h.handleToolSettingsError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// EffectiveToolSettings handles GET /api/v1/sensors/{id}/tool-settings/{tool}/effective
// @Summary      Effective tool settings of a sensor
// @Description  Every key of the tool's settings schema with the value a scan job of this sensor runs with before the scan's own options, where it comes from (default or sensor), the tool's native flag, the common option it is, its scope and its safety tier. 422 when the stored values no longer validate.
// @Tags         Sensors
// @Produce      json
// @Param        id    path      string  true  "Sensor ID"
// @Param        tool  path      string  true  "Tool name"
// @Success      200   {object}  SensorEffectiveToolSettingsResponse
// @Failure      404   {object}  apierror.Error
// @Failure      422   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/tool-settings/{tool}/effective [get]
func (h *SensorHandler) EffectiveToolSettings(w http.ResponseWriter, r *http.Request) {
	eff, view, err := h.service.EffectiveToolSettings(r.Context(), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"), chi.URLParam(r, "tool"))
	if err != nil {
		h.handleToolSettingsError(w, err)
		return
	}
	out := SensorEffectiveToolSettingsResponse{Tool: view.Tool, SchemaDigest: view.SchemaDigest,
		Items: make([]EffectiveToolSettingResponse, 0, len(eff))}
	for _, e := range eff {
		out.Items = append(out.Items, EffectiveToolSettingResponse{Key: e.Key, Value: e.Value, Source: string(e.Source),
			Flag: e.Flag, Common: e.Common, Scope: string(e.Scope), Tier: e.Tier})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// PreviewToolSettings handles POST /api/v1/sensors/{id}/tool-settings/{tool}/preview
// @Summary      Preview a scan's tool options on a sensor
// @Description  Resolves a scan's (or a workflow step's) config over the sensor's stored settings for the tool, as the sensor will when it runs a job of that scan: every key with its value and source (default, sensor or scan). Read-only. 422 with every problem by path when the sensor would refuse the config: a sensor-only option, a value out of bounds, a raise of rate, concurrency or retries above the value in force, or a dangerous option.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        id    path      string                            true  "Sensor ID"
// @Param        tool  path      string                            true  "Tool name"
// @Param        body  body      PreviewSensorToolSettingsRequest  true  "Scan config"
// @Success      200   {object}  SensorToolSettingsPreviewResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      422   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/tool-settings/{tool}/preview [post]
func (h *SensorHandler) PreviewToolSettings(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, sensor.MaxToolSettingsBytes+1024))
	if err != nil {
		apierror.BadRequest("Request body too large").WriteJSON(w)
		return
	}
	var req struct {
		Config json.RawMessage `json:"config"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	config, err := sensor.DecodeToolSettingsValues(req.Config)
	if err != nil {
		h.handleToolSettingsError(w, err)
		return
	}
	p, err := h.service.PreviewToolSettings(r.Context(), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"), chi.URLParam(r, "tool"), config)
	if err != nil {
		h.handleToolSettingsError(w, err)
		return
	}
	out := SensorToolSettingsPreviewResponse{Tool: p.View.Tool, SchemaDigest: p.View.SchemaDigest,
		Items: make([]EffectiveToolSettingResponse, 0, len(p.Effective)), Ignored: p.Ignored}
	if out.Ignored == nil {
		out.Ignored = []string{}
	}
	for _, e := range p.Effective {
		out.Items = append(out.Items, EffectiveToolSettingResponse{Key: e.Key, Value: e.Value, Source: string(e.Source),
			Flag: e.Flag, Common: e.Common, Scope: string(e.Scope), Tier: e.Tier})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
