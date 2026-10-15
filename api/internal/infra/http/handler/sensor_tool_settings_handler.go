package handler

// Tool settings (docs/architecture/sensors.md, "Tool settings"): the
// organization's defaults per tool and each sensor's overrides. Reads need
// sensors:read; saving and resetting need sensors:write (owners and
// administrators), plus step-up when an Impact option changes. Every route
// on one sensor ends with OwnSensor: another organization's sensor and a
// platform sensor answer 404.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/openctemio/ctis/settings"

	authapp "github.com/openctemio/openctem/api/internal/app/auth"
	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
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
	// OrganizationValues are the organization's defaults for the tool: the
	// sensor runs with them for every key it does not set itself.
	OrganizationValues map[string]any `json:"organization_values"`
	// OrganizationProblems are why the organization's defaults do not
	// validate against this sensor's schema (its jobs of the tool fail).
	OrganizationProblems []ToolSettingsProblem `json:"organization_problems"`
	UpdatedAt            *string               `json:"updated_at,omitempty"`
	UpdatedBy            *string               `json:"updated_by,omitempty"`
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
	Value any `json:"value"`
	// Source is the layer in force: the tool's default, the organization
	// ("tenant"), the sensor or the scan.
	Source string `json:"source" enums:"default,tenant,sensor,scan,"`
	Flag   string `json:"flag,omitempty"`
	Common string `json:"common,omitempty"`
	Scope  string `json:"scope" enums:"sensor,scan"`
	Tier   string `json:"tier,omitempty"`
	// Chain is every layer that sets the key, lowest first; the last one is
	// in force. An organization value the sensor overrides is listed too.
	Chain []ToolSettingLayerValue `json:"chain"`
}

// ToolSettingLayerValue is the value one layer sets for a key.
type ToolSettingLayerValue struct {
	Source string `json:"source" enums:"default,tenant,sensor,scan"`
	Value  any    `json:"value"`
}

// ToolDefaultsProblemResponse is why the organization's defaults do not
// validate against one sensor's schema of the tool.
type ToolDefaultsProblemResponse struct {
	SensorID   string                `json:"sensor_id"`
	SensorName string                `json:"sensor_name"`
	Problems   []ToolSettingsProblem `json:"problems"`
}

// ToolDefaultsResponse is one tool's organization defaults: the reference
// settings schema (from the most recently reported manifest that declares
// settings for the tool; null for stored defaults of a tool no sensor
// reports any more), the stored values, how many of the organization's own
// sensors declare settings for the tool, and the sensors whose schema
// refuses the values.
type ToolDefaultsResponse struct {
	Tool         string                        `json:"tool"`
	SchemaDigest string                        `json:"schema_digest"`
	Schema       json.RawMessage               `json:"schema" swaggertype:"object"`
	Values       map[string]any                `json:"values"`
	Stored       bool                          `json:"stored"`
	Sensors      int                           `json:"sensors"`
	Problems     []ToolDefaultsProblemResponse `json:"problems"`
	UpdatedAt    *string                       `json:"updated_at,omitempty"`
	UpdatedBy    *string                       `json:"updated_by,omitempty"`
}

// ToolDefaultsListResponse is every tool the organization's own sensors
// declare settings for, with the organization's defaults.
type ToolDefaultsListResponse struct {
	Items []ToolDefaultsResponse `json:"items"`
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
		OrganizationValues: v.Organization, OrganizationProblems: sensorToolSettingsProblems(v.OrganizationProblems),
	}
	if out.Values == nil {
		out.Values = map[string]any{}
	}
	if out.OrganizationValues == nil {
		out.OrganizationValues = map[string]any{}
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

func toEffectiveToolSettingResponse(e sensor.EffectiveToolSetting) EffectiveToolSettingResponse {
	out := EffectiveToolSettingResponse{Key: e.Key, Value: e.Value, Source: string(e.Source),
		Flag: e.Flag, Common: e.Common, Scope: string(e.Scope), Tier: e.Tier,
		Chain: make([]ToolSettingLayerValue, 0, len(e.Chain))}
	for _, c := range e.Chain {
		out.Chain = append(out.Chain, ToolSettingLayerValue{Source: string(c.Source), Value: c.Value})
	}
	return out
}

func toToolDefaultsResponse(v sensorapp.ToolDefaultsView) ToolDefaultsResponse {
	out := ToolDefaultsResponse{Tool: v.Tool, SchemaDigest: v.SchemaDigest, Schema: v.Schema, Values: v.Values,
		Stored: v.Stored, Sensors: v.Sensors, Problems: make([]ToolDefaultsProblemResponse, 0, len(v.Problems))}
	if len(out.Schema) == 0 {
		out.Schema = json.RawMessage("null")
	}
	if out.Values == nil {
		out.Values = map[string]any{}
	}
	for _, p := range v.Problems {
		out.Problems = append(out.Problems, ToolDefaultsProblemResponse{SensorID: p.SensorID.String(),
			SensorName: p.SensorName, Problems: sensorToolSettingsProblems(p.Errors)})
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
	if middleware.WriteStepUpError(w, err, authapp.StepUpWindow) {
		return
	}
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
// @Description  Replaces the tool's settings on the sensor: its overrides of the organization's defaults, in either direction. The values are validated with the tool's settings schema from the sensor's current manifest; a non-default value of a dangerous (T2) option is refused (the organization's enablement of dangerous options is not available yet). Setting an Impact (T1) option to a new value needs a recent re-authentication (403 STEP_UP_REQUIRED). The change is audited; values of sensitive keys never appear in the audit log. The settings reach the sensor inside each signed scan job of the tool.
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
// @Description  Every key of the tool's settings schema with the value a scan job of this sensor runs with before the scan's own options, where it comes from (default, tenant for the organization's defaults, or sensor), the chain of every layer that sets it, the tool's native flag, the common option it is, its scope and its safety tier. 422 when the sensor's values or the organization's defaults no longer validate against this sensor's schema.
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
		out.Items = append(out.Items, toEffectiveToolSettingResponse(e))
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
		out.Items = append(out.Items, toEffectiveToolSettingResponse(e))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// ListToolDefaults handles GET /api/v1/sensors/tool-defaults
// @Summary      Organization tool defaults
// @Description  Every tool that a current manifest of the organization's own sensors declares settings for: the reference schema (the most recently reported one), the organization's defaults, how many sensors declare settings for the tool, and the sensors whose schema refuses the defaults. Stored defaults of a tool no sensor reports any more come last, with a null schema. Shared platform sensors are never counted and never receive the defaults.
// @Tags         Sensors
// @Produce      json
// @Success      200  {object}  ToolDefaultsListResponse
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/tool-defaults [get]
func (h *SensorHandler) ListToolDefaults(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromContext(w, r)
	if !ok {
		return
	}
	views, err := h.service.ListToolDefaults(r.Context(), tid)
	if err != nil {
		h.handleToolSettingsError(w, err)
		return
	}
	out := ToolDefaultsListResponse{Items: make([]ToolDefaultsResponse, 0, len(views))}
	for _, v := range views {
		out.Items = append(out.Items, toToolDefaultsResponse(v))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// UpdateToolDefaults handles PUT /api/v1/sensors/tool-defaults/{tool}
// @Summary      Save a tool's organization defaults
// @Description  Replaces the organization's defaults for the tool: every one of its own sensors runs the tool with them unless the sensor overrides a key. The values must validate against every settings schema the organization's sensors report for the tool (422 by path, each message naming the sensor that refuses the value); a non-default dangerous (T2) value is refused. Setting an Impact (T1) option to a new value needs a recent re-authentication (403 STEP_UP_REQUIRED). Audited (high severity for an Impact change); values of sensitive keys never appear in the audit log.
// @Tags         Sensors
// @Accept       json
// @Produce      json
// @Param        tool  path      string                           true  "Tool name"
// @Param        body  body      UpdateSensorToolSettingsRequest  true  "Values"
// @Success      200   {object}  ToolDefaultsResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      422   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/tool-defaults/{tool} [put]
func (h *SensorHandler) UpdateToolDefaults(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromContext(w, r)
	if !ok {
		return
	}
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
	v, err := h.service.UpdateToolDefaults(r.Context(), sensorapp.UpdateToolDefaultsInput{
		TenantID: tid, Tool: chi.URLParam(r, "tool"), Values: values, AuditContext: h.buildAuditContext(r),
	})
	if err != nil {
		h.handleToolSettingsError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toToolDefaultsResponse(*v))
}

// ResetToolDefaults handles DELETE /api/v1/sensors/tool-defaults/{tool}
// @Summary      Reset a tool's organization defaults
// @Description  Removes the organization's defaults for the tool: every sensor runs it with the tool's defaults again, except the keys it overrides. Audited. Works for a tool no sensor reports any more.
// @Tags         Sensors
// @Param        tool  path  string  true  "Tool name"
// @Success      204   "No Content"
// @Failure      404   {object}  apierror.Error
// @Failure      500   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/tool-defaults/{tool} [delete]
func (h *SensorHandler) ResetToolDefaults(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromContext(w, r)
	if !ok {
		return
	}
	if err := h.service.ResetToolDefaults(r.Context(), tid, chi.URLParam(r, "tool"), h.buildAuditContext(r)); err != nil {
		h.handleToolSettingsError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// tenantFromContext is the caller's organization from the authenticated
// context (never the request).
func (h *SensorHandler) tenantFromContext(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Tenant context required").WriteJSON(w)
		return shared.ID{}, false
	}
	return tid, true
}
