package handler

// Management read of a sensor's config report: its setup checklist
// (research/26, pkg/domain/sensor/config_report.go). Summary, excerpt and
// observed values are sensor data and are returned as plain strings; title,
// why and fix come only from the platform catalog.

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// SensorConfigReportResponse is a sensor's setup checklist. state is
// reported (the sensor sent a config report), derived (an older sensor:
// the platform derived the checks from its heartbeat; see derived_note) or
// none (never connected). A stale report (the sensor's heartbeat no longer
// echoes its digest) keeps its checks with health unknown.
type SensorConfigReportResponse struct {
	State       string                      `json:"state" enums:"reported,derived,none"`
	Stale       bool                        `json:"stale"`
	Health      string                      `json:"health" enums:"ok,attention,impaired,blocked,unknown"`
	ObservedAt  *string                     `json:"observed_at"`
	ReceivedAt  *string                     `json:"received_at"`
	Truncated   bool                        `json:"truncated"`
	RuntimeKind string                      `json:"runtime_kind" enums:"docker,kubernetes,systemd,binary,unknown"`
	DerivedNote string                      `json:"derived_note"`
	Counts      sensor.ConfigCounts         `json:"counts"`
	Checks      []SensorConfigCheckResponse `json:"checks"`
	Settings    []sensor.ConfigSetting      `json:"settings"`
}

// SensorConfigCheckResponse is one check. known is false for a check id
// the platform catalog does not have (a newer sensor): title is then the
// id, and why and fix are empty. summary and excerpt are the sensor's text,
// to be shown as plain text only.
type SensorConfigCheckResponse struct {
	ID       string                     `json:"id"`
	Group    string                     `json:"group" enums:"platform,identity,policy,tools,content,network,storage,runtime,config,connector"`
	Status   string                     `json:"status" enums:"pass,warn,fail,skip,error"`
	Severity string                     `json:"severity" enums:"info,warning,critical"`
	Code     string                     `json:"code"`
	Known    bool                       `json:"known"`
	Title    string                     `json:"title"`
	Why      string                     `json:"why"`
	Observed []SensorConfigObservedItem `json:"observed"`
	Summary  string                     `json:"summary"`
	Excerpt  string                     `json:"excerpt"`
	Keys     []string                   `json:"keys"`
	Blocks   []string                   `json:"blocks"`
	// Fix maps a format (env, compose, helm) to a snippet from the
	// platform catalog with the check's values escaped for that format;
	// only the formats the catalog has, {} when none.
	Fix     map[string]string `json:"fix"`
	DocsURL string            `json:"docs_url"`
}

// SensorConfigObservedItem is one typed value the check reported.
type SensorConfigObservedItem struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

func toSensorConfigReportResponse(v *sensorapp.ConfigReportView) SensorConfigReportResponse {
	out := SensorConfigReportResponse{
		State: v.State, Stale: v.Stale, Health: v.Health,
		ObservedAt: rfc3339Ptr(v.ObservedAt), ReceivedAt: rfc3339Ptr(v.ReceivedAt),
		Truncated: v.Truncated, RuntimeKind: v.RuntimeKind, DerivedNote: v.DerivedNote,
		Counts: v.Counts, Checks: make([]SensorConfigCheckResponse, 0, len(v.Checks)),
		Settings: v.Settings,
	}
	if out.Settings == nil {
		out.Settings = []sensor.ConfigSetting{}
	}
	for _, c := range v.Checks {
		out.Checks = append(out.Checks, toSensorConfigCheckResponse(c))
	}
	return out
}

func toSensorConfigCheckResponse(c sensorapp.ConfigCheckView) SensorConfigCheckResponse {
	ch, ex := c.Check, c.Explanation
	keys := make([]string, 0, len(ch.Params))
	for k := range ch.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	observed := make([]SensorConfigObservedItem, 0, len(keys))
	for _, k := range keys {
		observed = append(observed, SensorConfigObservedItem{Label: k, Value: ch.Params[k].Text()})
	}
	fix := ex.Fix
	if fix == nil {
		fix = map[string]string{}
	}
	return SensorConfigCheckResponse{
		ID: ch.ID, Group: ex.Group, Status: ch.Status, Severity: ch.Severity, Code: ch.Code,
		Known: ex.Known, Title: ex.Title, Why: ex.Why, Observed: observed,
		Summary: ch.Summary, Excerpt: ch.Excerpt,
		Keys: nonNilStrings(ch.Keys), Blocks: nonNilStrings(ch.Blocks),
		Fix: fix, DocsURL: ex.DocsURL,
	}
}

// ConfigReport handles GET /api/v1/sensors/{id}/config-report
// @Summary      Sensor setup checklist
// @Description  The sensor's config report (research/26): the preflight checks it ran on itself, each explained from the platform catalog with fix snippets per install type, and the settings it declares (set or not and where from; never a value). For a sensor that sends no report the checks are derived from its heartbeat (state derived); none before it first connected. 404 for a sensor of another organization.
// @Tags         Sensors
// @Produce      json
// @Param        id   path      string  true  "Sensor ID"
// @Success      200  {object}  SensorConfigReportResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/config-report [get]
func (h *SensorHandler) ConfigReport(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	if sensorID == "" {
		apierror.BadRequest("Sensor ID is required").WriteJSON(w)
		return
	}
	v, err := h.service.ConfigReport(r.Context(), middleware.GetTenantID(r.Context()), sensorID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toSensorConfigReportResponse(v))
}
