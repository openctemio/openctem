package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	sensorapp "github.com/openctemio/openctem/api/internal/app/sensor"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
)

// SensorActivityItemResponse is one entry of a sensor's activity timeline.
// summary is a plain-English fallback; clients build their own wording from
// type and details. action, actor and result are set on audit items only.
type SensorActivityItemResponse struct {
	ID       string `json:"id"`
	At       string `json:"at"`
	Category string `json:"category" enums:"people,status,updates,jobs"`
	// Type: online, offline, restarted, heartbeat_recovered (status); version_changed,
	// sdk_version_changed, protocol_changed, tools_changed,
	// capacity_changed, content_updated, content_refresh_failed,
	// manifest_changed (updates; details.diff, RFC-033 §6.12);
	// job_claimed, job_completed, job_failed, job_canceled, job_expired
	// (jobs); audit (people).
	Type        string         `json:"type"`
	Source      string         `json:"source" enums:"sensor,audit,job"`
	Summary     string         `json:"summary"`
	Details     map[string]any `json:"details"`
	RepeatCount int            `json:"repeat_count"`
	LastAt      *string        `json:"last_at,omitempty"`
	Action      string         `json:"action,omitempty"`
	Actor       string         `json:"actor,omitempty"`
	Result      string         `json:"result,omitempty"`
}

// SensorActivityResponse is one page of a sensor's activity timeline.
type SensorActivityResponse struct {
	Items []SensorActivityItemResponse `json:"items"`
	// NextCursor fetches the next (older) page; "" when there is none.
	NextCursor string `json:"next_cursor"`
	// AuditIncluded is false when the caller cannot read the audit log:
	// administrator actions (people) are then left out.
	AuditIncluded bool `json:"audit_included"`
}

// Activity handles GET /api/v1/sensors/{id}/activity
// @Summary      Sensor activity timeline
// @Description  What happened to a sensor, newest first: status changes (online, offline, restarts), updates (version, SDK, protocol, tools, capacity, content), jobs it claimed and finished, and administrator actions from the audit log. Audit items are included only when the caller holds audit:read.
// @Tags         Sensors
// @Produce      json
// @Param        id      path      string  true   "Sensor ID"
// @Param        types   query     string  false  "Categories, comma-separated: people, status, updates, jobs (default all)"
// @Param        cursor  query     string  false  "next_cursor of the previous page"
// @Param        limit   query     int     false  "Page size (1-100)"  default(30)
// @Success      200  {object}  SensorActivityResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/activity [get]
func (h *SensorHandler) Activity(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	if sensorID == "" {
		apierror.BadRequest("Sensor ID is required").WriteJSON(w)
		return
	}
	q := r.URL.Query()
	includeAudit := middleware.HasPermission(r.Context(), string(permission.AuditRead))
	limit, ok := listLimit(w, r, sensorapp.DefaultActivityLimit, sensorapp.MaxActivityLimit)
	if !ok {
		return
	}
	page, err := h.service.ListActivity(r.Context(), sensorapp.ActivityInput{
		TenantID:     middleware.GetTenantID(r.Context()),
		SensorID:     sensorID,
		Categories:   parseQueryArray(q.Get("types")),
		IncludeAudit: includeAudit,
		Cursor:       q.Get("cursor"),
		Limit:        limit,
	})
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := SensorActivityResponse{
		Items:         make([]SensorActivityItemResponse, 0, len(page.Items)),
		NextCursor:    page.NextCursor,
		AuditIncluded: includeAudit,
	}
	for _, it := range page.Items {
		item := SensorActivityItemResponse{
			ID: it.Key, At: it.At.UTC().Format(time.RFC3339Nano), Category: string(it.Category),
			Type: it.Type, Source: it.Source, Summary: it.Summary, Details: it.Details,
			RepeatCount: max(it.RepeatCount, 1), LastAt: rfc3339Ptr(it.LastAt),
			Action: it.Action, Actor: it.Actor, Result: it.Result,
		}
		if item.Details == nil {
			item.Details = map[string]any{}
		}
		resp.Items = append(resp.Items, item)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// SensorHeartbeatHistoryResponse is a sensor's recent heartbeat history:
// one bucket per bucket_seconds, oldest first, only buckets that had a
// heartbeat (a missing bucket is a stretch without one).
type SensorHeartbeatHistoryResponse struct {
	BucketSeconds int                             `json:"bucket_seconds"`
	Hours         int                             `json:"hours"`
	Buckets       []SensorHeartbeatBucketResponse `json:"buckets"`
}

// SensorHeartbeatBucketResponse is one bucket of the heartbeat history.
type SensorHeartbeatBucketResponse struct {
	// At is the bucket's start (RFC 3339, UTC).
	At string `json:"at"`
	// Beats is the heartbeats received; avg/max gap are the times between
	// consecutive heartbeats in it, interval_s the interval the sensor
	// followed; max_lag_ms and failures come from its control report.
	Beats           int     `json:"beats"`
	AvgGapSeconds   float64 `json:"avg_gap_s"`
	MaxGapSeconds   float64 `json:"max_gap_s"`
	IntervalSeconds float64 `json:"interval_s"`
	MaxLagMillis    int64   `json:"max_lag_ms"`
	Failures        int64   `json:"failures"`
}

// HeartbeatHistory handles GET /api/v1/sensors/{id}/heartbeat-history
// @Summary      Sensor heartbeat history
// @Description  How the sensor's heartbeats arrived over the last hours (at most 24), in 15-minute buckets: heartbeats received, average and largest gap, the interval it followed, the largest timer lag and the heartbeats it reported lost. Kept 48 hours. Feeds the Control channel sparkline.
// @Tags         Sensors
// @Produce      json
// @Param        id     path   string  true   "Sensor ID"
// @Param        hours  query  int     false  "Window in hours (1-24)"  default(24)
// @Success      200  {object}  SensorHeartbeatHistoryResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /sensors/{id}/heartbeat-history [get]
func (h *SensorHandler) HeartbeatHistory(w http.ResponseWriter, r *http.Request) {
	sensorID := chi.URLParam(r, "id")
	if sensorID == "" {
		apierror.BadRequest("Sensor ID is required").WriteJSON(w)
		return
	}
	maxHours := int(sensordom.MaxHeartbeatHistoryWindow / time.Hour)
	hours := parseQueryIntBounded(r.URL.Query().Get("hours"), maxHours, 1, maxHours)
	buckets, err := h.service.HeartbeatHistory(r.Context(), middleware.GetTenantID(r.Context()), sensorID, time.Duration(hours)*time.Hour)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	resp := SensorHeartbeatHistoryResponse{
		BucketSeconds: int(sensordom.HeartbeatHistoryBucket / time.Second),
		Hours:         hours,
		Buckets:       make([]SensorHeartbeatBucketResponse, 0, len(buckets)),
	}
	for _, b := range buckets {
		resp.Buckets = append(resp.Buckets, SensorHeartbeatBucketResponse{
			At: b.Start.UTC().Format(time.RFC3339), Beats: b.Beats,
			AvgGapSeconds: b.AvgGapSeconds, MaxGapSeconds: b.MaxGapSeconds, IntervalSeconds: b.IntervalSeconds,
			MaxLagMillis: b.MaxLagMillis, Failures: b.Failures,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
