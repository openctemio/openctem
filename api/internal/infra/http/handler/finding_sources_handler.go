package handler

// GET /api/v1/findings/{id}/sources: what each source reported for a finding
// (docs/architecture/finding-source-records.md).

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/safetext"
)

// FindingSourceRecordResponse is what one source reported for a finding.
type FindingSourceRecordResponse struct {
	// Channel: scan, task, sensor, upload, ci, connector, platform, unknown (backfilled only).
	Channel string `json:"channel"`
	// Sensor is the organization's sensor; omitted without sensors:read and
	// for a shared platform sensor (sender is then "platform").
	Sensor *FindingSightingSensor `json:"sensor,omitempty"`
	// Sender is the CI repository or connector source name.
	Sender      string `json:"sender,omitempty"`
	Tool        string `json:"tool,omitempty"`
	ToolVersion string `json:"tool_version,omitempty"`
	// Primary: this source's tool reported the finding first; the finding's
	// own fields show its values (another source only fills empty ones).
	Primary     bool      `json:"primary"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	// Truncated: a value of this source was cut to its size limit.
	Truncated bool `json:"truncated"`
	// Backfilled: derived from the finding as it was before per-source
	// records existed; its values may mix earlier sources.
	Backfilled     bool                            `json:"backfilled"`
	Title          string                          `json:"title,omitempty"`
	Description    string                          `json:"description,omitempty"`
	Snippet        string                          `json:"snippet,omitempty"`
	Recommendation string                          `json:"recommendation,omitempty"`
	Message        string                          `json:"message,omitempty"`
	Severity       string                          `json:"severity,omitempty"`
	CVSSScore      *float64                        `json:"cvss_score,omitempty"`
	CVSSVector     string                          `json:"cvss_vector,omitempty"`
	Native         *vulnerability.InteropNative    `json:"native,omitempty"`
	Scores         []vulnerability.InteropScore    `json:"scores,omitempty"`
	VulnIDs        []vulnerability.InteropVulnID   `json:"vulnerability_ids,omitempty"`
	Lifecycle      *vulnerability.InteropLifecycle `json:"lifecycle,omitempty"`
	Solution       *vulnerability.InteropSolution  `json:"solution,omitempty"`
	SourceExtra    map[string]string               `json:"source_extra,omitempty"`
	LocationKey    string                          `json:"location_key,omitempty"`
}

// FindingSourceDifference is one field the sources disagree on, with one
// value per entry of data, in the same order ("" where a source does not
// carry it). Field: severity, vendor_severity, cvss_score, native_id,
// family, status, solution_type, title.
type FindingSourceDifference struct {
	Field  string   `json:"field"`
	Values []string `json:"values"`
}

// FindingSourcesResponse lists what each source reported for one finding.
type FindingSourcesResponse struct {
	Data        []FindingSourceRecordResponse `json:"data"`
	Differences []FindingSourceDifference     `json:"differences"`
}

// GetFindingSources handles GET /api/v1/findings/{id}/sources.
//
// @Summary      List what each source reported for a finding
// @Description  One entry per source (channel, the organization's sensor, CI repository or connector, tool) with that source's latest title, text, severity, native identity, scores, vulnerability ids and unmapped fields, the primary source first; and the fields the sources disagree on, side by side. The sensor is shown with sensors:read only. Out of the caller's data scope or another organization's: 404.
// @Tags         Findings
// @Produce      json
// @Param        id   path  string  true  "Finding id"
// @Success      200  {object}  FindingSourcesResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/sources [get]
func (h *VulnerabilityHandler) GetFindingSources(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID := middleware.MustGetTenantID(ctx)
	// Tenant, data scope and pentest membership, as the finding detail.
	f, err := h.service.GetFindingWithScope(ctx, tenantID, r.PathValue("id"), middleware.GetUserID(ctx), middleware.IsAdmin(ctx))
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}
	recs, err := h.service.GetFindingSourceRecords(ctx, f)
	if err != nil {
		h.logger.Error("finding sources: list", "finding_id", f.ID().String(), "error", err)
		apierror.InternalServerError("could not read what each source reported").WriteJSON(w)
		return
	}
	resp := toFindingSourcesResponse(recs, middleware.HasPermission(ctx, string(permission.SensorsRead)))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// toFindingSourcesResponse maps the records, cleaned like the finding
// detail's source data: secrets redacted in text, sensor-local paths
// reduced, the sensor only with sensors:read.
func toFindingSourcesResponse(recs []vulnerability.SourceRecord, showSensor bool) FindingSourcesResponse {
	out := FindingSourcesResponse{Data: make([]FindingSourceRecordResponse, 0, len(recs)),
		Differences: []FindingSourceDifference{}}
	for _, rec := range recs {
		v := rec.Values
		item := FindingSourceRecordResponse{
			Channel: rec.Channel, Sender: rec.Sender, Tool: rec.Tool, ToolVersion: v.ToolVersion, Primary: rec.Primary,
			FirstSeenAt: rec.FirstSeenAt, LastSeenAt: rec.LastSeenAt, Truncated: v.Truncated, Backfilled: rec.Backfilled,
			Title: safetext.RedactSecrets(v.Title), Description: safetext.RedactSecrets(v.Description),
			Snippet: safetext.RedactSecrets(v.Snippet), Recommendation: safetext.RedactSecrets(v.Recommendation),
			Message: safetext.RedactSecrets(v.Message), Severity: v.Severity, CVSSScore: v.CVSSScore,
			CVSSVector: v.CVSSVector, Native: v.Interop.Native, Scores: v.Interop.Scores,
			VulnIDs: v.Interop.VulnerabilityIDs, Lifecycle: v.Interop.Lifecycle, Solution: v.Interop.Solution,
			LocationKey: vulnerability.DisplayPath(v.Interop.LocationKey),
		}
		if len(v.Interop.SourceExtra) > 0 {
			item.SourceExtra = make(map[string]string, len(v.Interop.SourceExtra))
			for k, val := range v.Interop.SourceExtra {
				item.SourceExtra[k] = safetext.RedactSecrets(vulnerability.SourceExtraValue(k, val))
			}
		}
		if showSensor && rec.SensorID != nil {
			item.Sensor = &FindingSightingSensor{ID: rec.SensorID.String(), Name: rec.SensorName}
		}
		out.Data = append(out.Data, item)
	}
	for _, d := range vulnerability.SourceRecordDifferences(recs) {
		out.Differences = append(out.Differences, FindingSourceDifference{Field: d.Field, Values: d.Values})
	}
	return out
}
