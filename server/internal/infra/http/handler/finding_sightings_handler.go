package handler

// GET /api/v1/findings/{id}/sightings: who reported a finding
// (docs/architecture/finding-sightings.md).

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/server/internal/infra/http/middleware"
	"github.com/openctemio/openctem/server/pkg/apierror"
	"github.com/openctemio/openctem/server/pkg/domain/ingestreceipt"
	"github.com/openctemio/openctem/server/pkg/domain/permission"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// FindingSightingSensor is the tenant's sensor of a sighting.
type FindingSightingSensor struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// FindingSightingScan is the scan definition of a sighting.
type FindingSightingScan struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// FindingSightingResponse is one source that reported a finding.
type FindingSightingResponse struct {
	// Channel: scan, task, sensor, upload, ci, connector, platform, unknown (backfilled only).
	Channel string `json:"channel"`
	// Sensor is the tenant's own sensor; omitted without sensors:read and
	// for a shared platform sensor (sender is then "platform").
	Sensor *FindingSightingSensor `json:"sensor,omitempty"`
	// Sender is the CI repository or connector source name.
	Sender      string               `json:"sender,omitempty"`
	Tool        string               `json:"tool,omitempty"`
	ToolVersion string               `json:"tool_version,omitempty"`
	Scan        *FindingSightingScan `json:"scan,omitempty"`
	FirstSeenAt time.Time            `json:"first_seen_at"`
	LastSeenAt  time.Time            `json:"last_seen_at"`
	// SeenCount is the receipts (runs, uploads, reports) that reported it from this source.
	SeenCount int `json:"seen_count"`
	// ReceiptID is the last receipt, while it is kept (run receipts: 90 days).
	ReceiptID  string `json:"receipt_id,omitempty"`
	RunID      string `json:"run_id,omitempty"`
	StepRunID  string `json:"step_run_id,omitempty"`
	CommandID  string `json:"command_id,omitempty"`
	Backfilled bool   `json:"backfilled"`
}

// FindingSightingsResponse lists the sources of one finding.
type FindingSightingsResponse struct {
	Data []FindingSightingResponse `json:"data"`
}

// FindingSightings handles GET /api/v1/findings/{id}/sightings.
//
// @Summary      List who reported a finding
// @Description  One entry per source (channel, the organization's sensor, CI repository or connector, tool, scan) with first and last seen and how many runs, uploads or reports saw it; the last run, step and receipt link to where it was seen. The sensor is shown with sensors:read only, a scan's name with scans:read only. Out of the caller's data scope: 404.
// @Tags         Findings
// @Produce      json
// @Param        id   path  string  true  "Finding id"
// @Success      200  {object}  FindingSightingsResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/sightings [get]
func (h *IngestReceiptHandler) FindingSightings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tid, err := shared.IDFromString(middleware.MustGetTenantID(ctx))
	if err != nil {
		apierror.BadRequest("invalid tenant").WriteJSON(w)
		return
	}
	fid, err := shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Finding").WriteJSON(w)
		return
	}
	if err := h.scope.AssertFinding(ctx, tid, fid); err != nil {
		apierror.NotFound("Finding").WriteJSON(w)
		return
	}
	reader, ok := h.repo.(ingestreceipt.SightingReader)
	if !ok {
		writeJSON(w, http.StatusOK, FindingSightingsResponse{Data: []FindingSightingResponse{}})
		return
	}
	rows, err := reader.FindingSightings(ctx, tid, fid)
	if errors.Is(err, shared.ErrNotFound) {
		apierror.NotFound("Finding").WriteJSON(w)
		return
	}
	if err != nil {
		h.logger.Error("sightings: finding sightings", "error", err)
		apierror.InternalServerError("could not read who reported the finding").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, FindingSightingsResponse{Data: toSightingResponses(rows,
		middleware.HasPermission(ctx, string(permission.SensorsRead)),
		middleware.HasPermission(ctx, string(permission.ScansRead)))})
}

// toSightingResponses maps sightings to the response, leaving out the
// sensor without sensors:read and the scan name without scans:read.
func toSightingResponses(rows []ingestreceipt.Sighting, sensors, scans bool) []FindingSightingResponse {
	out := make([]FindingSightingResponse, 0, len(rows))
	for _, s := range rows {
		item := FindingSightingResponse{Channel: string(s.Channel), Sender: s.Sender, Tool: s.Tool,
			ToolVersion: s.ToolVersion, FirstSeenAt: s.FirstSeenAt, LastSeenAt: s.LastSeenAt, SeenCount: s.SeenCount,
			RunID: sightingID(s.LastRunID), StepRunID: sightingID(s.LastStepRunID), CommandID: sightingID(s.LastCommandID),
			Backfilled: s.Backfilled}
		if sensors && s.SensorID != nil {
			item.Sensor = &FindingSightingSensor{ID: s.SensorID.String(), Name: s.SensorName}
		}
		if s.ScanID != nil {
			item.Scan = &FindingSightingScan{ID: s.ScanID.String()}
			if scans {
				item.Scan.Name = s.ScanName
			}
		}
		if s.ReceiptKept {
			item.ReceiptID = sightingID(s.LastReceiptID)
		}
		out = append(out, item)
	}
	return out
}

func sightingID(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}
