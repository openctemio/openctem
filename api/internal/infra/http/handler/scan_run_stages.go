package handler

// A run's stage lanes (research/27 §5.8, §9.3 run drawer): how each stage
// was planned. Counts only: no target name is listed here.

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/command"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// RunStageResponse is how one stage of a run was planned.
type RunStageResponse struct {
	// StageKey is the step key of the stage in the run's template.
	StageKey string `json:"stage_key"`
	// Stage is the catalog capability ("" when the catalog cannot place
	// the step).
	Stage string `json:"stage"`
	Tool  string `json:"tool"`
	Tier  string `json:"tier" enums:"T0,T1,T2"`
	// Chained: the stage took targets an earlier stage produced.
	Chained bool `json:"chained"`
	// Inputs is how many targets were considered (seeds plus outputs of the
	// types the stage takes); Planned how many were handed to the stage.
	Inputs  int `json:"inputs"`
	Planned int `json:"planned"`
	// Skipped counts the targets left out, by reason: excluded,
	// unconfirmed, refused, other_zone, hop_limit, over_cap, duplicate,
	// invalid, incompatible_type.
	Skipped map[string]int `json:"skipped"`
	// MaxHop is the furthest discovery hop from a seed among planned
	// targets.
	MaxHop    int    `json:"max_hop"`
	PlannedAt string `json:"planned_at"`
	// Chunks counts the stage's commands by state; Sensors is how they are
	// spread over the sensors that took them (research/49 §3.12). Both are
	// empty before the stage is queued.
	Chunks  RunStageChunks   `json:"chunks"`
	Sensors []RunStageSensor `json:"sensors"`
}

// RunStageChunks counts a stage's commands (chunks) by state.
type RunStageChunks struct {
	Total     int `json:"total"`
	Queued    int `json:"queued"`
	Running   int `json:"running"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

// RunStageSensor is one sensor's share of a stage's chunks. A platform job
// is listed as platform without naming the platform sensor.
type RunStageSensor struct {
	SensorID   string `json:"sensor_id,omitempty"`
	SensorName string `json:"sensor_name,omitempty"`
	Platform   bool   `json:"platform,omitempty"`
	RunStageChunks
}

// RunStageListResponse lists a run's stage plans in planning order.
type RunStageListResponse struct {
	Data []RunStageResponse `json:"data"`
}

// ListRunStages handles GET /api/v1/scan-runs/{id}/stages
// @Summary      List a run's stage plans
// @Description  How each stage of the run was planned: inputs, planned targets and skipped targets by reason (counts only), and how its chunks are spread over sensors. A run of another organization is not found.
// @Tags         Scan workflows
// @Produce      json
// @Param        id   path      string  true  "Run ID"
// @Success      200  {object}  RunStageListResponse
// @Security     BearerAuth
// @Router       /scan-runs/{id}/stages [get]
func (h *ScanWorkflowHandler) ListRunStages(w http.ResponseWriter, r *http.Request) {
	tenantID, runID := middleware.GetTenantID(r.Context()), chi.URLParam(r, "id")
	plans, err := h.service.ListRunStages(r.Context(), tenantID, runID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	shares, err := h.service.RunStepShares(r.Context(), tenantID, runID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(withSensorShares(toRunStageList(plans), shares))
}

// withSensorShares adds each stage's chunk counts and per-sensor shares.
func withSensorShares(out RunStageListResponse, shares []command.StepSensorShare) RunStageListResponse {
	byStep := map[string][]command.StepSensorShare{}
	for _, sh := range shares {
		byStep[sh.StepKey] = append(byStep[sh.StepKey], sh)
	}
	for i := range out.Data {
		d := &out.Data[i]
		for _, sh := range byStep[d.StageKey] {
			c := RunStageChunks{Total: sh.Total, Queued: sh.Queued, Running: sh.Running, Completed: sh.Completed, Failed: sh.Failed}
			d.Chunks.Total += c.Total
			d.Chunks.Queued += c.Queued
			d.Chunks.Running += c.Running
			d.Chunks.Completed += c.Completed
			d.Chunks.Failed += c.Failed
			if sh.SensorID == nil && !sh.Platform {
				continue // waiting for a sensor: counted as queued only
			}
			rs := RunStageSensor{SensorName: sh.SensorName, Platform: sh.Platform, RunStageChunks: c}
			if sh.SensorID != nil {
				rs.SensorID = sh.SensorID.String()
			}
			d.Sensors = append(d.Sensors, rs)
		}
	}
	return out
}

func toRunStageList(plans []scanrun.StagePlan) RunStageListResponse {
	out := RunStageListResponse{Data: make([]RunStageResponse, 0, len(plans))}
	for _, p := range plans {
		skipped := p.Skipped
		if skipped == nil {
			skipped = map[string]int{}
		}
		out.Data = append(out.Data, RunStageResponse{
			StageKey: p.StageKey, Stage: p.Stage, Tool: p.Tool, Tier: stage.Tier(p.Tier).String(),
			Chained: p.Chained, Inputs: p.Inputs, Planned: p.Planned, Skipped: skipped,
			MaxHop: p.MaxHop, PlannedAt: p.PlannedAt.UTC().Format(time.RFC3339),
			Sensors: []RunStageSensor{},
		})
	}
	return out
}
