package handler

// A run's stage lanes (research/27 §5.8, §9.3 run drawer): how each stage
// was planned. Counts only: no target name is listed here.

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	pipelinedom "github.com/openctemio/openctem/api/pkg/domain/pipeline"
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
}

// RunStageListResponse lists a run's stage plans in planning order.
type RunStageListResponse struct {
	Data []RunStageResponse `json:"data"`
}

// ListRunStages handles GET /api/v1/pipeline-runs/{id}/stages
// @Summary      List a run's stage plans
// @Description  How each stage of the run was planned: inputs, planned targets and skipped targets by reason (counts only). A run of another organization is not found.
// @Tags         Pipelines
// @Produce      json
// @Param        id   path      string  true  "Run ID"
// @Success      200  {object}  RunStageListResponse
// @Security     BearerAuth
// @Router       /pipeline-runs/{id}/stages [get]
func (h *PipelineHandler) ListRunStages(w http.ResponseWriter, r *http.Request) {
	plans, err := h.service.ListRunStages(r.Context(), middleware.GetTenantID(r.Context()), chi.URLParam(r, "id"))
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toRunStageList(plans))
}

func toRunStageList(plans []pipelinedom.StagePlan) RunStageListResponse {
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
		})
	}
	return out
}
