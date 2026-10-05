package handler

// The scan stage catalog over HTTP (research/27 §6.1, RFC-046 stage
// catalog). Static platform data: no tenant data is read or returned.

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// ScanStageImplementationResponse is one tool that runs a stage.
type ScanStageImplementationResponse struct {
	Tool    string `json:"tool"`
	Default bool   `json:"default"`
}

// ScanStageResponse is one catalog stage.
type ScanStageResponse struct {
	Key             string                            `json:"key"`
	Name            string                            `json:"name"`
	Description     string                            `json:"description"`
	Inputs          []string                          `json:"inputs"`
	Outputs         []string                          `json:"outputs"`
	Relations       []string                          `json:"relations"`
	Findings        bool                              `json:"findings"`
	Tier            string                            `json:"tier" enums:"T0,T1,T2"`
	Implementations []ScanStageImplementationResponse `json:"implementations"`
	MaxFanout       int                               `json:"max_fanout"`
}

// ScanStageListResponse is the stage catalog.
type ScanStageListResponse struct {
	Stages []ScanStageResponse `json:"stages"`
	// MaxHops is how many discovery hops a derived target may be from the
	// run's seeds.
	MaxHops int `json:"max_hops"`
}

// ListStages handles GET /api/v1/scans/stages
// @Summary      List scan stages
// @Description  The scan stage catalog: each capability with the asset types it consumes and produces, its intrusiveness tier and the tools that implement it.
// @Tags         Scans
// @Produce      json
// @Success      200  {object}  ScanStageListResponse
// @Security     BearerAuth
// @Router       /scans/stages [get]
func (h *ScanHandler) ListStages(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(scanStageList())
}

func scanStageList() ScanStageListResponse {
	all := stage.All()
	out := ScanStageListResponse{Stages: make([]ScanStageResponse, 0, len(all)), MaxHops: stage.MaxHops}
	for _, s := range all {
		r := ScanStageResponse{
			Key: string(s.Key), Name: s.Name, Description: s.Description,
			Inputs: make([]string, 0, len(s.Inputs)), Outputs: make([]string, 0, len(s.Outputs)),
			Relations: append([]string{}, s.Relations...), Findings: s.Findings,
			Tier: s.Tier.String(), MaxFanout: s.MaxFanout,
			Implementations: make([]ScanStageImplementationResponse, 0, len(s.Implementations)),
		}
		for _, t := range s.Inputs {
			r.Inputs = append(r.Inputs, string(t))
		}
		for _, t := range s.Outputs {
			r.Outputs = append(r.Outputs, string(t))
		}
		for _, i := range s.Implementations {
			r.Implementations = append(r.Implementations, ScanStageImplementationResponse{Tool: i.Tool, Default: i.Default})
		}
		out.Stages = append(out.Stages, r)
	}
	return out
}
