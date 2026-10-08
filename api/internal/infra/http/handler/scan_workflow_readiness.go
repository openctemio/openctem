package handler

import (
	"context"
	"net/http"
	"strings"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// WorkflowReadinessFunc computes the readiness of workflows (steps loaded)
// for a tenant in one pass (scan.Service.WorkflowReadiness).
type WorkflowReadinessFunc func(ctx context.Context, tenantID shared.ID, workflows []*scanworkflow.Workflow) (map[shared.ID]*scanapp.WorkflowReadiness, error)

// SetReadiness enables ?include=readiness on the workflow list and read.
func (h *ScanWorkflowHandler) SetReadiness(f WorkflowReadinessFunc) { h.readiness = f }

// WorkflowReadinessResponse says whether the workflow can run for the caller's
// organization now (ready, waiting, ci_only, blocked) and why, per step.
type WorkflowReadinessResponse struct {
	State string                  `json:"state"`
	Steps []StepReadinessResponse `json:"steps"`
}

// StepReadinessResponse is one step's readiness.
type StepReadinessResponse struct {
	StepKey    string `json:"step_key"`
	Name       string `json:"name"`
	Capability string `json:"capability,omitempty"`
	State      string `json:"state"`
	Reason     string `json:"reason,omitempty"`
	Fix        string `json:"fix,omitempty"`
}

// wantsReadiness reports whether the request asked for readiness.
func wantsReadiness(r *http.Request) bool {
	for _, part := range strings.Split(r.URL.Query().Get("include"), ",") {
		if strings.TrimSpace(part) == "readiness" {
			return true
		}
	}
	return false
}

// attachReadiness fills in the readiness of the listed workflows. A failure
// leaves it out (the list still answers) and is logged.
func (h *ScanWorkflowHandler) attachReadiness(ctx context.Context, tenantID string, workflows []*scanworkflow.Workflow, out []*TemplateResponse) {
	if h.readiness == nil || len(workflows) == 0 {
		return
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return
	}
	m, err := h.readiness(ctx, tid, workflows)
	if err != nil {
		h.logger.Warn("workflow readiness unavailable", "error", err)
		return
	}
	for i, w := range workflows {
		r := m[w.ID]
		if r == nil || i >= len(out) {
			continue
		}
		resp := &WorkflowReadinessResponse{State: r.State, Steps: make([]StepReadinessResponse, 0, len(r.Steps))}
		for _, s := range r.Steps {
			resp.Steps = append(resp.Steps, StepReadinessResponse(s))
		}
		out[i].Readiness = resp
	}
}
