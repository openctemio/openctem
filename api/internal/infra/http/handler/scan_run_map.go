package handler

// The live run map (research/62 run page; owner request 2026-10-08): a run
// drawn on the workflow version it executes, each step with its state,
// chunks, findings and outputs, each edge with what flowed along it.
// The map is counts only (no target or asset is named); a step's outputs
// are listed by ListRunStepOutputs. Both cover only the assets the caller
// may see.

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	scanrundom "github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"

	scanrunapp "github.com/openctemio/openctem/api/internal/app/scanrun"
)

// Run map node states (RunMapNode.State).
const (
	mapStatePending   = "pending"   // not started: waits for its dependencies
	mapStateWaiting   = "waiting"   // queued, no chunk taken by a sensor yet
	mapStateRunning   = "running"   // at least one chunk taken
	mapStateSucceeded = "succeeded" // every chunk completed
	mapStatePartial   = "partial"   // finished with some chunks failed
	mapStateFailed    = "failed"
	mapStateSkipped   = "skipped"
	mapStateCanceled  = "canceled"
)

// RunMapChunks counts a step's chunks (commands) by state.
type RunMapChunks struct {
	Total     int `json:"total"`
	Queued    int `json:"queued"`
	Running   int `json:"running"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

// RunMapOutputs counts what a step produced, by asset type, in the caller's
// data scope. Previous, Added and Gone compare it with the previous run of
// the scan (absent when there is none): what the previous run's same step
// produced, what is new this run and what this run no longer produced.
type RunMapOutputs struct {
	Total    int            `json:"total"`
	ByType   map[string]int `json:"by_type"`
	Previous *int           `json:"previous,omitempty"`
	Added    *int           `json:"added,omitempty"`
	Gone     *int           `json:"gone,omitempty"`
}

// RunMapNode is one step of the run on the map.
type RunMapNode struct {
	StepKey      string   `json:"step_key"`
	Name         string   `json:"name,omitempty"`
	Tool         string   `json:"tool,omitempty"`
	Capabilities []string `json:"capabilities,omitempty"`
	DependsOn    []string `json:"depends_on"`
	// State: pending, waiting, running, succeeded, partial, failed,
	// skipped or canceled.
	State string `json:"state"`
	// Reason says why a waiting, skipped or failed step is so: for a
	// waiting step "waiting_for_sensor"; otherwise the step's error code.
	Reason       string `json:"reason,omitempty"`
	ErrorClass   string `json:"error_class,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
	StartedAt    string `json:"started_at,omitempty"`
	CompletedAt  string `json:"completed_at,omitempty"`
	// TimeoutSeconds is the step's timeout in the run's workflow version.
	TimeoutSeconds int           `json:"timeout_seconds,omitempty"`
	Findings       int           `json:"findings"`
	Chunks         RunMapChunks  `json:"chunks"`
	Outputs        RunMapOutputs `json:"outputs"`
	// Inputs and Planned: how many targets the stage considered and was
	// handed (absent before the stage is planned).
	Inputs  *int `json:"inputs,omitempty"`
	Planned *int `json:"planned,omitempty"`
}

// RunMapEdge is one dependency of the map: Count is what the upstream step
// produced (in the caller's data scope), the data available to flow on.
type RunMapEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Count int    `json:"count"`
}

// RunMapResponse is a run's live map.
type RunMapResponse struct {
	RunID  string `json:"run_id"`
	Status string `json:"status"`
	// ScanWorkflowVersion is the workflow version drawn (0: the run's step
	// runs, for a run without a saved version).
	ScanWorkflowVersion int `json:"scan_workflow_version,omitempty"`
	// PreviousRunID is the previous finished run of the same scan the
	// outputs are compared with (absent: none).
	PreviousRunID string       `json:"previous_run_id,omitempty"`
	Nodes         []RunMapNode `json:"nodes"`
	Edges         []RunMapEdge `json:"edges"`
}

// GetRunMap handles GET /api/v1/scan-runs/{id}/map
// @Summary      A run's live map
// @Description  The run drawn on the workflow version it executes: each step's state (pending, waiting, running, succeeded, partial, failed, skipped, canceled) and reason, its chunks by state, findings, planned inputs and outputs by asset type, and each dependency with the upstream output count. Output counts cover only assets in the caller's data scope; no target or asset is named. A run of another organization, or a run about a finding outside the caller's scope, is not found.
// @Tags         Scan workflows
// @Produce      json
// @Param        id   path      string  true  "Run ID"
// @Success      200  {object}  RunMapResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-runs/{id}/map [get]
func (h *ScanWorkflowHandler) GetRunMap(w http.ResponseWriter, r *http.Request) {
	if !h.guardRun(w, r) {
		return
	}
	tenant := middleware.GetTenantID(r.Context())
	tenantID, err := shared.IDFromString(tenant)
	if err != nil {
		apierror.NotFound("Run").WriteJSON(w)
		return
	}
	var scope *shared.DataScope
	if h.findingScope != nil {
		if scope, err = h.findingScope.Resolve(r.Context(), tenantID); err != nil {
			h.logger.Error("failed to resolve data scope", "error", err)
			apierror.InternalServerError("failed to read the run map").WriteJSON(w)
			return
		}
	}
	m, err := h.service.GetRunMap(r.Context(), tenant, chi.URLParam(r, "id"), scope)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toRunMapResponse(m))
}

// toRunMapResponse draws the map: the workflow version's steps (or the step
// runs, for a run without one) with their step run, chunks, plan and outputs.
func toRunMapResponse(m *scanrunapp.RunMap) RunMapResponse {
	run := m.Run
	resp := RunMapResponse{
		RunID: run.ID.String(), Status: string(run.Status),
		ScanWorkflowVersion: run.ScanWorkflowVersion,
		Nodes:               []RunMapNode{}, Edges: []RunMapEdge{},
	}

	chunks := map[string]RunMapChunks{}
	platform := map[string]bool{}
	for _, sh := range m.Shares {
		platform[sh.StepKey] = platform[sh.StepKey] || sh.Platform
		c := chunks[sh.StepKey]
		c.Total += sh.Total
		c.Queued += sh.Queued
		c.Running += sh.Running
		c.Completed += sh.Completed
		c.Failed += sh.Failed
		chunks[sh.StepKey] = c
	}
	plans := map[string]scanrundom.StagePlan{}
	for _, p := range m.Plans {
		plans[p.StageKey] = p
	}
	stepKeyOf := map[shared.ID]string{}
	stepRuns := map[string]*scanrundom.StepRun{}
	for _, sr := range run.StepRuns {
		stepKeyOf[sr.ID] = sr.StepKey
		stepRuns[sr.StepKey] = sr
	}
	outputs := map[string]RunMapOutputs{}
	for _, o := range m.Outputs {
		key, ok := stepKeyOf[o.StepRunID]
		if !ok {
			continue
		}
		out := outputs[key]
		if out.ByType == nil {
			out.ByType = map[string]int{}
		}
		out.ByType[o.AssetType] += o.Count
		out.Total += o.Count
		outputs[key] = out
	}
	if !m.PreviousRunID.IsZero() {
		resp.PreviousRunID = m.PreviousRunID.String()
		deltas := map[string]scanrundom.StepOutputDelta{}
		for _, d := range m.Deltas {
			deltas[d.StepKey] = d
		}
		// Every step compares, a step without outputs in either run as 0/0/0.
		for _, sr := range run.StepRuns {
			d := deltas[sr.StepKey]
			out := outputs[sr.StepKey]
			out.Previous, out.Added, out.Gone = intPtr(d.Previous), intPtr(d.Added), intPtr(d.Gone)
			outputs[sr.StepKey] = out
		}
	}

	steps := mapSteps(m.Workflow, run)
	for _, st := range steps {
		n := RunMapNode{
			StepKey: st.StepKey, Name: st.Name, Tool: st.Tool, Capabilities: st.Capabilities,
			DependsOn: append([]string{}, st.DependsOn...), TimeoutSeconds: st.TimeoutSeconds,
			Chunks: chunks[st.StepKey], Outputs: outputs[st.StepKey],
		}
		if n.Outputs.ByType == nil {
			n.Outputs.ByType = map[string]int{}
		}
		if p, ok := plans[st.StepKey]; ok {
			inputs, planned := p.Inputs, p.Planned
			n.Inputs, n.Planned = &inputs, &planned
		}
		if sr := stepRuns[st.StepKey]; sr != nil {
			fillNodeFromStepRun(&n, sr, platform[st.StepKey])
		} else {
			n.State = mapStatePending
		}
		resp.Nodes = append(resp.Nodes, n)
	}
	for _, n := range resp.Nodes {
		for _, dep := range n.DependsOn {
			resp.Edges = append(resp.Edges, RunMapEdge{From: dep, To: n.StepKey, Count: outputs[dep].Total})
		}
	}
	return resp
}

func intPtr(n int) *int { return &n }

// RunStepOutput is one asset a step of a run produced.
type RunStepOutput struct {
	AssetID string `json:"asset_id"`
	Name    string `json:"name"`
	Type    string `json:"type"`
	SubType string `json:"sub_type,omitempty"`
	// New: the previous run of the scan did not produce it in this step.
	New bool `json:"new"`
}

// RunStepOutputsResponse is a sample of what a step of a run produced.
type RunStepOutputsResponse struct {
	// Total is how many assets the step produced in the caller's scope;
	// Outputs lists up to the limit of them, new ones first.
	Total         int             `json:"total"`
	Outputs       []RunStepOutput `json:"outputs"`
	PreviousRunID string          `json:"previous_run_id,omitempty"`
}

// ListRunStepOutputs handles GET /api/v1/scan-runs/{id}/outputs?step_key=
// @Summary      What a step of a run produced
// @Description  Up to `limit` (default 20, at most 50) live assets one step of the run produced, new ones (not produced by the same step of the previous finished run of the scan) first, with how many there are. Only assets in the caller's data scope are listed and counted. A run of another organization, or a run about a finding outside the caller's scope, is not found.
// @Tags         Scan workflows
// @Produce      json
// @Param        id        path      string  true   "Run ID"
// @Param        step_key  query     string  true   "Step key"
// @Param        limit     query     int     false  "At most this many (1-50, default 20)"
// @Success      200  {object}  RunStepOutputsResponse
// @Failure      400  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scan-runs/{id}/outputs [get]
func (h *ScanWorkflowHandler) ListRunStepOutputs(w http.ResponseWriter, r *http.Request) {
	limit, ok := listLimit(w, r, 20, scanrunapp.MaxStepOutputPreview)
	if !ok {
		return
	}
	stepKey := r.URL.Query().Get("step_key")
	if stepKey == "" {
		apierror.BadRequest("step_key is required").WriteJSON(w)
		return
	}
	if !h.guardRun(w, r) {
		return
	}
	tenant := middleware.GetTenantID(r.Context())
	tenantID, err := shared.IDFromString(tenant)
	if err != nil {
		apierror.NotFound("Run").WriteJSON(w)
		return
	}
	var scope *shared.DataScope
	if h.findingScope != nil {
		if scope, err = h.findingScope.Resolve(r.Context(), tenantID); err != nil {
			h.logger.Error("failed to resolve data scope", "error", err)
			apierror.InternalServerError("failed to read the step outputs").WriteJSON(w)
			return
		}
	}
	p, err := h.service.PreviewStepOutputs(r.Context(), tenant, chi.URLParam(r, "id"), stepKey, scope, limit)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	resp := RunStepOutputsResponse{Total: p.Total, Outputs: make([]RunStepOutput, 0, len(p.Outputs))}
	if !p.PreviousRunID.IsZero() {
		resp.PreviousRunID = p.PreviousRunID.String()
	}
	for _, o := range p.Outputs {
		resp.Outputs = append(resp.Outputs, RunStepOutput{
			AssetID: o.AssetID.String(), Name: o.Name, Type: o.Type, SubType: o.SubType, New: o.New,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// mapSteps is what the map draws: the workflow version's steps, or, for a
// run without one (a retest, a deleted workflow), one node per step run.
func mapSteps(wf *scanworkflow.Workflow, run *scanrundom.Run) []*scanworkflow.Step {
	if wf != nil && len(wf.Steps) > 0 {
		steps := append([]*scanworkflow.Step{}, wf.Steps...)
		sort.SliceStable(steps, func(i, j int) bool { return steps[i].StepOrder < steps[j].StepOrder })
		return steps
	}
	steps := make([]*scanworkflow.Step, 0, len(run.StepRuns))
	for _, sr := range run.StepRuns {
		steps = append(steps, &scanworkflow.Step{StepKey: sr.StepKey, Name: sr.StepName, Tool: sr.Tool, StepOrder: sr.StepOrder})
	}
	sort.SliceStable(steps, func(i, j int) bool { return steps[i].StepOrder < steps[j].StepOrder })
	return steps
}

// fillNodeFromStepRun sets a node's state, reason, error and times from its
// step run. The error message is redacted like every run field: a platform
// sensor is never named.
func fillNodeFromStepRun(n *RunMapNode, sr *scanrundom.StepRun, platform bool) {
	if sr.Tool != "" {
		n.Tool = sr.Tool
	}
	if n.Name == "" {
		n.Name = sr.StepName
	}
	n.Findings = sr.FindingsCount
	n.State = mapNodeState(sr.Status, n.Chunks)
	switch n.State {
	case mapStateWaiting:
		n.Reason = "waiting_for_sensor"
	case mapStateFailed, mapStatePartial, mapStateSkipped, mapStateCanceled:
		n.Reason = sr.ErrorCode
		n.ErrorClass = stepErrorClass(sr.ErrorCode)
		n.ErrorMessage = platformText(platform, sr.ErrorMessage)
	}
	if sr.StartedAt != nil {
		n.StartedAt = sr.StartedAt.Format("2006-01-02T15:04:05Z07:00")
	}
	if sr.CompletedAt != nil {
		n.CompletedAt = sr.CompletedAt.Format("2006-01-02T15:04:05Z07:00")
	}
}

// mapNodeState maps a step run status (and its chunks) onto the map states.
func mapNodeState(status scanrundom.StepRunStatus, c RunMapChunks) string {
	switch status {
	case scanrundom.StepRunStatusPending:
		return mapStatePending
	case scanrundom.StepRunStatusQueued, scanrundom.StepRunStatusRunning:
		if c.Running > 0 || c.Completed > 0 || c.Failed > 0 {
			return mapStateRunning
		}
		if c.Queued > 0 || status == scanrundom.StepRunStatusQueued {
			return mapStateWaiting
		}
		return mapStateRunning
	case scanrundom.StepRunStatusCompleted:
		return mapStateSucceeded
	case scanrundom.StepRunStatusPartial:
		return mapStatePartial
	case scanrundom.StepRunStatusFailed, scanrundom.StepRunStatusTimeout:
		return mapStateFailed
	case scanrundom.StepRunStatusSkipped:
		return mapStateSkipped
	case scanrundom.StepRunStatusCanceled:
		return mapStateCanceled
	default:
		return mapStatePending
	}
}
