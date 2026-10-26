package handler

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	automationsvc "github.com/openctemio/openctem/api/internal/app/automation"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/automation"
)

// Preview and validate rate limits per user (one replica's view; each call
// only reads).
const (
	previewPerWindow  = 1
	validatePerWindow = 10
	previewWindow     = 10 * time.Second
)

// userWindowLimiter allows n calls per user per window.
type userWindowLimiter struct {
	mu    sync.Mutex
	calls map[string][]time.Time
}

func (l *userWindowLimiter) allow(key string, n int, window time.Duration, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.calls == nil {
		l.calls = map[string][]time.Time{}
	}
	kept := l.calls[key][:0]
	for _, t := range l.calls[key] {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= n {
		l.calls[key] = kept
		return false
	}
	l.calls[key] = append(kept, now)
	if len(l.calls) > 10000 { // bound memory: forget idle users
		for k, v := range l.calls {
			if len(v) == 0 || now.Sub(v[len(v)-1]) >= window {
				delete(l.calls, k)
			}
		}
	}
	return true
}

var (
	previewLimiter  userWindowLimiter
	validateLimiter userWindowLimiter
)

// WorkflowDraftRequest names a draft: the given nodes and edges, or the
// saved draft when nodes is empty.
type WorkflowDraftRequest struct {
	Nodes []NodeRequest       `json:"nodes" validate:"max=50,dive"`
	Edges []CreateEdgeRequest `json:"edges" validate:"max=100,dive"`
	// Limit is how many subjects a preview runs against (1-100, default 20).
	Limit int `json:"limit" validate:"omitempty,min=1"`
}

// WorkflowPreviewDelivery is one message or ticket the draft would send.
type WorkflowPreviewDelivery struct {
	NodeKey   string         `json:"node_key"`
	SubjectID string         `json:"subject_id,omitempty"`
	Channel   string         `json:"channel"`
	Target    string         `json:"target,omitempty"`
	Payload   map[string]any `json:"payload,omitempty"`
}

// WorkflowPreviewResponse is what the draft would do on the latest subjects
// the caller may read. Nothing is stored or sent.
type WorkflowPreviewResponse struct {
	Subjects   int                       `json:"subjects"`
	SampleIDs  []string                  `json:"sample_ids"`
	Steps      []WorkflowTraceStep       `json:"steps"`
	Deliveries []WorkflowPreviewDelivery `json:"deliveries"`
}

// WorkflowProblem is one validate finding.
type WorkflowProblem struct {
	Code    string `json:"code"`
	NodeKey string `json:"node_key,omitempty"`
	Message string `json:"message"`
}

// WorkflowValidationResponse lists a draft's problems (they block
// publishing) and warnings.
type WorkflowValidationResponse struct {
	Problems []WorkflowProblem `json:"problems"`
	Warnings []WorkflowProblem `json:"warnings"`
}

func (h *WorkflowHandler) draftInput(w http.ResponseWriter, r *http.Request) (automationsvc.DraftInput, WorkflowDraftRequest, bool) {
	var in automationsvc.DraftInput
	var req WorkflowDraftRequest
	tenantID, workflowID, userID, ok := workflowPathIDs(w, r)
	if !ok {
		return in, req, false
	}
	if r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apierror.BadRequest("Invalid request body").WriteJSON(w)
			return in, req, false
		}
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return in, req, false
	}
	in = automationsvc.DraftInput{TenantID: tenantID, UserID: userID, WorkflowID: workflowID}
	for _, n := range req.Nodes {
		ni := automationsvc.CreateNodeInput{NodeKey: n.NodeKey, NodeType: automation.NodeType(n.NodeType), Name: n.Name}
		if n.Config != nil {
			ni.Config = toNodeConfig(n.Config)
		}
		in.Nodes = append(in.Nodes, ni)
	}
	for _, e := range req.Edges {
		in.Edges = append(in.Edges, automationsvc.CreateEdgeInput{SourceNodeKey: e.SourceNodeKey, TargetNodeKey: e.TargetNodeKey,
			SourceHandle: e.SourceHandle, Label: e.Label})
	}
	return in, req, true
}

func writeRateLimitedAutomation(w http.ResponseWriter, window time.Duration) {
	w.Header().Set("Retry-After", "10")
	apierror.New(http.StatusTooManyRequests, "RATE_LIMITED", "Too many requests; try again in "+window.String()).WriteJSON(w)
}

// Preview handles POST /api/v1/workflows/{id}/preview.
// @Summary      Preview an automation draft
// @Description  Runs the draft (the body's nodes and edges, or the saved draft) against the latest subjects of its trigger's kind that the caller may read (limit 1-100, default 20), through the read-only simulate evaluator. Returns per-step counts and what it would send. Nothing is stored or sent. At most one call per 10 seconds per user.
// @Tags         Automations
// @Accept       json
// @Produce      json
// @Param        id    path      string                true   "Automation ID"
// @Param        body  body      WorkflowDraftRequest  false  "Draft and limit"
// @Success      200   {object}  WorkflowPreviewResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      429   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /workflows/{id}/preview [post]
func (h *WorkflowHandler) Preview(w http.ResponseWriter, r *http.Request) {
	in, req, ok := h.draftInput(w, r)
	if !ok {
		return
	}
	if req.Limit > automationsvc.MaxPreviewSubjects {
		apierror.BadRequest("limit is at most 100").WriteJSON(w)
		return
	}
	if !previewLimiter.allow(middleware.GetTenantID(r.Context())+":"+in.UserID.String(), previewPerWindow, previewWindow, time.Now()) {
		writeRateLimitedAutomation(w, previewWindow)
		return
	}
	res, err := h.service.Preview(r.Context(), in, req.Limit)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	resp := WorkflowPreviewResponse{Subjects: res.Subjects, SampleIDs: res.SampleIDs, Steps: []WorkflowTraceStep{}, Deliveries: []WorkflowPreviewDelivery{}}
	for _, s := range res.Steps {
		resp.Steps = append(resp.Steps, WorkflowTraceStep{NodeKey: s.NodeKey, In: s.In, Out: s.Out, Skipped: s.Skipped})
	}
	for _, d := range res.Deliveries {
		resp.Deliveries = append(resp.Deliveries, WorkflowPreviewDelivery{NodeKey: d.NodeKey, SubjectID: d.SubjectID,
			Channel: d.Channel, Target: d.Target, Payload: d.Payload})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Validate handles POST /api/v1/workflows/{id}/verify.
// @Summary      Validate an automation draft
// @Description  Checks the draft (the body's nodes and edges, or the saved draft) statically: unsupported types, graph errors, conditions, required settings, integrations, permissions the caller lacks (the caller owns the automation once they publish it) and whether it ran in simulate since its last change. Problems block publishing; warnings do not. At most 10 calls per 10 seconds per user.
// @Tags         Automations
// @Accept       json
// @Produce      json
// @Param        id    path      string                true   "Automation ID"
// @Param        body  body      WorkflowDraftRequest  false  "Draft"
// @Success      200   {object}  WorkflowValidationResponse
// @Failure      404   {object}  apierror.Error
// @Failure      429   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /workflows/{id}/verify [post]
func (h *WorkflowHandler) Validate(w http.ResponseWriter, r *http.Request) {
	in, _, ok := h.draftInput(w, r)
	if !ok {
		return
	}
	if !validateLimiter.allow(middleware.GetTenantID(r.Context())+":"+in.UserID.String(), validatePerWindow, previewWindow, time.Now()) {
		writeRateLimitedAutomation(w, previewWindow)
		return
	}
	res, err := h.service.Validate(r.Context(), in)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	resp := WorkflowValidationResponse{Problems: []WorkflowProblem{}, Warnings: []WorkflowProblem{}}
	for _, p := range res.Problems {
		resp.Problems = append(resp.Problems, WorkflowProblem{Code: p.Code, NodeKey: p.NodeKey, Message: p.Message})
	}
	for _, p := range res.Warnings {
		resp.Warnings = append(resp.Warnings, WorkflowProblem{Code: p.Code, NodeKey: p.NodeKey, Message: p.Message})
	}
	resp.Problems = append(resp.Problems, h.ownerPermissionProblems(r, in)...)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// ownerPermissionProblems lists the steps whose permission the caller lacks:
// publishing would make them the owner the steps act as.
func (h *WorkflowHandler) ownerPermissionProblems(r *http.Request, in automationsvc.DraftInput) []WorkflowProblem {
	type step struct {
		key string
		cfg automation.NodeConfig
	}
	var steps []step
	if len(in.Nodes) > 0 {
		for _, n := range in.Nodes {
			steps = append(steps, step{n.NodeKey, n.Config})
		}
	} else if wf, err := h.service.GetWorkflow(r.Context(), in.TenantID, in.WorkflowID); err == nil {
		for _, n := range wf.Nodes {
			steps = append(steps, step{n.NodeKey, n.Config})
		}
	}
	out := []WorkflowProblem{}
	for _, s := range steps {
		if perm, required := automationsvc.NodePermission(s.cfg); required && !middleware.HasPermission(r.Context(), string(perm)) {
			out = append(out, WorkflowProblem{Code: "OWNER_LACKS_PERMISSION", NodeKey: s.key,
				Message: "you would own this automation when you publish it, and you lack " + string(perm)})
		}
	}
	return out
}
