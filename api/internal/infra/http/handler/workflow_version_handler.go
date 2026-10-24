package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	automationsvc "github.com/openctemio/openctem/api/internal/app/automation"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/automation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// WorkflowVersionResponse is one published definition of an automation.
type WorkflowVersionResponse struct {
	ID              string  `json:"id"`
	Version         int     `json:"version"`
	Digest          string  `json:"digest"`
	RiskClass       string  `json:"risk_class"`
	Status          string  `json:"status"`
	PublishedBy     *string `json:"published_by,omitempty"`
	PublishedByName string  `json:"published_by_name,omitempty"`
	PublishedAt     *string `json:"published_at,omitempty"`
	ApprovedBy      *string `json:"approved_by,omitempty"`
	ApprovedByName  string  `json:"approved_by_name,omitempty"`
	ApprovedAt      *string `json:"approved_at,omitempty"`
	StepUpAt        *string `json:"step_up_at,omitempty"`
	CreatedAt       string  `json:"created_at"`
	// Definition is set only on GET /workflows/{id}/versions/{version_id}.
	Definition *automation.Definition `json:"definition,omitempty"`
}

func timePtrString(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format(time.RFC3339)
	return &s
}

// withNames sets the publisher and approver names on resp from names.
func withNames(resp *WorkflowVersionResponse, v *automation.Version, names map[shared.ID]string) *WorkflowVersionResponse {
	if resp == nil || v == nil {
		return resp
	}
	if v.PublishedBy != nil {
		resp.PublishedByName = names[*v.PublishedBy]
	}
	if v.ApprovedBy != nil {
		resp.ApprovedByName = names[*v.ApprovedBy]
	}
	return resp
}

func toWorkflowVersionResponse(v *automation.Version, withDefinition bool) *WorkflowVersionResponse {
	if v == nil {
		return nil
	}
	resp := &WorkflowVersionResponse{
		ID: v.ID.String(), Version: v.Version, Digest: v.Digest, RiskClass: string(v.RiskClass), Status: string(v.Status),
		PublishedBy: idPtrString(v.PublishedBy), PublishedAt: timePtrString(v.PublishedAt),
		ApprovedBy: idPtrString(v.ApprovedBy), ApprovedAt: timePtrString(v.ApprovedAt),
		StepUpAt: timePtrString(v.StepUpAt), CreatedAt: v.CreatedAt.Format(time.RFC3339),
	}
	if withDefinition {
		def := v.Definition
		resp.Definition = &def
	}
	return resp
}

// toWorkflowDetailResponse is the automation with its draft graph, mode,
// versions and the draft's risk class.
func toWorkflowDetailResponse(d *automationsvc.WorkflowDetail) *WorkflowResponse {
	resp := toWorkflowResponse(d.Workflow)
	resp.RiskClass = string(d.RiskClass)
	resp.DraftChanged = d.DraftChanged
	resp.PublishedVersion = withNames(toWorkflowVersionResponse(d.Published, false), d.Published, d.Names)
	resp.PendingVersion = withNames(toWorkflowVersionResponse(d.Pending, false), d.Pending, d.Names)
	return resp
}

// workflowPathIDs reads the tenant and the {id} path parameter, writing a 400
// and returning false when either is not an id.
func workflowPathIDs(w http.ResponseWriter, r *http.Request) (tenantID, workflowID, userID shared.ID, ok bool) {
	tenantID, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("Invalid tenant ID").WriteJSON(w)
		return tenantID, workflowID, userID, false
	}
	workflowID, err = shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.BadRequest("Invalid workflow ID").WriteJSON(w)
		return tenantID, workflowID, userID, false
	}
	userID, _ = shared.IDFromString(middleware.GetUserID(r.Context()))
	return tenantID, workflowID, userID, true
}

// ListVersions handles GET /api/v1/workflows/{id}/versions.
// @Summary      List automation versions
// @Description  The published versions of an automation, newest first (status published, pending_approval, superseded or retired).
// @Tags         Automations
// @Produce      json
// @Param        id   path      string  true  "Automation ID"
// @Success      200  {object}  map[string][]WorkflowVersionResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /workflows/{id}/versions [get]
func (h *WorkflowHandler) ListVersions(w http.ResponseWriter, r *http.Request) {
	tenantID, workflowID, _, ok := workflowPathIDs(w, r)
	if !ok {
		return
	}
	versions, err := h.service.ListVersions(r.Context(), tenantID, workflowID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	names := h.service.VersionNames(r.Context(), versions...)
	items := make([]*WorkflowVersionResponse, 0, len(versions))
	for _, v := range versions {
		items = append(items, withNames(toWorkflowVersionResponse(v, false), v, names))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"items": items})
}

// GetVersion handles GET /api/v1/workflows/{id}/versions/{version_id}.
// @Summary      Get an automation version
// @Description  One version with its stored definition (nodes and edges).
// @Tags         Automations
// @Produce      json
// @Param        id         path      string  true  "Automation ID"
// @Param        version_id  path      string  true  "Version ID"
// @Success      200  {object}  WorkflowVersionResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /workflows/{id}/versions/{version_id} [get]
func (h *WorkflowHandler) GetVersion(w http.ResponseWriter, r *http.Request) {
	tenantID, workflowID, _, ok := workflowPathIDs(w, r)
	if !ok {
		return
	}
	versionID, err := shared.IDFromString(chi.URLParam(r, "version_id"))
	if err != nil {
		apierror.BadRequest("Invalid version ID").WriteJSON(w)
		return
	}
	v, err := h.service.GetVersion(r.Context(), tenantID, workflowID, versionID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(withNames(toWorkflowVersionResponse(v, true), v, h.service.VersionNames(r.Context(), v)))
}

// Publish handles POST /api/v1/workflows/{id}/publish: the draft becomes a
// new version and goes live. The caller needs the permission of every step,
// as switching an automation on does.
// @Summary      Publish an automation
// @Description  Stores the draft as a new immutable version and makes it live through the go-live gate: low risk publishes at once; elevated needs a recent re-authentication (403 STEP_UP_REQUIRED); high also waits for a second person with automations:publish to approve the version (202 pending_approval). A draft with blocking validate problems is refused (400 WORKFLOW_INVALID, problems in details). The caller needs the permission of every step and becomes the owner live runs act as.
// @Tags         Automations
// @Produce      json
// @Param        id   path      string  true  "Automation ID"
// @Success      200  {object}  WorkflowResponse
// @Success      202  {object}  PublishPendingResponse
// @Failure      400  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /workflows/{id}/publish [post]
func (h *WorkflowHandler) Publish(w http.ResponseWriter, r *http.Request) {
	tenantID, workflowID, userID, ok := workflowPathIDs(w, r)
	if !ok {
		return
	}
	res, err := h.service.Publish(r.Context(), automationsvc.PublishInput{
		TenantID: tenantID, UserID: userID, WorkflowID: workflowID, Authorize: h.authorizeDefinition(r),
	})
	h.writePublishResult(w, r, tenantID, workflowID, res, err)
}

// PublishPendingResponse is the 202 answer of a publish that waits for a
// second person's approval.
type PublishPendingResponse struct {
	Status  string                   `json:"status"`
	Version *WorkflowVersionResponse `json:"version"`
}

// writePublishResult answers a publish or rollback: the automation (200),
// or the version waiting for approval (202); a step-up refusal the way the
// web's re-authentication dialog expects; WORKFLOW_INVALID with the
// problems in details.
func (h *WorkflowHandler) writePublishResult(w http.ResponseWriter, r *http.Request, tenantID, workflowID shared.ID, res *automationsvc.PublishResult, err error) {
	if err != nil {
		if writeStepUpError(w, err) {
			return
		}
		var invalid *automationsvc.WorkflowInvalidError
		if errors.As(err, &invalid) {
			problems := make([]WorkflowProblem, 0, len(invalid.Problems))
			for _, p := range invalid.Problems {
				problems = append(problems, WorkflowProblem{Code: p.Code, NodeKey: p.NodeKey, Message: p.Message})
			}
			apierror.New(http.StatusBadRequest, automationsvc.ErrCodeWorkflowInvalid, invalid.Error()).
				WithDetails(map[string]any{"problems": problems}).WriteJSON(w)
			return
		}
		h.handleServiceError(w, err)
		return
	}
	if !res.Live {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(PublishPendingResponse{Status: string(automation.VersionPendingApproval), Version: toWorkflowVersionResponse(res.Version, false)})
		return
	}
	h.writeWorkflowDetail(w, r, tenantID, workflowID, http.StatusOK)
}

// ApproveVersionRequest names the digest the approver reviewed.
type ApproveVersionRequest struct {
	Digest string `json:"digest" validate:"required,len=64,hexadecimal"`
}

// ApproveVersion handles POST /api/v1/workflows/{id}/versions/{version_id}/approve.
// @Summary      Approve a high-risk automation version
// @Description  A second person with automations:publish, who re-authenticated recently and did not publish it, approves the version they reviewed (its digest). The version goes live; its publisher is the owner live runs act as. 403 SELF_APPROVAL for the publisher, 409 VERSION_CHANGED when the digest differs or the version no longer waits, 403 STEP_UP_REQUIRED without a recent sign-in.
// @Tags         Automations
// @Accept       json
// @Produce      json
// @Param        id         path      string                 true  "Automation ID"
// @Param        version_id path      string                 true  "Version ID"
// @Param        body       body      ApproveVersionRequest  true  "Reviewed digest"
// @Success      200  {object}  WorkflowResponse
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /workflows/{id}/versions/{version_id}/approve [post]
func (h *WorkflowHandler) ApproveVersion(w http.ResponseWriter, r *http.Request) {
	tenantID, workflowID, userID, ok := workflowPathIDs(w, r)
	if !ok {
		return
	}
	versionID, err := shared.IDFromString(chi.URLParam(r, "version_id"))
	if err != nil {
		apierror.BadRequest("Invalid version ID").WriteJSON(w)
		return
	}
	var req ApproveVersionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	v, err := h.service.GetVersion(r.Context(), tenantID, workflowID, versionID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	// The approver needs the permission of every step they let act.
	cfgs := make([]*NodeConfigRequest, 0, len(v.Definition.Nodes))
	for _, n := range v.Definition.Nodes {
		cfgs = append(cfgs, &NodeConfigRequest{ActionType: string(n.Config.ActionType), NotificationType: string(n.Config.NotificationType)})
	}
	if !h.requireActionPermissions(w, r, cfgs...) {
		return
	}
	if _, err := h.service.ApproveVersion(r.Context(), tenantID, userID, workflowID, versionID, req.Digest); err != nil {
		if writeStepUpError(w, err) {
			return
		}
		h.handleServiceError(w, err)
		return
	}
	h.writeWorkflowDetail(w, r, tenantID, workflowID, http.StatusOK)
}

// Rollback handles POST /api/v1/workflows/{id}/versions/{version_id}/rollback:
// the older version's definition is published again as a new version.
// @Summary      Roll an automation back to a version
// @Description  Publishes the older version's definition again as a new version.
// @Tags         Automations
// @Produce      json
// @Param        id         path      string  true  "Automation ID"
// @Param        version_id  path      string  true  "Version ID"
// @Success      200  {object}  WorkflowResponse
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /workflows/{id}/versions/{version_id}/rollback [post]
func (h *WorkflowHandler) Rollback(w http.ResponseWriter, r *http.Request) {
	tenantID, workflowID, userID, ok := workflowPathIDs(w, r)
	if !ok {
		return
	}
	versionID, err := shared.IDFromString(chi.URLParam(r, "version_id"))
	if err != nil {
		apierror.BadRequest("Invalid version ID").WriteJSON(w)
		return
	}
	res, err := h.service.Rollback(r.Context(), automationsvc.PublishInput{
		TenantID: tenantID, UserID: userID, WorkflowID: workflowID, Authorize: h.authorizeDefinition(r),
	}, versionID)
	h.writePublishResult(w, r, tenantID, workflowID, res, err)
}

// authorizeDefinition is the publish permission check: the caller needs the
// permission of every step of the definition the service is about to store.
func (h *WorkflowHandler) authorizeDefinition(r *http.Request) func(automation.Definition) error {
	return func(d automation.Definition) error {
		perm, ok := authorizeActionConfigs(r.Context(), definitionConfigs(d)...)
		if ok {
			return nil
		}
		h.logger.Warn("workflow publish permission denied",
			"user_id", middleware.GetUserID(r.Context()), "required_permission", string(perm))
		return shared.NewDomainError("FORBIDDEN", "insufficient permission for a workflow action node; '"+string(perm)+"' is required", shared.ErrForbidden)
	}
}

// SetWorkflowModeRequest is the body of PUT /workflows/{id}/mode.
type SetWorkflowModeRequest struct {
	Mode string `json:"mode" validate:"required,oneof=simulate live"`
}

// SetMode handles PUT /api/v1/workflows/{id}/mode. Only simulate is
// accepted: an automation goes live by publishing.
// @Summary      Switch an automation to simulate
// @Description  Simulate runs execute the draft and record what they would do. Live is reached only by publishing (400 MODE_LIVE_NEEDS_PUBLISH).
// @Tags         Automations
// @Accept       json
// @Produce      json
// @Param        id    path      string                  true  "Automation ID"
// @Param        body  body      SetWorkflowModeRequest  true  "Mode"
// @Success      200   {object}  WorkflowResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /workflows/{id}/mode [put]
func (h *WorkflowHandler) SetMode(w http.ResponseWriter, r *http.Request) {
	tenantID, workflowID, userID, ok := workflowPathIDs(w, r)
	if !ok {
		return
	}
	var req SetWorkflowModeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	if _, err := h.service.ChangeMode(r.Context(), tenantID, userID, workflowID, automation.Mode(req.Mode)); err != nil {
		h.handleServiceError(w, err)
		return
	}
	h.writeWorkflowDetail(w, r, tenantID, workflowID, http.StatusOK)
}

func (h *WorkflowHandler) writeWorkflowDetail(w http.ResponseWriter, r *http.Request, tenantID, workflowID shared.ID, status int) {
	d, err := h.service.GetWorkflowDetail(r.Context(), tenantID, workflowID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(toWorkflowDetailResponse(d))
}

// WorkflowTraceStep is one step's trace summed over runs.
type WorkflowTraceStep struct {
	NodeKey string         `json:"node_key"`
	In      int            `json:"in"`
	Out     int            `json:"out"`
	Skipped map[string]int `json:"skipped,omitempty"`
}

// WorkflowTraceResponse is an automation's trace over a window, counted over
// runs whose subject the caller may see.
type WorkflowTraceResponse struct {
	Mode                string              `json:"mode"`
	Days                int                 `json:"days"`
	Runs                int                 `json:"runs"`
	Steps               []WorkflowTraceStep `json:"steps"`
	DeliveriesByChannel map[string]int      `json:"deliveries_by_channel"`
}

// GetTrace handles GET /api/v1/workflows/{id}/trace?mode=simulate&days=30.
// @Summary      Automation trace
// @Description  Per-step in, out and per-reason skipped counts summed over the automation's runs of one mode in the last days (default simulate, 30; at most 180), and deliveries per channel. Only runs whose subject (finding or asset) is in the caller's data scope are counted.
// @Tags         Automations
// @Produce      json
// @Param        id    path      string  true   "Automation ID"
// @Param        mode  query     string  false  "simulate or live"
// @Param        days  query     int     false  "Days back (1-180)"
// @Success      200   {object}  WorkflowTraceResponse
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /workflows/{id}/trace [get]
func (h *WorkflowHandler) GetTrace(w http.ResponseWriter, r *http.Request) {
	tenantID, workflowID, userID, ok := workflowPathIDs(w, r)
	if !ok {
		return
	}
	in := automationsvc.TraceInput{TenantID: tenantID, UserID: userID, WorkflowID: workflowID,
		Mode: automation.Mode(r.URL.Query().Get("mode"))}
	if d := r.URL.Query().Get("days"); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || n < 1 || n > 180 {
			apierror.BadRequest("days must be between 1 and 180").WriteJSON(w)
			return
		}
		in.Days = n
	}
	agg, err := h.service.Trace(r.Context(), in)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	if !in.Mode.IsValid() {
		in.Mode = automation.ModeSimulate
	}
	if in.Days == 0 {
		in.Days = 30
	}
	resp := WorkflowTraceResponse{Mode: string(in.Mode), Days: in.Days, Runs: agg.Runs,
		Steps: []WorkflowTraceStep{}, DeliveriesByChannel: agg.DeliveriesByChannel}
	for _, s := range agg.Steps {
		resp.Steps = append(resp.Steps, WorkflowTraceStep{NodeKey: s.NodeKey, In: s.In, Out: s.Out, Skipped: s.Skipped})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
