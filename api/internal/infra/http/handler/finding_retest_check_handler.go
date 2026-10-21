package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	retestcheckapp "github.com/openctemio/openctem/api/internal/app/retestcheck"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	retestcheckdom "github.com/openctemio/openctem/api/pkg/domain/retestcheck"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// maxRetestCheckBody bounds a retest check request (a template is at most
// 1 MiB; the assertion is far smaller).
const maxRetestCheckBody = 2 << 20

// FindingRetestCheckHandler serves a finding's retest check
// (docs/architecture/finding-retest-checks.md). The tenant comes from the
// token; the finding's data scope is enforced by the /findings/{id}/** route
// guard, and every lookup is tenant-scoped (another tenant's finding or
// template is 404).
type FindingRetestCheckHandler struct {
	service *retestcheckapp.Service
	logger  *logger.Logger
}

// NewFindingRetestCheckHandler creates the handler.
func NewFindingRetestCheckHandler(svc *retestcheckapp.Service, log *logger.Logger) *FindingRetestCheckHandler {
	return &FindingRetestCheckHandler{service: svc, logger: log}
}

// RetestCheckRequest is a check to validate or save: a nuclei template
// (content), a declarative assertion, or a library template to reuse
// (template_id).
type RetestCheckRequest struct {
	Kind       string                        `json:"kind"`
	Name       string                        `json:"name,omitempty"`
	Content    string                        `json:"content,omitempty"`
	Assertion  *retestcheckdom.HTTPAssertion `json:"assertion,omitempty"`
	TemplateID string                        `json:"template_id,omitempty"`
}

// RetestCheckApproval is the approval state of an intrusive check.
type RetestCheckApproval struct {
	Required   bool       `json:"required"`
	Approved   bool       `json:"approved"`
	ApprovedBy string     `json:"approved_by,omitempty"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
}

// RetestCheckResponse is a finding's retest check.
type RetestCheckResponse struct {
	ID             string                        `json:"id"`
	FindingID      string                        `json:"finding_id"`
	Kind           string                        `json:"kind"`
	TemplateID     string                        `json:"template_id"`
	TemplateName   string                        `json:"template_name"`
	TemplateDigest string                        `json:"template_digest"`
	Content        string                        `json:"content"`
	Assertion      *retestcheckdom.HTTPAssertion `json:"assertion"`
	Tier           string                        `json:"tier"`
	TierReason     string                        `json:"tier_reason"`
	Approval       RetestCheckApproval           `json:"approval"`
	// TemplatePendingSensorApproval: the organization requires template
	// versions to be approved for sensors and this one is not yet.
	TemplatePendingSensorApproval bool `json:"template_pending_sensor_approval"`
	// Calibrated: this version matched the finding once, so a no-match
	// proves a fix.
	Calibrated   bool       `json:"calibrated"`
	CalibratedAt *time.Time `json:"calibrated_at,omitempty"`
	CreatedBy    string     `json:"created_by,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedBy    string     `json:"updated_by,omitempty"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// RetestCheckGetResponse wraps a finding's check (null when it has none).
type RetestCheckGetResponse struct {
	Check *RetestCheckResponse `json:"check"`
}

// RetestCheckValidationResponse is the outcome of validating a check.
type RetestCheckValidationResponse struct {
	Valid            bool                   `json:"valid"`
	Errors           []retestcheckdom.Issue `json:"errors"`
	Tier             string                 `json:"tier"`
	TierReason       string                 `json:"tier_reason"`
	Capabilities     []string               `json:"capabilities"`
	Content          string                 `json:"content"`
	ApprovalRequired bool                   `json:"approval_required"`
}

func idOrEmpty(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}

func toRetestCheckResponse(v *retestcheckapp.View) *RetestCheckResponse {
	if v == nil {
		return nil
	}
	c, t := v.Check, v.Template
	digest := v.Digest()
	out := &RetestCheckResponse{
		ID: c.ID.String(), FindingID: c.FindingID.String(), Kind: string(c.Kind),
		TemplateID: t.ID.String(), TemplateName: t.Name, TemplateDigest: digest, Content: string(t.Content),
		Assertion: c.Assertion, Tier: c.Tier, TierReason: c.TierReason,
		Approval:                      RetestCheckApproval{Required: c.NeedsApproval(), Approved: c.NeedsApproval() && c.Approved(digest)},
		TemplatePendingSensorApproval: !t.ApprovedForSensors(),
		Calibrated:                    c.Calibrated(digest),
		CreatedBy:                     idOrEmpty(c.CreatedBy), CreatedAt: c.CreatedAt,
		UpdatedBy: idOrEmpty(c.UpdatedBy), UpdatedAt: c.UpdatedAt,
	}
	if out.Approval.Approved {
		out.Approval.ApprovedBy, out.Approval.ApprovedAt = idOrEmpty(c.ApprovedBy), c.ApprovedAt
	}
	if out.Calibrated {
		out.CalibratedAt = c.CalibratedAt
	}
	return out
}

func (h *FindingRetestCheckHandler) ids(w http.ResponseWriter, r *http.Request) (tenantID, findingID shared.ID, ok bool) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("invalid tenant").WriteJSON(w)
		return tenantID, findingID, false
	}
	findingID, err = shared.IDFromString(chi.URLParam(r, "id"))
	if err != nil {
		apierror.NotFound("Finding").WriteJSON(w)
		return tenantID, findingID, false
	}
	return tenantID, findingID, true
}

func actorID(r *http.Request) (shared.ID, bool) {
	if uid := middleware.GetLocalUserID(r.Context()); !uid.IsZero() {
		return uid, true
	}
	uid, err := shared.IDFromString(middleware.GetUserID(r.Context()))
	return uid, err == nil
}

func retestCheckAudit(r *http.Request, tenantID shared.ID) auditapp.AuditContext {
	return auditapp.AuditContext{
		TenantID: tenantID.String(), ActorID: middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()), ActorIP: getClientIP(r),
		UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
	}
}

func decodeRetestCheck(w http.ResponseWriter, r *http.Request) (retestcheckapp.Input, bool) {
	var req RetestCheckRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRetestCheckBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return retestcheckapp.Input{}, false
	}
	return retestcheckapp.Input{Kind: retestcheckdom.Kind(req.Kind), Name: req.Name, Content: req.Content,
		Assertion: req.Assertion, TemplateID: req.TemplateID}, true
}

func writeRetestCheckJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Get handles GET /api/v1/findings/{id}/retest-check.
// @Summary      A finding's retest check
// @Description  The custom check the finding's retest runs (null when none): its template, digest, tier, approval and calibration. Requires findings:read; out-of-scope findings are 404.
// @Tags         Findings
// @Produce      json
// @Param        id   path      string  true  "Finding ID"
// @Success      200  {object}  RetestCheckGetResponse
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/retest-check [get]
func (h *FindingRetestCheckHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID, findingID, ok := h.ids(w, r)
	if !ok {
		return
	}
	v, err := h.service.Get(r.Context(), tenantID, findingID)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeRetestCheckJSON(w, http.StatusOK, RetestCheckGetResponse{Check: toRetestCheckResponse(v)})
}

// Validate handles POST /api/v1/findings/{id}/retest-check/test.
// @Summary      Validate a retest check
// @Description  Parses and checks a retest check without saving it: the template library's validator, the retest check rules (HTTP only, requests on the finding's target, no out-of-band callbacks, no credentials) and the tier. Returns the nuclei template that would run (compiled for an assertion). Requires findings:retest_checks:write.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Param        id    path      string              true  "Finding ID"
// @Param        body  body      RetestCheckRequest  true  "Check"
// @Success      200   {object}  RetestCheckValidationResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/retest-check/test [post]
func (h *FindingRetestCheckHandler) Validate(w http.ResponseWriter, r *http.Request) {
	tenantID, findingID, ok := h.ids(w, r)
	if !ok {
		return
	}
	in, ok := decodeRetestCheck(w, r)
	if !ok {
		return
	}
	v, err := h.service.Validate(r.Context(), tenantID, findingID, in)
	if err != nil {
		h.writeError(w, err)
		return
	}
	out := RetestCheckValidationResponse{Valid: v.Valid, Errors: v.Issues, Tier: v.Tier, TierReason: v.TierReason,
		Capabilities: v.Capabilities, Content: v.Content, ApprovalRequired: v.ApprovalRequired}
	if out.Errors == nil {
		out.Errors = []retestcheckdom.Issue{}
	}
	if out.Capabilities == nil {
		out.Capabilities = []string{}
	}
	writeRetestCheckJSON(w, http.StatusOK, out)
}

// Put handles PUT /api/v1/findings/{id}/retest-check.
// @Summary      Attach or change a finding's retest check
// @Description  Saves the check the finding's retest runs. Content and assertions are stored as a template of the organization's library (approved for sensors as the organization's policy says); a library template is reused as it is. Changing the content resets the approval and the calibration. Audited. Requires findings:retest_checks:write.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Param        id    path      string              true  "Finding ID"
// @Param        body  body      RetestCheckRequest  true  "Check"
// @Success      200   {object}  RetestCheckResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/retest-check [put]
func (h *FindingRetestCheckHandler) Put(w http.ResponseWriter, r *http.Request) {
	tenantID, findingID, ok := h.ids(w, r)
	if !ok {
		return
	}
	actor, ok := actorID(r)
	if !ok {
		apierror.Unauthorized("a user is required").WriteJSON(w)
		return
	}
	in, ok := decodeRetestCheck(w, r)
	if !ok {
		return
	}
	v, err := h.service.Save(r.Context(), retestCheckAudit(r, tenantID), tenantID, findingID, actor, in)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeRetestCheckJSON(w, http.StatusOK, toRetestCheckResponse(v))
}

// Delete handles DELETE /api/v1/findings/{id}/retest-check.
// @Summary      Remove a finding's retest check
// @Description  Detaches the check; a template created for it is deleted when no other check uses it, a library template stays. Audited. Requires findings:retest_checks:write.
// @Tags         Findings
// @Param        id   path  string  true  "Finding ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/retest-check [delete]
func (h *FindingRetestCheckHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID, findingID, ok := h.ids(w, r)
	if !ok {
		return
	}
	if err := h.service.Remove(r.Context(), retestCheckAudit(r, tenantID), tenantID, findingID); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Approve handles POST /api/v1/findings/{id}/retest-check/approve.
// @Summary      Approve an intrusive retest check
// @Description  Approves the current version of an intrusive (T2) check so its retest may run. The person who wrote this version, or the template's content, cannot approve it. Audited. Requires scope:approve and a recent sign-in.
// @Tags         Findings
// @Produce      json
// @Param        id   path      string  true  "Finding ID"
// @Success      200  {object}  RetestCheckResponse
// @Failure      404  {object}  apierror.Error
// @Failure      409  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /findings/{id}/retest-check/approve [post]
func (h *FindingRetestCheckHandler) Approve(w http.ResponseWriter, r *http.Request) {
	tenantID, findingID, ok := h.ids(w, r)
	if !ok {
		return
	}
	actor, ok := actorID(r)
	if !ok {
		apierror.Unauthorized("a user is required").WriteJSON(w)
		return
	}
	v, err := h.service.Approve(r.Context(), retestCheckAudit(r, tenantID), tenantID, findingID, actor)
	if err != nil {
		h.writeError(w, err)
		return
	}
	writeRetestCheckJSON(w, http.StatusOK, toRetestCheckResponse(v))
}

func (h *FindingRetestCheckHandler) writeError(w http.ResponseWriter, err error) {
	var de *shared.DomainError
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Finding").WriteJSON(w)
	case errors.As(err, &de) && (errors.Is(err, shared.ErrConflict) || errors.Is(err, shared.ErrAlreadyExists)):
		apierror.Conflict(de.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict), errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict(err.Error()).WriteJSON(w)
	case errors.As(err, &de) && errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(de.Message).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("retest check request failed", "error", err)
		apierror.InternalServerError("Internal server error").WriteJSON(w)
	}
}
