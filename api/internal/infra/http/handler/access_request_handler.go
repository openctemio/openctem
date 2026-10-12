package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/internal/app/accessrequest"
	tenantapp "github.com/openctemio/openctem/api/internal/app/tenant"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	ardom "github.com/openctemio/openctem/api/pkg/domain/accessrequest"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// AccessRequestHandler serves the request-access queue: the public form and
// its email confirmation, and the admin console's queue
// (docs/architecture/user-onboarding.md, "Request access").
type AccessRequestHandler struct {
	svc    *accessrequest.Service
	logger *logger.Logger
}

// NewAccessRequestHandler creates the handler.
func NewAccessRequestHandler(svc *accessrequest.Service, log *logger.Logger) *AccessRequestHandler {
	return &AccessRequestHandler{svc: svc, logger: log.With("handler", "access_request")}
}

// SubmitAccessRequest is the public form.
type SubmitAccessRequest struct {
	Company string `json:"company"`
	Email   string `json:"email"`
	Note    string `json:"note"`
	// CaptchaToken is the Turnstile token when a CAPTCHA is configured.
	CaptchaToken string `json:"captcha_token"`
}

// accessRequestAccepted is the one answer to every accepted submission.
const accessRequestAccepted = "Thanks. If your request is approved, you will get an email at the address you entered."

// Submit records a request.
// @Summary      Request access (public)
// @Description  Asks the platform administrators for an organization when sign-up is closed and requests are allowed. Every accepted submission gets the same answer, whatever happens to it (rate limits, duplicates, disposable addresses). A confirmation link is emailed when email is configured.
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body  SubmitAccessRequest  true  "Request"
// @Success      202  {object}  map[string]string
// @Router       /auth/access-requests [post]
func (h *AccessRequestHandler) Submit(w http.ResponseWriter, r *http.Request) {
	var req SubmitAccessRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	err := h.svc.Submit(r.Context(), accessrequest.SubmitInput{
		Company: req.Company, Email: req.Email, Note: req.Note,
		CaptchaToken: req.CaptchaToken, IP: middleware.ClientIP(r),
	})
	switch {
	case err == nil:
		writeJSON(w, http.StatusAccepted, map[string]string{"message": accessRequestAccepted})
	case errors.Is(err, accessrequest.ErrClosed):
		writeSignupNotAvailable(w)
	case errors.Is(err, accessrequest.ErrCaptcha):
		apierror.New(http.StatusBadRequest, "CAPTCHA_FAILED", "Complete the check and try again.").WriteJSON(w)
	case errors.Is(err, ardom.ErrInvalid):
		apierror.BadRequest("Enter your company and a valid email (company up to 200 characters, note up to 1000).").WriteJSON(w)
	default:
		h.logger.Error("submit access request", "error", logger.SanitizeError(err))
		apierror.InternalServerError("could not record the request").WriteJSON(w)
	}
}

// ConfirmAccessRequest carries the emailed token (in the body, never the URL).
type ConfirmAccessRequest struct {
	Token string `json:"token"`
}

// Confirm confirms a request by its emailed token.
// @Summary      Confirm an access request (public)
// @Tags         Authentication
// @Accept       json
// @Produce      json
// @Param        request  body  ConfirmAccessRequest  true  "Token"
// @Success      200  {object}  map[string]string
// @Router       /auth/access-requests/confirm [post]
func (h *AccessRequestHandler) Confirm(w http.ResponseWriter, r *http.Request) {
	var req ConfirmAccessRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if err := h.svc.Confirm(r.Context(), req.Token); err != nil {
		apierror.BadRequest("This link is invalid or has expired.").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "Your request is confirmed and waits for an administrator."})
}

// AccessRequestResponse is one request in the console.
type AccessRequestResponse struct {
	ID          string     `json:"id"`
	Company     string     `json:"company"`
	Email       string     `json:"email"`
	Domain      string     `json:"domain"`
	Note        string     `json:"note"`
	Status      string     `json:"status"`
	Confirmed   bool       `json:"confirmed"`
	CreatedAt   time.Time  `json:"created_at"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	TenantID    string     `json:"tenant_id,omitempty"`
	ConfirmedAt *time.Time `json:"confirmed_at,omitempty"`
}

// AccessRequestListResponse is a page of requests (the list envelope).
type AccessRequestListResponse struct {
	Data       []AccessRequestResponse `json:"data"`
	Total      int64                   `json:"total"`
	Page       int                     `json:"page"`
	PerPage    int                     `json:"per_page"`
	TotalPages int                     `json:"total_pages"`
}

func toAccessRequestResponse(a *ardom.Request) AccessRequestResponse {
	resp := AccessRequestResponse{
		ID: a.ID.String(), Company: a.Company, Email: a.Email, Domain: a.Domain, Note: a.Note,
		Status: string(a.Status), Confirmed: a.ConfirmedAt != nil, CreatedAt: a.CreatedAt,
		DecidedAt: a.DecidedAt, ConfirmedAt: a.ConfirmedAt,
	}
	if a.TenantID != nil {
		resp.TenantID = a.TenantID.String()
	}
	return resp
}

// List lists requests (any admin).
// @Summary      List access requests
// @Description  Open requests (pending and unconfirmed) by default; status=pending|unconfirmed|approved|rejected filters.
// @Tags         Admin Organizations
// @Produce      json
// @Param        status    query  string  false  "Status"
// @Param        page      query  int     false  "Page (1-based)"
// @Param        per_page  query  int     false  "Page size (default 50, at most 100)"
// @Success      200  {object}  AccessRequestListResponse
// @Router       /admin/access-requests [get]
func (h *AccessRequestHandler) List(w http.ResponseWriter, r *http.Request) {
	status := ardom.Status(strings.TrimSpace(r.URL.Query().Get("status")))
	if status != "" && !status.IsValid() {
		apierror.BadRequest("invalid status").WriteJSON(w)
		return
	}
	page, ok := listPage(w, r, 50)
	if !ok {
		return
	}
	items, total, err := h.svc.List(r.Context(), ardom.Filter{Status: status, Limit: page.Limit(), Offset: page.Offset()})
	if err != nil {
		h.logger.Error("list access requests", "error", err)
		apierror.InternalServerError("could not list access requests").WriteJSON(w)
		return
	}
	result := pagination.NewResult(items, int64(total), page)
	resp := AccessRequestListResponse{
		Data:  make([]AccessRequestResponse, 0, len(items)),
		Total: result.Total, Page: result.Page, PerPage: result.PerPage, TotalPages: result.TotalPages,
	}
	for _, a := range items {
		resp.Data = append(resp.Data, toAccessRequestResponse(a))
	}
	writeJSON(w, http.StatusOK, resp)
}

// ApproveAccessRequest names the organization to create.
type ApproveAccessRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// ApproveAccessRequestResponse is the closed request and the new organization.
type ApproveAccessRequestResponse struct {
	Request        AccessRequestResponse    `json:"request"`
	OrganizationID string                   `json:"organization_id"`
	OwnerSetup     *AdminOwnerSetupResponse `json:"owner_setup,omitempty"`
}

func (h *AccessRequestHandler) requestID(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	id, err := shared.IDFromString(r.PathValue("id"))
	if err != nil {
		apierror.BadRequest("invalid id").WriteJSON(w)
		return shared.ID{}, false
	}
	return id, true
}

// Approve creates the organization with the requester as owner (ops_admin+, audited).
// @Summary      Approve an access request
// @Description  Creates the organization with the requester as its owner; a new owner account gets a one-time set-password link (emailed; returned once only when email cannot be sent). Only a confirmed (pending) request can be approved.
// @Tags         Admin Organizations
// @Accept       json
// @Produce      json
// @Param        id       path  string                true  "Request ID"
// @Param        request  body  ApproveAccessRequest  true  "Organization"
// @Success      200  {object}  ApproveAccessRequestResponse
// @Router       /admin/access-requests/{id}/approve [post]
func (h *AccessRequestHandler) Approve(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	var req ApproveAccessRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	a, created, err := h.svc.Approve(r.Context(), actor, id, accessrequest.ApproveInput{Name: req.Name, Slug: req.Slug}, adminAuditContext(r, ""))
	if err != nil {
		switch {
		case errors.Is(err, ardom.ErrNotFound):
			apierror.NotFound("Access request not found").WriteJSON(w)
		case errors.Is(err, ardom.ErrNotDecidable):
			apierror.Conflict("Only a confirmed request that is still pending can be approved").WriteJSON(w)
		case errors.Is(err, tenant.ErrPlatformAdminMembership):
			apierror.Conflict("The requester is a platform administrator and cannot own an organization.").WriteJSON(w)
		case errors.Is(err, tenantapp.ErrAccountExists):
			apierror.Conflict("An account with this email was just created. Try again.").WriteJSON(w)
		case shared.IsValidation(err):
			apierror.BadRequest(err.Error()).WriteJSON(w)
		case errors.Is(err, shared.ErrConflict), errors.Is(err, shared.ErrAlreadyExists):
			apierror.Conflict("This organization slug is taken; choose another").WriteJSON(w)
		default:
			h.logger.Error("approve access request", "error", logger.SanitizeError(err))
			apierror.InternalServerError("could not approve the request").WriteJSON(w)
		}
		return
	}
	middleware.SetAuditResource(r.Context(), created.Tenant.ID(), created.Tenant.Name())
	resp := ApproveAccessRequestResponse{Request: toAccessRequestResponse(a), OrganizationID: created.Tenant.ID().String()}
	if setup := created.OwnerSetup; setup != nil {
		resp.OwnerSetup = &AdminOwnerSetupResponse{EmailSent: setup.EmailSent, EmailFailed: setup.EmailFailed, SetupToken: setup.SetupToken}
		if setup.SetupToken != "" {
			exp := setup.SetupExpiresAt
			resp.OwnerSetup.SetupExpiresAt = &exp
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

// Reject declines a request (ops_admin+, audited); a confirmed requester gets a neutral email.
// @Summary      Reject an access request
// @Tags         Admin Organizations
// @Produce      json
// @Param        id  path  string  true  "Request ID"
// @Success      200  {object}  AccessRequestResponse
// @Router       /admin/access-requests/{id}/reject [post]
func (h *AccessRequestHandler) Reject(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	a, err := h.svc.Reject(r.Context(), actor, id)
	if err != nil {
		switch {
		case errors.Is(err, ardom.ErrNotFound):
			apierror.NotFound("Access request not found").WriteJSON(w)
		case errors.Is(err, ardom.ErrNotDecidable):
			apierror.Conflict("The request is already decided").WriteJSON(w)
		default:
			h.logger.Error("reject access request", "error", logger.SanitizeError(err))
			apierror.InternalServerError("could not reject the request").WriteJSON(w)
		}
		return
	}
	writeJSON(w, http.StatusOK, toAccessRequestResponse(a))
}
