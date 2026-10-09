package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/accesscontrol"
	"github.com/openctemio/openctem/api/internal/app/apikey"
	"github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/serviceaccount"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// ServiceAccountHandler serves /api/v1/service-accounts.
type ServiceAccountHandler struct {
	service   *accesscontrol.ServiceAccountService
	keys      *apikey.Service
	validator *validator.Validator
	logger    *logger.Logger
}

// NewServiceAccountHandler creates the handler. keys mints and lists the
// accounts' API keys; nil answers those routes 503.
func NewServiceAccountHandler(svc *accesscontrol.ServiceAccountService, keys *apikey.Service, v *validator.Validator, log *logger.Logger) *ServiceAccountHandler {
	return &ServiceAccountHandler{service: svc, keys: keys, validator: v, logger: log}
}

// ServiceAccountResponse is one service account.
type ServiceAccountResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	OwnerID     string    `json:"owner_id,omitempty"`
	OwnerName   string    `json:"owner_name,omitempty"`
	Status      string    `json:"status"`
	APIKeys     int       `json:"api_keys"`
	CreatedAt   time.Time `json:"created_at"`
}

// ServiceAccountListResponse lists service accounts.
type ServiceAccountListResponse struct {
	Data []ServiceAccountResponse `json:"data"`
}

func toServiceAccountResponse(a *serviceaccount.ServiceAccount) ServiceAccountResponse {
	r := ServiceAccountResponse{
		ID: a.ID.String(), Name: a.Name, Description: a.Description, OwnerName: a.OwnerName,
		Status: a.Status, APIKeys: a.APIKeys, CreatedAt: a.CreatedAt,
	}
	if a.OwnerID != nil {
		r.OwnerID = a.OwnerID.String()
	}
	return r
}

func (h *ServiceAccountHandler) writeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Service account").WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, apikey.ErrScopeNotHeld):
		apierror.Forbidden("Cannot grant a scope you do not hold").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrAlreadyExists):
		apierror.Conflict("An API key with this name already exists").WriteJSON(w)
	case WritePlanLimitError(w, err):
	default:
		h.logger.Error("service account error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// List handles GET /api/v1/service-accounts
// @Summary List service accounts
// @Description Organization-owned identities for integrations. They never sign in; they act through API keys minted for them.
// @Tags service-accounts
// @Produce json
// @Success 200 {object} ServiceAccountListResponse
// @Security BearerAuth
// @Router /service-accounts [get]
func (h *ServiceAccountHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := h.service.List(ctx, middleware.MustGetTenantID(ctx))
	if err != nil {
		h.writeError(w, err)
		return
	}
	resp := ServiceAccountListResponse{Data: make([]ServiceAccountResponse, 0, len(list))}
	for _, a := range list {
		resp.Data = append(resp.Data, toServiceAccountResponse(a))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// Create handles POST /api/v1/service-accounts
// @Summary Create a service account
// @Description Creates an identity with no role; give it roles with the role APIs and mint API keys for it with the API key APIs. It can never be an owner or administrator, hold full data access or sign in.
// @Tags service-accounts
// @Accept json
// @Produce json
// @Param request body accesscontrol.CreateServiceAccountInput true "Service account"
// @Success 201 {object} ServiceAccountResponse
// @Security BearerAuth
// @Router /service-accounts [post]
func (h *ServiceAccountHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req accesscontrol.CreateServiceAccountInput
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}
	a, err := h.service.Create(r.Context(), req, serviceAccountAuditContext(r))
	if err != nil {
		h.writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toServiceAccountResponse(a))
}

// Delete handles DELETE /api/v1/service-accounts/{id}
// @Summary Delete a service account
// @Description Removes the account with its roles, team memberships and API keys.
// @Tags service-accounts
// @Param id path string true "Service account ID"
// @Success 204
// @Security BearerAuth
// @Router /service-accounts/{id} [delete]
func (h *ServiceAccountHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if err := h.service.Delete(r.Context(), chi.URLParam(r, "id"), serviceAccountAuditContext(r)); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func serviceAccountAuditContext(r *http.Request) audit.AuditContext {
	actx := audit.AuditContext{
		ActorIP:   getClientIP(r),
		UserAgent: r.UserAgent(),
		RequestID: r.Header.Get("X-Request-ID"),
		TenantID:  middleware.GetTenantID(r.Context()),
	}
	if u := middleware.GetLocalUser(r.Context()); u != nil {
		actx.ActorID, actx.ActorEmail = u.ID().String(), u.Email()
	}
	return actx
}
