package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/apikey"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
)

// API keys of a service account. The generic /api/v1/api-keys routes always
// act for the caller (a member sees and mints only their own keys); these act
// for one service account of the caller's organization, which must exist in
// that organization before anything else happens (another organization's
// account, or a person, reads as not found).

// serviceAccountID resolves {id} to a service account of the caller's
// organization, writing the error response when it is not one.
func (h *ServiceAccountHandler) serviceAccountID(w http.ResponseWriter, r *http.Request) (string, bool) {
	ctx := r.Context()
	a, err := h.service.Get(ctx, middleware.MustGetTenantID(ctx), chi.URLParam(r, "id"))
	if err != nil {
		h.writeError(w, err)
		return "", false
	}
	return a.ID.String(), true
}

func (h *ServiceAccountHandler) keysAvailable(w http.ResponseWriter) bool {
	if h.keys == nil {
		apierror.ServiceUnavailable("API keys are not available").WriteJSON(w)
		return false
	}
	return true
}

// ListKeys handles GET /api/v1/service-accounts/{id}/api-keys
// @Summary List a service account's API keys
// @Tags service-accounts
// @Produce json
// @Param id path string true "Service account ID"
// @Success 200 {object} ListResponse[APIKeyResponse]
// @Security BearerAuth
// @Router /service-accounts/{id}/api-keys [get]
func (h *ServiceAccountHandler) ListKeys(w http.ResponseWriter, r *http.Request) {
	if !h.keysAvailable(w) {
		return
	}
	accountID, ok := h.serviceAccountID(w, r)
	if !ok {
		return
	}
	paging, ok := listPage(w, r, 50)
	if !ok {
		return
	}
	result, err := h.keys.List(r.Context(), apikey.ListInput{
		TenantID: middleware.MustGetTenantID(r.Context()),
		UserID:   accountID,
		Page:     paging.Page,
		PerPage:  paging.PerPage,
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	data := make([]APIKeyResponse, len(result.Data))
	for i, k := range result.Data {
		data[i] = toAPIKeyResponse(k)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ListResponse[APIKeyResponse]{
		Data: data, Total: result.Total, Page: result.Page, PerPage: result.PerPage, TotalPages: result.TotalPages,
	})
}

// CreateKey handles POST /api/v1/service-accounts/{id}/api-keys
// @Summary Mint an API key for a service account
// @Description The key acts as the service account. Each scope must be held by the caller; at request time the key carries only the scopes the account itself still holds. The plaintext is returned once.
// @Tags service-accounts
// @Accept json
// @Produce json
// @Param id path string true "Service account ID"
// @Param request body CreateAPIKeyRequest true "API key"
// @Success 201 {object} CreateAPIKeyResponse
// @Security BearerAuth
// @Router /service-accounts/{id}/api-keys [post]
func (h *ServiceAccountHandler) CreateKey(w http.ResponseWriter, r *http.Request) {
	if !h.keysAvailable(w) {
		return
	}
	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		apierror.BadRequest(err.Error()).WriteJSON(w)
		return
	}
	if len(req.Scopes) == 0 {
		// A key with no scope can do nothing; refuse rather than mint dead weight.
		apierror.BadRequest("Select at least one scope").WriteJSON(w)
		return
	}
	accountID, ok := h.serviceAccountID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	tenantID := middleware.MustGetTenantID(ctx)
	result, err := h.keys.Create(ctx, apikey.CreateInput{
		TenantID:      tenantID,
		UserID:        accountID,
		Name:          req.Name,
		Description:   req.Description,
		Scopes:        req.Scopes,
		RateLimit:     req.RateLimit,
		ExpiresInDays: req.ExpiresInDays,
		CreatedBy:     middleware.GetUserID(ctx),
		// Nobody mints a key carrying a scope they do not hold themselves.
		CallerHolds:  func(scope string) bool { return middleware.HasPermission(ctx, scope) },
		AuditContext: apiKeyAuditContext(r, tenantID),
	})
	if err != nil {
		h.writeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(CreateAPIKeyResponse{APIKeyResponse: toAPIKeyResponse(result.Key), Key: result.Plaintext})
}

// DeleteKey handles DELETE /api/v1/service-accounts/{id}/api-keys/{key_id}
// @Summary Delete a service account's API key
// @Tags service-accounts
// @Param id path string true "Service account ID"
// @Param key_id path string true "API key ID"
// @Success 204
// @Security BearerAuth
// @Router /service-accounts/{id}/api-keys/{key_id} [delete]
func (h *ServiceAccountHandler) DeleteKey(w http.ResponseWriter, r *http.Request) {
	if !h.keysAvailable(w) {
		return
	}
	accountID, ok := h.serviceAccountID(w, r)
	if !ok {
		return
	}
	tenantID := middleware.MustGetTenantID(r.Context())
	// DeleteOwned: a key of anyone other than this account reads as not found.
	if err := h.keys.DeleteOwned(r.Context(), chi.URLParam(r, "key_id"), tenantID, accountID, apiKeyAuditContext(r, tenantID)); err != nil {
		h.writeError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
