package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/apikey"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	apikeydom "github.com/openctemio/openctem/api/pkg/domain/apikey"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/validator"
)

// APIKeyHandler handles HTTP requests for API key management.
type APIKeyHandler struct {
	service   *apikey.Service
	validator *validator.Validator
	logger    *logger.Logger
}

// NewAPIKeyHandler creates a new APIKeyHandler.
func NewAPIKeyHandler(svc *apikey.Service, v *validator.Validator, log *logger.Logger) *APIKeyHandler {
	return &APIKeyHandler{
		service:   svc,
		validator: v,
		logger:    log,
	}
}

// --- Request/Response Types ---

// CreateAPIKeyRequest represents the request to create an API key.
type CreateAPIKeyRequest struct {
	Name          string   `json:"name" validate:"required,min=1,max=255"`
	Description   string   `json:"description" validate:"max=1000"`
	Scopes        []string `json:"scopes" validate:"max=50"`
	RateLimit     int      `json:"rate_limit" validate:"min=0,max=100000"`
	ExpiresInDays int      `json:"expires_in_days" validate:"required,min=1,max=365"`
}

// APIKeyResponse represents an API key in the response.
type APIKeyResponse struct {
	ID          string     `json:"id"`
	TenantID    string     `json:"tenant_id"`
	UserID      string     `json:"user_id,omitempty"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	KeyPrefix   string     `json:"key_prefix"`
	Scopes      []string   `json:"scopes"`
	RateLimit   int        `json:"rate_limit"`
	Status      string     `json:"status"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	LastUsedIP  string     `json:"last_used_ip,omitempty"`
	UseCount    int64      `json:"use_count"`
	CreatedBy   string     `json:"created_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	RevokedBy   string     `json:"revoked_by,omitempty"`
}

// CreateAPIKeyResponse includes the plaintext key (only shown once).
type CreateAPIKeyResponse struct {
	APIKeyResponse
	Key string `json:"key"` // Plaintext key, shown only once
}

// --- Handlers ---

// Create handles POST /api/v1/api-keys
func (h *APIKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req CreateAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	input := apikey.CreateInput{
		TenantID:      tenantID,
		UserID:        userID,
		Name:          req.Name,
		Description:   req.Description,
		Scopes:        req.Scopes,
		RateLimit:     req.RateLimit,
		ExpiresInDays: req.ExpiresInDays,
		CreatedBy:     userID,
		// A key may only carry scopes its creator holds (owner/admin bypass
		// via the same HasPermission check the route gates use).
		CallerHolds: func(scope string) bool {
			return middleware.HasPermission(r.Context(), scope)
		},
		AuditContext: apiKeyAuditContext(r, tenantID),
	}

	result, err := h.service.Create(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	resp := CreateAPIKeyResponse{
		APIKeyResponse: toAPIKeyResponse(result.Key),
		Key:            result.Plaintext,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// ownKeysOnly returns the user whose keys the caller may see, or "" when the
// caller is an organization owner/admin and may see every key of the
// organization. Members and viewers see only their own keys: the list shows
// other people's key names, scopes and last-used IPs (owner decision
// 2026-10-02). ok is false when the caller has no user identity at all.
func ownKeysOnly(r *http.Request) (userID string, ok bool) {
	if middleware.IsAdmin(r.Context()) {
		return "", true
	}
	userID = middleware.GetUserID(r.Context())
	return userID, userID != ""
}

// List handles GET /api/v1/api-keys
func (h *APIKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	ownerFilter, ok := ownKeysOnly(r)
	if !ok {
		apierror.Forbidden("Insufficient permissions").WriteJSON(w)
		return
	}

	query := r.URL.Query()
	input := apikey.ListInput{
		TenantID:  tenantID,
		UserID:    ownerFilter,
		Status:    query.Get("status"),
		Search:    query.Get("search"),
		Page:      parseQueryInt(query.Get("page"), 1),
		PerPage:   parseQueryIntBounded(query.Get("per_page"), 20, 1, MaxPerPage),
		SortBy:    query.Get("sort"),
		SortOrder: query.Get("order"),
	}

	result, err := h.service.List(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	data := make([]APIKeyResponse, len(result.Data))
	for i, key := range result.Data {
		data[i] = toAPIKeyResponse(key)
	}

	response := ListResponse[APIKeyResponse]{
		Data:       data,
		Total:      result.Total,
		Page:       result.Page,
		PerPage:    result.PerPage,
		TotalPages: result.TotalPages,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}

// Get handles GET /api/v1/api-keys/{id}
func (h *APIKeyHandler) Get(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	ownerFilter, ok := ownKeysOnly(r)
	if !ok {
		apierror.Forbidden("Insufficient permissions").WriteJSON(w)
		return
	}

	key, err := h.service.Get(r.Context(), id, tenantID)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}
	// Someone else's key reads as not found, so a member cannot probe ids.
	if ownerFilter != "" && (key.UserID() == nil || key.UserID().String() != ownerFilter) {
		apierror.NotFound("API key").WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toAPIKeyResponse(key))
}

// Revoke handles POST /api/v1/api-keys/{id}/revoke
func (h *APIKeyHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())
	id := chi.URLParam(r, "id")

	// Members revoke only their own keys; owners and administrators any key
	// of the organization (the same rule as List and Get).
	ownerFilter, ok := ownKeysOnly(r)
	if !ok {
		apierror.Forbidden("Insufficient permissions").WriteJSON(w)
		return
	}

	input := apikey.RevokeInput{
		ID:           id,
		TenantID:     tenantID,
		RevokedBy:    userID,
		OwnerID:      ownerFilter,
		AuditContext: apiKeyAuditContext(r, tenantID),
	}

	key, err := h.service.Revoke(r.Context(), input)
	if err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toAPIKeyResponse(key))
}

// Delete handles DELETE /api/v1/api-keys/{id}
func (h *APIKeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.MustGetTenantID(r.Context())
	id := chi.URLParam(r, "id")

	ownerFilter, ok := ownKeysOnly(r)
	if !ok {
		apierror.Forbidden("Insufficient permissions").WriteJSON(w)
		return
	}
	if err := h.service.DeleteOwned(r.Context(), id, tenantID, ownerFilter, apiKeyAuditContext(r, tenantID)); err != nil {
		h.handleServiceError(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// --- Helpers ---

// apiKeyAuditContext attributes an API-key lifecycle event to the caller.
func apiKeyAuditContext(r *http.Request, tenantID string) *app.AuditContext {
	return &app.AuditContext{
		TenantID:   tenantID,
		ActorID:    middleware.GetUserID(r.Context()),
		ActorEmail: auditActorEmail(r.Context()),
		ActorIP:    middleware.ClientIP(r),
		UserAgent:  r.UserAgent(),
		RequestID:  middleware.GetRequestID(r.Context()),
	}
}

func toAPIKeyResponse(k *apikeydom.APIKey) APIKeyResponse {
	resp := APIKeyResponse{
		ID:          k.ID().String(),
		TenantID:    k.TenantID().String(),
		Name:        k.Name(),
		Description: k.Description(),
		KeyPrefix:   k.KeyPrefix(),
		Scopes:      k.Scopes(),
		RateLimit:   k.RateLimit(),
		Status:      string(k.Status()),
		ExpiresAt:   k.ExpiresAt(),
		LastUsedAt:  k.LastUsedAt(),
		LastUsedIP:  k.LastUsedIP(),
		UseCount:    k.UseCount(),
		CreatedAt:   k.CreatedAt(),
		UpdatedAt:   k.UpdatedAt(),
		RevokedAt:   k.RevokedAt(),
	}

	if k.UserID() != nil {
		resp.UserID = k.UserID().String()
	}
	if k.CreatedBy() != nil {
		resp.CreatedBy = k.CreatedBy().String()
	}
	if k.RevokedBy() != nil {
		resp.RevokedBy = k.RevokedBy().String()
	}

	return resp
}

func (h *APIKeyHandler) handleValidationError(w http.ResponseWriter, err error) {
	var validationErrors validator.ValidationErrors
	if errors.As(err, &validationErrors) {
		apiErrors := make([]apierror.ValidationError, len(validationErrors))
		for i, ve := range validationErrors {
			apiErrors[i] = apierror.ValidationError{
				Field:   ve.Field,
				Message: ve.Message,
			}
		}
		apierror.ValidationFailed("Validation failed", apiErrors).WriteJSON(w)
		return
	}
	apierror.BadRequest("Validation error").WriteJSON(w)
}

func (h *APIKeyHandler) handleServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, apikeydom.ErrAPIKeyNotFound):
		apierror.NotFound("API key").WriteJSON(w)
	case errors.Is(err, apikeydom.ErrAPIKeyNameExists):
		apierror.Conflict("API key name already exists").WriteJSON(w)
	case errors.Is(err, apikey.ErrScopeNotHeld):
		apierror.Forbidden("Cannot grant a scope you do not hold").WriteJSON(w)
	case shared.IsValidation(err):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	default:
		h.logger.Error("api key service error", "error", logger.SanitizeError(err))
		apierror.InternalServerError("Internal server error").WriteJSON(w)
	}
}
