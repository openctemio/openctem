package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/user"
	"github.com/openctemio/api/pkg/logger"
	"github.com/openctemio/api/pkg/validator"
)

// UserHandler handles user-related HTTP requests.
type UserHandler struct {
	service       *app.UserService
	tenantService *app.TenantService
	validator     *validator.Validator
	logger        *logger.Logger
}

// NewUserHandler creates a new user handler.
func NewUserHandler(svc *app.UserService, tenantSvc *app.TenantService, v *validator.Validator, log *logger.Logger) *UserHandler {
	return &UserHandler{
		service:       svc,
		tenantService: tenantSvc,
		validator:     v,
		logger:        log,
	}
}

// UserResponse represents a user in API responses.
type UserResponse struct {
	ID          string         `json:"id"`
	Email       string         `json:"email"`
	Name        string         `json:"name"`
	AvatarURL   string         `json:"avatar_url,omitempty"`
	Phone       string         `json:"phone,omitempty"`
	Status      string         `json:"status"`
	Preferences PreferencesDTO `json:"preferences"`
	LastLoginAt *time.Time     `json:"last_login_at,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// PreferencesDTO represents user preferences in API responses.
type PreferencesDTO struct {
	Theme         string `json:"theme,omitempty"`
	Language      string `json:"language,omitempty"`
	Notifications bool   `json:"notifications"`
}

// UpdateProfileRequest represents the request to update a user profile.
type UpdateProfileRequest struct {
	Name      *string `json:"name" validate:"omitempty,max=255"`
	Phone     *string `json:"phone" validate:"omitempty,max=50"`
	AvatarURL *string `json:"avatar_url" validate:"omitempty,url,max=500"`
}

// UpdatePreferencesRequest represents the request to update user preferences.
type UpdatePreferencesRequest struct {
	Theme         *string `json:"theme" validate:"omitempty,oneof=light dark system"`
	Language      *string `json:"language" validate:"omitempty,oneof=en vi"`
	Notifications *bool   `json:"notifications"`
}

// toUserResponse converts a domain user to API response.
func toUserResponse(u *user.User) UserResponse {
	return UserResponse{
		ID:        u.ID().String(),
		Email:     u.Email(),
		Name:      u.Name(),
		AvatarURL: u.AvatarURL(),
		Phone:     u.Phone(),
		Status:    u.Status().String(),
		Preferences: PreferencesDTO{
			Theme:         u.Preferences().Theme,
			Language:      u.Preferences().Language,
			Notifications: u.Preferences().Notifications,
		},
		LastLoginAt: u.LastLoginAt(),
		CreatedAt:   u.CreatedAt(),
		UpdatedAt:   u.UpdatedAt(),
	}
}

// GetMe returns the current authenticated user's profile.
// @Summary      Get current user profile
// @Description  Returns the profile of the authenticated user
// @Tags         Users
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  UserResponse
// @Failure      401  {object}  map[string]string
// @Router       /users/me [get]
func (h *UserHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	localUser := middleware.GetLocalUser(r.Context())
	if localUser == nil {
		apierror.Unauthorized("User not found").WriteJSON(w)
		return
	}

	response := toUserResponse(localUser)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// UpdateMe updates the current authenticated user's profile.
// @Summary      Update current user profile
// @Description  Updates the profile of the authenticated user
// @Tags         Users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      UpdateProfileRequest  true  "Profile data"
// @Success      200  {object}  UserResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /users/me [put]
func (h *UserHandler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	localUser := middleware.GetLocalUser(r.Context())
	if localUser == nil {
		apierror.Unauthorized("User not found").WriteJSON(w)
		return
	}

	var req UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	// Validate request
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	// Update profile
	input := app.UpdateProfileInput{
		Name:      req.Name,
		Phone:     req.Phone,
		AvatarURL: req.AvatarURL,
	}

	updatedUser, err := h.service.UpdateProfile(r.Context(), localUser.ID().String(), input)
	if err != nil {
		h.handleError(w, err)
		return
	}

	response := toUserResponse(updatedUser)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// UpdatePreferences updates the current authenticated user's preferences.
// @Summary      Update user preferences
// @Description  Updates the preferences of the authenticated user
// @Tags         Users
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      UpdatePreferencesRequest  true  "Preferences data"
// @Success      200  {object}  UserResponse
// @Failure      400  {object}  map[string]string
// @Failure      401  {object}  map[string]string
// @Router       /users/me/preferences [put]
func (h *UserHandler) UpdatePreferences(w http.ResponseWriter, r *http.Request) {
	localUser := middleware.GetLocalUser(r.Context())
	if localUser == nil {
		apierror.Unauthorized("User not found").WriteJSON(w)
		return
	}

	var req UpdatePreferencesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}

	// Validate request
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}

	// Build preferences from current + updates
	currentPrefs := localUser.Preferences()
	newPrefs := user.Preferences{
		Theme:         currentPrefs.Theme,
		Language:      currentPrefs.Language,
		Notifications: currentPrefs.Notifications,
	}

	if req.Theme != nil {
		newPrefs.Theme = *req.Theme
	}
	if req.Language != nil {
		newPrefs.Language = *req.Language
	}
	if req.Notifications != nil {
		newPrefs.Notifications = *req.Notifications
	}

	updatedUser, err := h.service.UpdatePreferences(r.Context(), localUser.ID().String(), newPrefs)
	if err != nil {
		h.handleError(w, err)
		return
	}

	response := toUserResponse(updatedUser)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// handleValidationError converts validation errors to API errors and writes response.
func (h *UserHandler) handleValidationError(w http.ResponseWriter, err error) {
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
	apierror.BadRequest("Validation failed").WriteJSON(w)
}

// handleError handles domain errors and converts them to API errors.
func (h *UserHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, user.ErrUserNotFound):
		apierror.NotFound("User not found").WriteJSON(w)
	case errors.Is(err, user.ErrUserAlreadyExists):
		apierror.Conflict("User already exists").WriteJSON(w)
	case errors.Is(err, user.ErrUserSuspended):
		apierror.Forbidden("User account is suspended").WriteJSON(w)
	default:
		h.logger.Error("unexpected error", "error", err)
		apierror.InternalError(err).WriteJSON(w)
	}
}

// =============================================================================
// Tenant Membership Endpoints
// =============================================================================

// TenantMembershipResponse represents a tenant with the user's role.
type TenantMembershipResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Description string    `json:"description,omitempty"`
	LogoURL     string    `json:"logo_url,omitempty"`
	Plan        string    `json:"plan"`
	Role        string    `json:"role"`
	JoinedAt    time.Time `json:"joined_at"`
	CreatedAt   time.Time `json:"created_at"`
}

// GetMyTenants returns all tenants the current user belongs to.
// @Summary      Get user's tenants
// @Description  Returns all tenants the current user belongs to
// @Tags         Users
// @Produce      json
// @Security     BearerAuth
// @Success      200  {array}   TenantMembershipResponse
// @Failure      401  {object}  map[string]string
// @Failure      500  {object}  map[string]string
// @Router       /users/me/tenants [get]
func (h *UserHandler) GetMyTenants(w http.ResponseWriter, r *http.Request) {
	localUser := middleware.GetLocalUser(r.Context())
	if localUser == nil {
		apierror.Unauthorized("User not found").WriteJSON(w)
		return
	}

	tenants, err := h.tenantService.ListUserTenants(r.Context(), localUser.ID())
	if err != nil {
		h.logger.Error("failed to list user tenants", "error", err, "user_id", localUser.ID().String())
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	// Convert to response
	response := make([]TenantMembershipResponse, len(tenants))
	for i, t := range tenants {
		response[i] = TenantMembershipResponse{
			ID:          t.Tenant.ID().String(),
			Name:        t.Tenant.Name(),
			Slug:        t.Tenant.Slug(),
			Description: t.Tenant.Description(),
			LogoURL:     t.Tenant.LogoURL(),
			Plan:        t.Tenant.Plan().String(),
			Role:        t.Role.String(),
			JoinedAt:    t.JoinedAt,
			CreatedAt:   t.Tenant.CreatedAt(),
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
