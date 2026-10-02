// Package handler provides HTTP handlers for the API server.
// This file implements admin authentication endpoints.
package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// AdminAuthHandler handles admin authentication endpoints.
type AdminAuthHandler struct {
	logger *logger.Logger
}

// NewAdminAuthHandler creates a new AdminAuthHandler.
func NewAdminAuthHandler(log *logger.Logger) *AdminAuthHandler {
	return &AdminAuthHandler{
		logger: log.With("handler", "admin_auth"),
	}
}

// ValidateResponse represents the response for API key validation.
type ValidateResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
	Role  string `json:"role"`
	// AuthMethod is how this console session was opened: password or idp.
	AuthMethod string `json:"auth_method,omitempty"`
	// IsBreakGlass marks an emergency-access administrator.
	IsBreakGlass bool `json:"is_break_glass"`
	// PasswordChangeRequired: the session may only change the temporary password.
	PasswordChangeRequired bool `json:"password_change_required"`
}

// Validate validates the admin API key and returns admin info.
// GET /api/v1/admin/auth/validate
//
// The actual authentication is done by the AdminAuthMiddleware.
// This handler just returns the authenticated admin's information.
func (h *AdminAuthHandler) Validate(w http.ResponseWriter, r *http.Request) {
	// Get admin user from context (set by AdminAuthMiddleware)
	adminUser := middleware.MustGetAdminUser(r.Context())

	h.logger.Debug("admin auth validated",
		"admin_id", adminUser.ID().String(),
		"email", adminUser.Email(),
		"role", adminUser.Role())

	response := ValidateResponse{
		ID:           adminUser.ID().String(),
		Email:        adminUser.Email(),
		Name:         adminUser.Name(),
		Role:         string(adminUser.Role()),
		IsBreakGlass: adminUser.IsBreakGlass(),
	}
	if sess := middleware.GetAdminSession(r.Context()); sess != nil {
		response.AuthMethod = sess.AuthMethod
		response.PasswordChangeRequired = adminUser.PasswordChangeRequired() && sess.AuthMethod == admin.AuthMethodPassword
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}
