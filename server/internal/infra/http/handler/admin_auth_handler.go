// Package handler provides HTTP handlers for the API server.
// This file implements admin authentication endpoints.
package handler

import (
	"encoding/json"
	"net/http"
	"time"

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
	// FactorEnrollmentRequired: the console requires security keys and this
	// administrator must register them (and recovery codes) first.
	FactorEnrollmentRequired bool `json:"factor_enrollment_required"`
	// MaxRole is the administrator's own role: the most this session may
	// elevate to. Role is what the session acts as now.
	MaxRole string `json:"max_role,omitempty"`
	// ElevatedUntil is when the session's elevation ends (absent: not elevated).
	ElevatedUntil *time.Time `json:"elevated_until,omitempty"`
	// ElevatedAs is the platform role the session acts as (absent: not
	// elevated).
	ElevatedAs string `json:"elevated_as,omitempty"`
	// Roles are the platform roles the administrator holds.
	Roles []string `json:"roles"`
	// Permissions is what the session acts with now; MaxPermissions what the
	// roles grant (the most an elevation reaches). The console hides what
	// Permissions lacks; the API decides on its own.
	Permissions    []string `json:"permissions"`
	MaxPermissions []string `json:"max_permissions"`
	// CSRFToken is the console session's CSRF token, for the console to echo
	// in X-CSRF-Token. Returned only by the sign-in steps that open a session
	// and by validate (the session's own cookie request), never in a readable
	// cookie: on a second port of the tenant host the two sites share cookies,
	// but a tenant page cannot read the console's responses.
	CSRFToken string `json:"csrf_token,omitempty"`
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
		"role", adminUser.EffectiveRole())

	response := ValidateResponse{
		ID:             adminUser.ID().String(),
		Email:          adminUser.Email(),
		Name:           adminUser.Name(),
		Role:           string(adminUser.EffectiveRole()),
		MaxRole:        string(adminUser.MaxRole()),
		IsBreakGlass:   adminUser.IsBreakGlass(),
		Roles:          []string{},
		Permissions:    adminUser.Permissions().Sorted(),
		MaxPermissions: adminUser.HeldPermissions().Sorted(),
	}
	for _, k := range adminUser.PlatformRoles() {
		response.Roles = append(response.Roles, string(k))
	}
	if sess := middleware.GetAdminSession(r.Context()); sess != nil {
		response.AuthMethod = sess.AuthMethod
		if as := sess.ElevatedAs(time.Now()); as != "" {
			response.ElevatedUntil = sess.ElevatedUntil
			response.ElevatedAs = string(as)
		}
		response.PasswordChangeRequired = adminUser.PasswordChangeRequired() && sess.AuthMethod == admin.AuthMethodPassword
		response.FactorEnrollmentRequired = sess.EnrollmentRequired
	}
	// The session's own CSRF token (bound to the session cookie that
	// authenticated this request).
	if c, err := r.Cookie(middleware.AdminSessionCookie); err == nil && c.Value != "" {
		response.CSRFToken = middleware.AdminCSRFToken(c.Value)
	}
	w.Header().Set("Cache-Control", "no-store")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}
