package handler

// Platform console: the Configuration page
// (docs/rfcs/RFC-022-platform-admin-console.md, revision 22). Any
// administrator reads where each operator setting comes from (console,
// environment, default), whether changing it needs a restart and which page
// changes it. Secrets appear only as set or not set.

import (
	"context"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/configoverview"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ConfigurationBuilder is what the handler needs from the overview.
type ConfigurationBuilder interface {
	Build(ctx context.Context) ([]configoverview.Item, error)
}

// AdminConfigurationResponse is the Configuration page's list.
type AdminConfigurationResponse struct {
	Data []configoverview.Item `json:"data"`
}

// AdminConfigurationHandler serves GET /api/v1/admin/configuration.
type AdminConfigurationHandler struct {
	builder ConfigurationBuilder
	logger  *logger.Logger
}

// NewAdminConfigurationHandler creates the handler.
func NewAdminConfigurationHandler(b ConfigurationBuilder, log *logger.Logger) *AdminConfigurationHandler {
	return &AdminConfigurationHandler{builder: b, logger: log.With("handler", "admin_configuration")}
}

// List handles GET /api/v1/admin/configuration
// @Summary      Configuration overview
// @Description  Every operator setting with where it is managed (console or server), where its value comes from (console, environment, default), whether a change needs a restart, and the console page that changes it. Secrets are reported as set or not set only. Any admin role.
// @Tags         Admin
// @Produce      json
// @Success      200  {object}  AdminConfigurationResponse
// @Security     AdminAuth
// @Router       /admin/configuration [get]
func (h *AdminConfigurationHandler) List(w http.ResponseWriter, r *http.Request) {
	items, err := h.builder.Build(r.Context())
	if err != nil {
		h.logger.Error("configuration overview failed", "error", logger.SanitizeError(err))
		apierror.InternalServerError("The configuration overview could not be read").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, AdminConfigurationResponse{Data: items})
}
