package handler

import (
	"encoding/json"
	"net/http"

	automationsvc "github.com/openctemio/openctem/api/internal/app/automation"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
)

// The 401/403 answers of the catalog route (named for the spec generator).
var _ = apierror.Error{}

// WorkflowCatalogEntry is one type a builder may offer. Allowed says
// whether the caller holds its permission, so the builder can explain a type
// the caller cannot add instead of hiding it.
type WorkflowCatalogEntry struct {
	Type       string `json:"type"`
	Permission string `json:"permission,omitempty"`
	Allowed    bool   `json:"allowed"`
}

// WorkflowCatalogResponse lists every trigger, action and notification type
// the engine runs, in builder order.
type WorkflowCatalogResponse struct {
	Triggers      []WorkflowCatalogEntry `json:"triggers"`
	Actions       []WorkflowCatalogEntry `json:"actions"`
	Notifications []WorkflowCatalogEntry `json:"notifications"`
}

// GetCatalog handles GET /api/v1/workflows/catalog.
// @Summary      Automation catalog
// @Description  Every trigger, action and notification type the automation engine runs, in builder order, with the permission each needs and whether the caller holds it. A type not listed here is refused on save.
// @Tags         Automations
// @Produce      json
// @Success      200  {object}  WorkflowCatalogResponse
// @Failure      401  {object}  apierror.Error
// @Failure      403  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /workflows/catalog [get]
func (h *WorkflowHandler) GetCatalog(w http.ResponseWriter, r *http.Request) {
	resp := WorkflowCatalogResponse{
		Triggers:      []WorkflowCatalogEntry{},
		Actions:       []WorkflowCatalogEntry{},
		Notifications: []WorkflowCatalogEntry{},
	}
	for _, e := range automationsvc.Catalog() {
		entry := WorkflowCatalogEntry{
			Type:       e.Type,
			Permission: string(e.Permission),
			Allowed:    e.Permission == "" || middleware.HasPermission(r.Context(), string(e.Permission)),
		}
		switch e.Kind {
		case automationsvc.CatalogKindTrigger:
			resp.Triggers = append(resp.Triggers, entry)
		case automationsvc.CatalogKindAction:
			resp.Actions = append(resp.Actions, entry)
		case automationsvc.CatalogKindNotification:
			resp.Notifications = append(resp.Notifications, entry)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
